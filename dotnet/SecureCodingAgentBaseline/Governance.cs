using System.Collections.Immutable;
using System.Text.RegularExpressions;
public enum TrustBoundary
{
    InputValidation,
    ToolInvocation,
    OutputFiltering
}

public enum PolicyAttachmentPoint
{
    PreInput,
    PreTool,
    PreOutput
}

public enum Decision
{
    Permit,
    Deny
}

public sealed record AgentPrincipal(
    string PrincipalId,
    string TenantId,
    ImmutableHashSet<string> Claims);

public sealed record AgentIdentity(
    string AgentId,
    string Version,
    string Role);

public sealed record ToolIdentity(
    string ToolName,
    string ToolVersion,
    ImmutableHashSet<string> AllowedScopes);

public sealed record ExecutionContext(
    string CorrelationId,
    string SessionId,
    AgentPrincipal Principal,
    AgentIdentity Agent,
    ImmutableHashSet<ToolIdentity> ToolInventory,
    string Workspace = "synthetic://prompt-only",
    string Environment = "development");

public sealed record EvaluationResult(
    Decision Decision,
    string Reason,
    TrustBoundary Boundary,
    PolicyAttachmentPoint AttachmentPoint,
    string CorrelationId,
    string PolicyName)
{
    public bool Permitted => Decision == Decision.Permit;
}

public delegate Task<(bool Permitted, string Reason)> PolicyEvaluator(
    ExecutionContext context,
    string payload,
    CancellationToken cancellationToken);

public sealed class EvaluationPipeline
{
    private readonly Dictionary<
        PolicyAttachmentPoint,
        List<(string Name, PolicyEvaluator Evaluator)>> _evaluators = [];

    private readonly TimeSpan _timeout;

    public EvaluationPipeline(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? TimeSpan.FromSeconds(1);
    }

    public void Attach(
        PolicyAttachmentPoint point,
        string policyName,
        PolicyEvaluator evaluator)
    {
        if (!_evaluators.TryGetValue(point, out var list))
        {
            list = [];
            _evaluators[point] = list;
        }
        list.Add((policyName, evaluator));
    }

    public async Task<EvaluationResult> EvaluateAsync(
        PolicyAttachmentPoint point,
        ExecutionContext context,
        string payload,
        CancellationToken cancellationToken = default)
    {
        var boundary = BoundaryFor(point);
        if (!_evaluators.TryGetValue(point, out var evaluators))
        {
            return new EvaluationResult(
                Decision.Deny,
                "No evaluator is attached at the required boundary",
                boundary,
                point,
                context.CorrelationId,
                "default-deny");
        }

        foreach (var (name, evaluator) in evaluators)
        {
            try
            {
                var evaluation = evaluator(context, payload, cancellationToken);
                var (permitted, reason) = await evaluation.WaitAsync(
                    _timeout,
                    cancellationToken);

                if (!permitted)
                {
                    return new EvaluationResult(
                        Decision.Deny,
                        reason,
                        boundary,
                        point,
                        context.CorrelationId,
                        name);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new EvaluationResult(
                    Decision.Deny,
                    $"Policy evaluation failed closed: {ex.GetType().Name}",
                    boundary,
                    point,
                    context.CorrelationId,
                    name);
            }
        }

        return Permit(point, boundary, context, "pipeline");
    }

    private static TrustBoundary BoundaryFor(PolicyAttachmentPoint point) =>
        point switch
        {
            PolicyAttachmentPoint.PreInput => TrustBoundary.InputValidation,
            PolicyAttachmentPoint.PreTool => TrustBoundary.ToolInvocation,
            PolicyAttachmentPoint.PreOutput => TrustBoundary.OutputFiltering,
            _ => throw new ArgumentOutOfRangeException(nameof(point))
        };

    private static EvaluationResult Permit(
        PolicyAttachmentPoint point,
        TrustBoundary boundary,
        ExecutionContext context,
        string policyName) =>
        new(
            Decision.Permit,
            "All attached policies permitted progression",
            boundary,
            point,
            context.CorrelationId,
            policyName);
}

public sealed record AgentPolicySet(
    string AgentId,
    ImmutableHashSet<PolicyAttachmentPoint> Attachments);

public sealed record GovernedRunResult(
    Decision Decision,
    string CorrelationId,
    string Reason,
    TrustBoundary? Boundary,
    string? Output = null);

public static class PolicyEvaluators
{
    private static readonly string[] SuspiciousInputPatterns =
    [
        "ignore previous instructions",
        "ignore all security requirements",
        "print environment variables",
        "read every .env",
        "reveal api keys"
    ];

    public static Task<(bool, string)> RequireCodeReviewClaimAsync(
        ExecutionContext context,
        string payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var permitted = context.Principal.Claims.Contains("code:review");
        return Task.FromResult(
            permitted
                ? (true, "Principal is entitled to request code review")
                : (false, "Principal lacks the code:review claim"));
    }

    public static Task<(bool, string)> DenyGoalManipulationAsync(
        ExecutionContext context,
        string payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var blocked = SuspiciousInputPatterns.Any(
            pattern => payload.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(
            blocked
                ? (false, "Potential goal-manipulation instruction detected")
                : (true, "No blocked goal-manipulation pattern detected"));
    }

    public static Task<(bool, string)> AuthorizeToolRequestAsync(
        ExecutionContext context,
        string payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var parts = payload.Split('|', 2);
        if (parts.Length != 2)
            return Task.FromResult((false, "Malformed tool authorization request"));

        var tool = context.ToolInventory.FirstOrDefault(
            item => item.ToolName == parts[0]);
        if (tool is null)
            return Task.FromResult((false, $"Tool {parts[0]} is not in the immutable inventory"));
        if (!tool.AllowedScopes.Contains(parts[1]))
            return Task.FromResult((false, $"Tool {parts[0]} does not allow {parts[1]}"));
        if (!context.Principal.Claims.Contains(parts[1]))
            return Task.FromResult((false, $"Principal is not entitled to {parts[1]}"));
        return Task.FromResult((true, $"Principal and tool both permit {parts[1]}"));
    }

    public static Task<(bool, string)> DenySecretOutputAsync(
    ExecutionContext context,
    string payload,
    CancellationToken cancellationToken)
{
    cancellationToken.ThrowIfCancellationRequested();

    const string secretPattern =
        @"(?:sk-[A-Za-z0-9_-]{20,}"
        + @"|AKIA[0-9A-Z]{16}"
        + @"|gh[pousr]_[A-Za-z0-9]{20,}"
        + @"|github_pat_[A-Za-z0-9_]{20,}"
        + @"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})";

    var secretLike = Regex.IsMatch(
        payload,
        secretPattern,
        RegexOptions.IgnoreCase);

    return Task.FromResult(
        secretLike
            ? (false, "Potential secret detected in agent output")
            : (true, "No high-confidence secret pattern detected in agent output"));
    }
}

public interface IRunnableAgent
{
    Task<string> RunAsync(
        string query,
        CancellationToken cancellationToken = default);
}

public sealed class GovernedAgentRunner
{
    private readonly IRunnableAgent _agent;
    private readonly EvaluationPipeline _pipeline;
    private readonly AgentPolicySet _policySet;

    public GovernedAgentRunner(
        IRunnableAgent agent,
        EvaluationPipeline pipeline,
        AgentPolicySet policySet)
    {
        _agent = agent;
        _pipeline = pipeline;
        _policySet = policySet;
    }

    public async Task<EvaluationResult> AuthorizeToolAsync(
        string toolName,
        string requiredScope,
        ExecutionContext context,
        CancellationToken cancellationToken = default)
    {
        if (context.Agent.AgentId != _policySet.AgentId)
        {
            return new EvaluationResult(
                Decision.Deny,
                "Execution-context agent identity does not match policy set",
                TrustBoundary.ToolInvocation,
                PolicyAttachmentPoint.PreTool,
                context.CorrelationId,
                "agent-identity-binding");
        }

        if (!_policySet.Attachments.Contains(PolicyAttachmentPoint.PreTool))
        {
            return new EvaluationResult(
                Decision.Deny,
                "No PRE_TOOL policy is attached; failed closed",
                TrustBoundary.ToolInvocation,
                PolicyAttachmentPoint.PreTool,
                context.CorrelationId,
                "default-deny");
        }

        return await _pipeline.EvaluateAsync(
            PolicyAttachmentPoint.PreTool,
            context,
            $"{toolName}|{requiredScope}",
            cancellationToken);
    }

    public async Task<GovernedRunResult> RunAsync(
        string query,
        ExecutionContext context,
        CancellationToken cancellationToken = default)
    {
        if (context.Agent.AgentId != _policySet.AgentId)
        {
            return new GovernedRunResult(
                Decision.Deny,
                context.CorrelationId,
                "Execution-context agent identity does not match policy set",
                TrustBoundary.InputValidation);
        }

        if (_policySet.Attachments.Contains(PolicyAttachmentPoint.PreInput))
        {
            var input = await _pipeline.EvaluateAsync(
                PolicyAttachmentPoint.PreInput,
                context,
                query,
                cancellationToken);
            if (!input.Permitted)
                return Denied(input);
        }

        var output = await _agent.RunAsync(query, cancellationToken);

        if (_policySet.Attachments.Contains(PolicyAttachmentPoint.PreOutput))
        {
            var filter = await _pipeline.EvaluateAsync(
                PolicyAttachmentPoint.PreOutput,
                context,
                output,
                cancellationToken);
            if (!filter.Permitted)
                return Denied(filter);
        }

        return new GovernedRunResult(
            Decision.Permit,
            context.CorrelationId,
            "Request passed every active governance boundary",
            null,
            output);
    }

    private static GovernedRunResult Denied(EvaluationResult result) =>
        new(
            Decision.Deny,
            result.CorrelationId,
            result.Reason,
            result.Boundary);
}
