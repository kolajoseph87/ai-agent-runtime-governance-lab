using System.Collections.Immutable;
using System.Text.RegularExpressions;

public enum PolicyAction { Allow, Deny }
public enum ConditionKind { MatchAll, InputContains, ToolIs, OutputRegex }

public sealed record PolicyVersion(int Major, int Minor, int Patch) : IComparable<PolicyVersion>
{
    public int CompareTo(PolicyVersion? other) => other is null ? 1 :
        (Major, Minor, Patch).CompareTo((other.Major, other.Minor, other.Patch));
    public override string ToString() => $"{Major}.{Minor}.{Patch}";
}

public sealed record PolicyCondition(ConditionKind Kind, string? Value = null);
public sealed record PolicyRule(
    string Name, int Priority, PolicyCondition Condition,
    PolicyAction Action, string Description = "");
public sealed record PolicyRuleSet(
    string Name, PolicyVersion Version, PolicyAttachmentPoint AttachmentPoint,
    ImmutableArray<PolicyRule> Rules);
public sealed record PolicyEvaluationContext(
    ExecutionContext ExecutionContext, PolicyAttachmentPoint AttachmentPoint,
    string InputText = "", string ToolName = "", string RequiredScope = "",
    string OutputText = "");
public sealed record RuleEvaluationResult(
    bool Permitted, string Reason, string RuleName,
    string RuleSetName, string PolicyVersion);

public static class PolicyValidator
{
    public static ImmutableArray<string> Validate(PolicyRuleSet ruleSet)
    {
        var errors = ImmutableArray.CreateBuilder<string>();
        if (string.IsNullOrWhiteSpace(ruleSet.Name)) errors.Add("Rule-set name is required");
        if (ruleSet.Rules.IsEmpty) errors.Add("Rule set must contain at least one rule");
        foreach (var group in ruleSet.Rules.GroupBy(r => r.Name).Where(g => g.Count() > 1))
            errors.Add($"Duplicate rule name: {group.Key}");
        foreach (var group in ruleSet.Rules.GroupBy(r => r.Priority).Where(g => g.Count() > 1))
            errors.Add($"Ambiguous duplicate priority: {group.Key}");
        var catchAll = ruleSet.Rules.Where(r => r.Condition.Kind == ConditionKind.MatchAll).ToArray();
        if (catchAll.Length != 1) errors.Add("Exactly one catch-all rule is required");
        else if (ruleSet.Rules.Length > 0 && catchAll[0].Priority != ruleSet.Rules.Max(r => r.Priority))
            errors.Add("Catch-all rule must have the lowest precedence");
        foreach (var rule in ruleSet.Rules.Where(r =>
                     r.Condition.Kind != ConditionKind.MatchAll && string.IsNullOrWhiteSpace(r.Condition.Value)))
            errors.Add($"Rule {rule.Name} requires a condition value");
        return errors.ToImmutable();
    }

    public static void RequireValid(PolicyRuleSet ruleSet)
    {
        var errors = Validate(ruleSet);
        if (!errors.IsEmpty) throw new ArgumentException(string.Join("; ", errors));
    }
}

public sealed class PolicyRegistry
{
    private readonly Dictionary<(string Name, string Version), PolicyRuleSet> _store = [];
    public void Register(PolicyRuleSet ruleSet)
    {
        PolicyValidator.RequireValid(ruleSet);
        var key = (ruleSet.Name, ruleSet.Version.ToString());
        if (!_store.TryAdd(key, ruleSet))
            throw new ArgumentException($"Rule set {ruleSet.Name}@{ruleSet.Version} is already registered");
    }
    public PolicyRuleSet Load(string name, string version) =>
        _store.TryGetValue((name, version), out var rules) ? rules :
        throw new KeyNotFoundException($"Rule set {name}@{version} not found");
}

public sealed class StructuredPolicyEvaluator
{
    private readonly PolicyRuleSet _ruleSet;
    private readonly ImmutableArray<PolicyRule> _orderedRules;
    public StructuredPolicyEvaluator(PolicyRuleSet ruleSet)
    {
        PolicyValidator.RequireValid(ruleSet);
        _ruleSet = ruleSet;
        _orderedRules = ruleSet.Rules.OrderBy(r => r.Priority).ToImmutableArray();
    }

    public RuleEvaluationResult Evaluate(PolicyEvaluationContext context)
    {
        try
        {
            if (context.AttachmentPoint != _ruleSet.AttachmentPoint)
                return Deny("Attachment point does not match the rule set", "attachment-point-binding");
            foreach (var rule in _orderedRules)
                if (Matches(rule.Condition, context))
                    return new(rule.Action == PolicyAction.Allow, $"Rule '{rule.Name}' matched",
                        rule.Name, _ruleSet.Name, _ruleSet.Version.ToString());
            return Deny("No rule matched; default deny", "default-deny");
        }
        catch (Exception ex)
        {
            return Deny($"Policy evaluator failed closed: {ex.GetType().Name}", "evaluator-exception");
        }
    }

    public Task<(bool, string)> EvaluateInputAsync(ExecutionContext execution, string payload,
        CancellationToken token) => EvaluateForPipeline(
            new(execution, PolicyAttachmentPoint.PreInput, InputText: payload), token);
    public Task<(bool, string)> EvaluateToolAsync(ExecutionContext execution, string payload,
        CancellationToken token)
    {
        var parts = payload.Split('|', 2);
        return EvaluateForPipeline(new(execution, PolicyAttachmentPoint.PreTool,
            ToolName: parts[0], RequiredScope: parts.Length == 2 ? parts[1] : ""), token);
    }
    public Task<(bool, string)> EvaluateOutputAsync(ExecutionContext execution, string payload,
        CancellationToken token) => EvaluateForPipeline(
            new(execution, PolicyAttachmentPoint.PreOutput, OutputText: payload), token);

    private Task<(bool, string)> EvaluateForPipeline(PolicyEvaluationContext context,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var result = Evaluate(context);
        return Task.FromResult((result.Permitted,
            $"{result.RuleSetName}@{result.PolicyVersion}: {result.Reason}"));
    }
    private RuleEvaluationResult Deny(string reason, string ruleName) =>
        new(false, reason, ruleName, _ruleSet.Name, _ruleSet.Version.ToString());
    private static bool Matches(PolicyCondition condition, PolicyEvaluationContext context) =>
        condition.Kind switch
        {
            ConditionKind.MatchAll => true,
            ConditionKind.InputContains => context.InputText.Contains(condition.Value!, StringComparison.OrdinalIgnoreCase),
            ConditionKind.ToolIs => string.Equals(context.ToolName, condition.Value, StringComparison.OrdinalIgnoreCase),
            ConditionKind.OutputRegex => Regex.IsMatch(context.OutputText, condition.Value!, RegexOptions.IgnoreCase),
            _ => throw new ArgumentOutOfRangeException(nameof(condition.Kind))
        };
}

public static class SecureCodingPolicySet
{
    public static readonly PolicyVersion V1_0_0 = new(1, 0, 0);
    public static readonly PolicyVersion V1_1_0 = new(1, 1, 0);
    public static void RegisterAll(PolicyRegistry registry)
    {
        foreach (var version in new[] { V1_0_0, V1_1_0 })
        {
            registry.Register(InputRules(version));
            registry.Register(ToolRules(version));
            registry.Register(OutputRules(version));
        }
    }
    private static void RequireSupported(PolicyVersion version)
    {
        if (version != V1_0_0 && version != V1_1_0)
            throw new ArgumentException($"Unsupported policy version {version}");
    }
    public static PolicyRuleSet InputRules(PolicyVersion version)
    {
        RequireSupported(version);
        var rules = new List<PolicyRule>
        {
            Rule("deny_ignore_previous_instructions", 100, ConditionKind.InputContains, "ignore previous instructions", PolicyAction.Deny),
            Rule("deny_read_all_env_files", 110, ConditionKind.InputContains, "read every .env", PolicyAction.Deny),
            Rule("deny_print_environment", 120, ConditionKind.InputContains, "print environment variables", PolicyAction.Deny),
            Rule("deny_reveal_api_keys", 130, ConditionKind.InputContains, "reveal api keys", PolicyAction.Deny)
        };
        if (version.CompareTo(V1_1_0) >= 0)
            rules.Add(Rule("deny_npmrc_collection", 140, ConditionKind.InputContains,
                "read every .npmrc", PolicyAction.Deny));
        rules.Add(Rule("allow_standard_code_review", 9999, ConditionKind.MatchAll, null, PolicyAction.Allow));
        return new("secure-coding-input", version, PolicyAttachmentPoint.PreInput, rules.ToImmutableArray());
    }
    public static PolicyRuleSet ToolRules(PolicyVersion version)
    {
        RequireSupported(version);
        return new("secure-coding-tool", version, PolicyAttachmentPoint.PreTool,
            ImmutableArray.Create(
                Rule("deny_production_deployer", 100, ConditionKind.ToolIs, "production-deployer", PolicyAction.Deny),
                Rule("deny_terminal_executor", 110, ConditionKind.ToolIs, "terminal-executor", PolicyAction.Deny),
                Rule("deny_git_push", 120, ConditionKind.ToolIs, "git-push", PolicyAction.Deny),
                Rule("allow_repository_reader", 500, ConditionKind.ToolIs, "repository-reader", PolicyAction.Allow),
                Rule("allow_unit_test_runner", 510, ConditionKind.ToolIs, "unit-test-runner", PolicyAction.Allow),
                Rule("allow_sast_scanner", 520, ConditionKind.ToolIs, "sast-scanner", PolicyAction.Allow),
                Rule("deny_unlisted_tool", 9999, ConditionKind.MatchAll, null, PolicyAction.Deny)));
    }
    public static PolicyRuleSet OutputRules(PolicyVersion version)
    {
        RequireSupported(version);
        var rules = new List<PolicyRule>
        {
            Rule("deny_high_confidence_credential", 100, ConditionKind.OutputRegex,
                @"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", PolicyAction.Deny)
        };
        if (version.CompareTo(V1_1_0) >= 0)
            rules.Add(Rule("deny_private_key_material", 110, ConditionKind.OutputRegex,
                @"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", PolicyAction.Deny));
        rules.Add(Rule("allow_standard_security_review", 9999, ConditionKind.MatchAll, null, PolicyAction.Allow));
        return new("secure-coding-output", version, PolicyAttachmentPoint.PreOutput, rules.ToImmutableArray());
    }
    private static PolicyRule Rule(string name, int priority, ConditionKind kind,
        string? value, PolicyAction action) => new(name, priority, new(kind, value), action);
}

public static class PolicyComposition
{
    public static PolicyRegistry CreateRegistry()
    {
        var registry = new PolicyRegistry();
        SecureCodingPolicySet.RegisterAll(registry);
        return registry;
    }
    public static EvaluationPipeline CreatePipeline(string version)
    {
        var registry = CreateRegistry();
        var input = new StructuredPolicyEvaluator(registry.Load("secure-coding-input", version));
        var tool = new StructuredPolicyEvaluator(registry.Load("secure-coding-tool", version));
        var output = new StructuredPolicyEvaluator(registry.Load("secure-coding-output", version));
        var pipeline = new EvaluationPipeline();
        pipeline.Attach(PolicyAttachmentPoint.PreInput, "require-code-review-claim", PolicyEvaluators.RequireCodeReviewClaimAsync);
        pipeline.Attach(PolicyAttachmentPoint.PreInput, $"secure-coding-input@{version}", input.EvaluateInputAsync);
        pipeline.Attach(PolicyAttachmentPoint.PreTool, $"secure-coding-tool@{version}", tool.EvaluateToolAsync);
        pipeline.Attach(PolicyAttachmentPoint.PreTool, "authorize-tool-scope", PolicyEvaluators.AuthorizeToolRequestAsync);
        pipeline.Attach(PolicyAttachmentPoint.PreOutput, $"secure-coding-output@{version}", output.EvaluateOutputAsync);
        return pipeline;
    }
}
