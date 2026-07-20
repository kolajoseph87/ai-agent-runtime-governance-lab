using System.Collections.Immutable;

public enum PolicyChannel { Dev, Staging, Prod }
public enum BoundaryFailMode { FailClosed, FailOpen }

public sealed record BoundaryOperationsConfig(
    ImmutableDictionary<PolicyAttachmentPoint, BoundaryFailMode> FailModes,
    ImmutableDictionary<PolicyAttachmentPoint, TimeSpan> LatencyBudgets)
{
    public void Validate()
    {
        foreach (var point in Enum.GetValues<PolicyAttachmentPoint>())
        {
            if (!FailModes.ContainsKey(point) || !LatencyBudgets.ContainsKey(point))
                throw new ArgumentException($"Missing operations configuration for {point}");
            if (LatencyBudgets[point] <= TimeSpan.Zero)
                throw new ArgumentException("Latency budgets must be positive");
        }
        foreach (var point in new[] { PolicyAttachmentPoint.PreInput, PolicyAttachmentPoint.PreTool })
            if (FailModes[point] != BoundaryFailMode.FailClosed)
                throw new ArgumentException($"{point} is security-critical and must fail closed");
    }
}

public sealed record PolicyActivation(
    string Name, PolicyChannel Source, PolicyChannel Target,
    string? PreviousVersion, string Version, string CorrelationId,
    DateTimeOffset Timestamp);

public sealed class OperationalPolicyRegistry
{
    private readonly PolicyRegistry _policies;
    private readonly Dictionary<(string, PolicyChannel), string> _active = [];
    private readonly object _gate = new();

    public OperationalPolicyRegistry(PolicyRegistry policies) => _policies = policies;

    public string? Active(string name, PolicyChannel channel)
    {
        lock (_gate) return _active.GetValueOrDefault((name, channel));
    }

    public void CompareAndActivate(string name, PolicyChannel channel, string version,
        string? expectedCurrent)
    {
        _policies.Load(name, version);
        lock (_gate)
        {
            var actual = _active.GetValueOrDefault((name, channel));
            if (actual != expectedCurrent)
                throw new InvalidOperationException(
                    $"Active version changed: expected {expectedCurrent}, found {actual}");
            _active[(name, channel)] = version;
        }
    }
}

public sealed class PolicyPromotionService
{
    private readonly OperationalPolicyRegistry _registry;
    private readonly List<PolicyActivation> _history = [];

    public PolicyPromotionService(OperationalPolicyRegistry registry) => _registry = registry;
    public IReadOnlyList<PolicyActivation> History => _history.AsReadOnly();

    public PolicyActivation Promote(string name, string version, PolicyChannel source,
        PolicyChannel target, string correlationId)
    {
        if ((source, target) is not (PolicyChannel.Dev, PolicyChannel.Staging)
            and not (PolicyChannel.Staging, PolicyChannel.Prod))
            throw new ArgumentException("Policies must move dev -> staging -> prod");
        if (source == PolicyChannel.Staging &&
            _registry.Active(name, PolicyChannel.Staging) != version)
            throw new UnauthorizedAccessException(
                "Production promotion requires the same staged version");

        var previous = _registry.Active(name, target);
        var record = new PolicyActivation(name, source, target, previous, version,
            correlationId, DateTimeOffset.UtcNow);
        _registry.CompareAndActivate(name, target, version, previous);
        // Record only a completed activation. Production still needs a transactional
        // outbox so state and durable evidence cannot diverge on process failure.
        _history.Add(record);
        return record;
    }

    public string Rollback(string name, PolicyChannel channel, string expectedBadVersion)
    {
        if (_registry.Active(name, channel) != expectedBadVersion)
            throw new InvalidOperationException("Rollback refused because active state changed");
        var activation = _history.LastOrDefault(item =>
            item.Name == name && item.Target == channel && item.Version == expectedBadVersion);
        if (activation?.PreviousVersion is null)
            throw new InvalidOperationException("No previous version available for rollback");
        _registry.CompareAndActivate(name, channel, activation.PreviousVersion, expectedBadVersion);
        _history.Add(new PolicyActivation(name, channel, channel, expectedBadVersion,
            activation.PreviousVersion, "rollback", DateTimeOffset.UtcNow));
        return activation.PreviousVersion;
    }
}

public sealed record ComponentHealth(string Name, bool Ready, string Reason);

public static class GovernanceHealth
{
    public static ComponentHealth Probe(string name, Func<bool> check)
    {
        try
        {
            return check()
                ? new(name, true, "ready")
                : new(name, false, "required state unavailable");
        }
        catch (Exception ex)
        {
            return new(name, false, $"probe failed safely: {ex.GetType().Name}");
        }
    }
}

public static class Chapter8Diagnostics
{
    public static void Run()
    {
        var modes = ImmutableDictionary.CreateRange(new[]
        {
            KeyValuePair.Create(PolicyAttachmentPoint.PreInput, BoundaryFailMode.FailClosed),
            KeyValuePair.Create(PolicyAttachmentPoint.PreTool, BoundaryFailMode.FailClosed),
            KeyValuePair.Create(PolicyAttachmentPoint.PreOutput, BoundaryFailMode.FailClosed)
        });
        var budgets = Enum.GetValues<PolicyAttachmentPoint>().ToImmutableDictionary(
            point => point, _ => TimeSpan.FromMilliseconds(50));
        new BoundaryOperationsConfig(modes, budgets).Validate();

        var policies = PolicyComposition.CreateRegistry();
        var registry = new OperationalPolicyRegistry(policies);
        var service = new PolicyPromotionService(registry);
        registry.CompareAndActivate("secure-coding-input", PolicyChannel.Dev, "1.0.0", null);
        service.Promote("secure-coding-input", "1.0.0", PolicyChannel.Dev,
            PolicyChannel.Staging, "corr-ch8-stage");
        service.Promote("secure-coding-input", "1.0.0", PolicyChannel.Staging,
            PolicyChannel.Prod, "corr-ch8-prod");

        var health = GovernanceHealth.Probe("policy-registry",
            () => registry.Active("secure-coding-input", PolicyChannel.Prod) is not null);
        if (!health.Ready) throw new InvalidOperationException("Chapter 8 readiness failed");
        Console.WriteLine("Chapter 8 operations diagnostics passed");
    }
}
