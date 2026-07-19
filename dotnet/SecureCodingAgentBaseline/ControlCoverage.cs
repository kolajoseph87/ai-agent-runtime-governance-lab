using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public enum OwaspAgenticRisk { T1, T2, T3, T4, T5, T6, T7, T8, T9, T10 }
public enum ControlLayer { Runtime, Framework, Infrastructure, Identity, Data, HumanProcess }
public enum CoverageStatus { Verified, Partial, Missing, ExternalRequired }

public sealed record CapabilityRequirement(
    string Capability, ControlLayer Layer,
    PolicyAttachmentPoint? AttachmentPoint = null);

public sealed record OwaspRiskCoverage(
    OwaspAgenticRisk Risk, string RiskName, ControlLayer PrimaryLayer,
    bool RuntimeAddressable, ImmutableArray<CapabilityRequirement> Requirements,
    ImmutableHashSet<ControlLayer> SecondaryLayers);

public sealed record ControlEvidence(
    string ControlId, string Capability, ControlLayer Layer,
    bool Implemented, bool Tested, string ImplementationReference,
    string TestReference, PolicyAttachmentPoint? AttachmentPoint = null)
{
    public bool Verified => Implemented && Tested;
}

public sealed record RiskFinding(
    OwaspAgenticRisk Risk, string RiskName, CoverageStatus Status,
    ControlLayer PrimaryLayer, ImmutableArray<string> VerifiedCapabilities,
    ImmutableArray<string> MissingCapabilities, string Explanation);

public sealed record GapAnalysisReport(
    string MatrixVersion, string ConfigurationFingerprint,
    ImmutableArray<RiskFinding> Findings,
    ImmutableArray<string> FalseConfidenceFlags)
{
    public ImmutableArray<RiskFinding> DeploymentBlockingRuntimeGaps =>
        Findings.Where(f => f.Status == CoverageStatus.Missing &&
            f.PrimaryLayer is ControlLayer.Runtime or ControlLayer.Identity or ControlLayer.Infrastructure)
        .ToImmutableArray();
}

public sealed class ControlCoverageMatrix
{
    public const string Version = "secure-coding-lab-2026.1";
    private readonly ImmutableDictionary<OwaspAgenticRisk, OwaspRiskCoverage> _entries;

    public ControlCoverageMatrix()
    {
        var input = PolicyAttachmentPoint.PreInput;
        var tool = PolicyAttachmentPoint.PreTool;
        var entries = new[]
        {
            Entry(OwaspAgenticRisk.T1, "Memory Poisoning", ControlLayer.Data, false,
                Req("memory_write_integrity", ControlLayer.Data),
                Req("memory_provenance", ControlLayer.Data)),
            Entry(OwaspAgenticRisk.T2, "Tool Misuse", ControlLayer.Runtime, true,
                Req("tool_allowlist", ControlLayer.Runtime, tool),
                Req("inventory_scope_authorization", ControlLayer.Runtime, tool),
                Req("risk_based_ring_routing", ControlLayer.Runtime, tool)),
            Entry(OwaspAgenticRisk.T3, "Privilege Compromise", ControlLayer.Runtime, true,
                Req("least_privilege_tool_scopes", ControlLayer.Runtime, tool),
                Req("agent_policy_identity_binding", ControlLayer.Identity, tool),
                Req("verified_workload_identity", ControlLayer.Identity)),
            Entry(OwaspAgenticRisk.T4, "Resource Overload", ControlLayer.Infrastructure, true,
                Req("worker_timeout", ControlLayer.Runtime, tool),
                Req("payload_output_bounds", ControlLayer.Runtime, tool),
                Req("worker_concurrency_limit", ControlLayer.Infrastructure, tool),
                Req("agent_request_budget", ControlLayer.Runtime, input),
                Req("kill_switch", ControlLayer.Infrastructure)),
            Entry(OwaspAgenticRisk.T5, "Cascading Hallucination Attacks", ControlLayer.HumanProcess, false,
                Req("multi_agent_human_review", ControlLayer.HumanProcess),
                Req("independent_output_verification", ControlLayer.HumanProcess)),
            Entry(OwaspAgenticRisk.T6, "Intent Breaking and Goal Manipulation", ControlLayer.Runtime, true,
                Req("preinput_goal_policy", ControlLayer.Runtime, input),
                Req("adversarial_semantic_detection", ControlLayer.Runtime, input)),
            Entry(OwaspAgenticRisk.T7, "Misaligned and Deceptive Behaviors", ControlLayer.Framework, false,
                Req("model_alignment_evaluation", ControlLayer.Framework),
                Req("independent_red_team", ControlLayer.HumanProcess)),
            Entry(OwaspAgenticRisk.T8, "Repudiation and Untraceability", ControlLayer.Runtime, true,
                Req("correlation_id_propagation", ControlLayer.Runtime, input),
                Req("persistent_audit_log", ControlLayer.Infrastructure),
                Req("tamper_evident_evidence", ControlLayer.Infrastructure)),
            Entry(OwaspAgenticRisk.T9, "Identity Spoofing and Impersonation", ControlLayer.Identity, true,
                Req("agent_policy_identity_binding", ControlLayer.Identity, input),
                Req("verified_workload_identity", ControlLayer.Identity),
                Req("tool_inventory_identity_check", ControlLayer.Identity, tool)),
            Entry(OwaspAgenticRisk.T10, "Overwhelming Human-in-the-Loop", ControlLayer.HumanProcess, false,
                Req("approval_risk_tiers", ControlLayer.HumanProcess),
                Req("approval_queue_throttling", ControlLayer.HumanProcess))
        };
        _entries = entries.ToImmutableDictionary(e => e.Risk);
    }

    public OwaspRiskCoverage CoverageFor(OwaspAgenticRisk risk) => _entries[risk];
    public ImmutableArray<OwaspRiskCoverage> Entries =>
        Enum.GetValues<OwaspAgenticRisk>().Select(CoverageFor).ToImmutableArray();

    private static CapabilityRequirement Req(string capability, ControlLayer layer,
        PolicyAttachmentPoint? point = null) => new(capability, layer, point);
    private static OwaspRiskCoverage Entry(OwaspAgenticRisk risk, string name,
        ControlLayer layer, bool runtime, params CapabilityRequirement[] requirements) =>
        new(risk, name, layer, runtime, requirements.ToImmutableArray(),
            ImmutableHashSet<ControlLayer>.Empty);
}

public static class ControlPlacementValidator
{
    public static ImmutableArray<string> ValidatePolicyAnnotations(
        PolicyRuleSet ruleSet, ControlCoverageMatrix matrix)
    {
        var errors = ImmutableArray.CreateBuilder<string>();
        var annotations = ruleSet.Annotations.IsDefault
            ? ImmutableArray<PolicyTraceAnnotation>.Empty : ruleSet.Annotations;
        foreach (var annotation in annotations)
        {
            if (!Enum.TryParse<OwaspAgenticRisk>(annotation.RiskId, out var risk))
            {
                errors.Add($"Unknown risk {annotation.RiskId}");
                continue;
            }
            var coverage = matrix.CoverageFor(risk);
            if (!coverage.RuntimeAddressable)
            {
                errors.Add($"{ruleSet.Name} cannot claim non-runtime risk {risk}");
                continue;
            }
            var requirement = coverage.Requirements.FirstOrDefault(
                r => r.Capability == annotation.Capability);
            if (requirement is null)
                errors.Add($"{annotation.Capability} is not a requirement for {risk}");
            else if (requirement.AttachmentPoint is not null &&
                     requirement.AttachmentPoint != ruleSet.AttachmentPoint)
                errors.Add($"{annotation.Capability} belongs at {requirement.AttachmentPoint}");
        }
        return errors.ToImmutable();
    }
}

public sealed class OwaspGapAnalyzer
{
    private readonly ControlCoverageMatrix _matrix;
    public OwaspGapAnalyzer(ControlCoverageMatrix matrix) => _matrix = matrix;

    public GapAnalysisReport Analyze(IEnumerable<ControlEvidence> evidence,
        ImmutableHashSet<PolicyAttachmentPoint> activeAttachments, object snapshot)
    {
        var byCapability = evidence.GroupBy(e => e.Capability)
            .ToDictionary(g => g.Key, g => g.ToArray());
        var findings = ImmutableArray.CreateBuilder<RiskFinding>();
        var flags = ImmutableArray.CreateBuilder<string>();
        foreach (var coverage in _matrix.Entries)
        {
            var verified = ImmutableArray.CreateBuilder<string>();
            var missing = ImmutableArray.CreateBuilder<string>();
            foreach (var requirement in coverage.Requirements)
            {
                var satisfied = byCapability.TryGetValue(requirement.Capability, out var candidates) &&
                    candidates.Any(item => item.Verified && item.Layer == requirement.Layer &&
                        (requirement.AttachmentPoint is null ||
                         item.AttachmentPoint == requirement.AttachmentPoint &&
                         activeAttachments.Contains(requirement.AttachmentPoint.Value)));
                (satisfied ? verified : missing).Add(requirement.Capability);
            }

            CoverageStatus status;
            string explanation;
            if (!coverage.RuntimeAddressable)
            {
                status = CoverageStatus.ExternalRequired;
                explanation = $"Primary remediation belongs to {coverage.PrimaryLayer}; runtime policy cannot close this risk.";
            }
            else if (missing.Count == 0)
            {
                status = CoverageStatus.Verified;
                explanation = "Every declared lab requirement has implemented and tested evidence.";
            }
            else if (verified.Count > 0)
            {
                status = CoverageStatus.Partial;
                explanation = "Some controls are verified, but missing capabilities prevent a full lab claim.";
                flags.Add($"{coverage.Risk} is only partial; missing: {string.Join(", ", missing)}");
            }
            else
            {
                status = CoverageStatus.Missing;
                explanation = "No required capability has verified evidence.";
                flags.Add($"{coverage.Risk} has no verified control evidence");
            }
            findings.Add(new(coverage.Risk, coverage.RiskName, status,
                coverage.PrimaryLayer, verified.ToImmutable(), missing.ToImmutable(), explanation));
        }
        var json = JsonSerializer.Serialize(snapshot);
        var fingerprint = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
        return new(ControlCoverageMatrix.Version, fingerprint,
            findings.ToImmutable(), flags.ToImmutable());
    }
}

public static class SecureCodingControlEvidence
{
    public static readonly ImmutableArray<ControlEvidence> Items =
    [
        E("C-T2-ALLOWLIST", "tool_allowlist", ControlLayer.Runtime, "PolicyEngine.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T2-SCOPE", "inventory_scope_authorization", ControlLayer.Runtime, "Governance.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T2-RINGS", "risk_based_ring_routing", ControlLayer.Runtime, "RingRuntime.cs", "Chapter4Diagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T3-SCOPES", "least_privilege_tool_scopes", ControlLayer.Runtime, "Governance.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T3-BIND-TOOL", "agent_policy_identity_binding", ControlLayer.Identity, "Governance.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T9-BIND-INPUT", "agent_policy_identity_binding", ControlLayer.Identity, "Governance.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreInput),
        E("C-T9-TOOL-ID", "tool_inventory_identity_check", ControlLayer.Identity, "Governance.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T4-TIMEOUT", "worker_timeout", ControlLayer.Runtime, "RingRuntime.cs", "Chapter4Diagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T4-BOUNDS", "payload_output_bounds", ControlLayer.Runtime, "RingRuntime.cs", "Chapter4Diagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T4-CONCURRENCY", "worker_concurrency_limit", ControlLayer.Infrastructure, "RingRuntime.cs", "Chapter4Diagnostics.cs", PolicyAttachmentPoint.PreTool),
        E("C-T6-INPUT", "preinput_goal_policy", ControlLayer.Runtime, "PolicyEngine.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreInput),
        E("C-T8-CORRELATION", "correlation_id_propagation", ControlLayer.Runtime, "Governance.cs", "PolicyDiagnostics.cs", PolicyAttachmentPoint.PreInput)
    ];

    private static ControlEvidence E(string id, string capability, ControlLayer layer,
        string implementation, string test, PolicyAttachmentPoint point) =>
        new(id, capability, layer, true, true, implementation, test, point);
}

public static class Chapter5Audit
{
    public static GapAnalysisReport Run(EvaluationPipeline pipeline, string policyVersion)
    {
        var registry = PolicyComposition.CreateRegistry();
        var policySnapshot = new[]
        {
            registry.Load("secure-coding-input", policyVersion),
            registry.Load("secure-coding-tool", policyVersion),
            registry.Load("secure-coding-output", policyVersion)
        }.Select(set => new
        {
            set.Name,
            Version = set.Version.ToString(),
            AttachmentPoint = set.AttachmentPoint.ToString(),
            Rules = set.Rules.Select(rule => new
            {
                rule.Name,
                rule.Priority,
                ConditionKind = rule.Condition.Kind.ToString(),
                rule.Condition.Value,
                Action = rule.Action.ToString(),
                rule.Description
            }).ToArray(),
            Annotations = (set.Annotations.IsDefault
                ? ImmutableArray<PolicyTraceAnnotation>.Empty
                : set.Annotations).Select(annotation => new
            {
                annotation.RiskId,
                annotation.Capability,
                annotation.Justification
            }).ToArray()
        }).ToArray();
        var ringSnapshot = SecureCodingRingRegistry.Assignments
            .OrderBy(a => a.ToolName).Select(a => $"{a.ToolName}:{(int)a.Ring}").ToArray();
        var snapshot = new
        {
            policyVersion,
            policies = policySnapshot,
            pipeline = pipeline.ConfigurationSnapshot,
            rings = ringSnapshot
        };
        var report = new OwaspGapAnalyzer(new ControlCoverageMatrix()).Analyze(
            SecureCodingControlEvidence.Items, pipeline.AttachmentPoints, snapshot);
        Console.WriteLine("=== Chapter 5 OWASP Evidence Audit ===");
        foreach (var finding in report.Findings)
            Console.WriteLine($"{finding.Risk} {finding.Status}: missing [{string.Join(", ", finding.MissingCapabilities)}]");
        Console.WriteLine($"Configuration fingerprint: {report.ConfigurationFingerprint}");
        return report;
    }
}
