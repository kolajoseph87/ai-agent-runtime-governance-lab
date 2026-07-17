using Microsoft.Agents.AI;
using OpenAI;
using OpenAI.Chat;

public record AgentConfiguration(
    string ModelName = "gpt-4o-mini",
    string AgentName = "SecurityIncidentAgent");

public sealed class SecurityIncidentAgent
{
    private readonly AIAgent _agent;

    public SecurityIncidentAgent(AgentConfiguration config, string apiKey)
    {
        var chatClient = new OpenAIClient(apiKey).GetChatClient(config.ModelName);
        _agent = chatClient.AsAIAgent(
    instructions: """
        You are a security operations assistant.

        For every security incident:
        1. Explain why the activity is suspicious.
        2. Identify the likely security risk.
        3. Recommend investigation steps.
        4. Recommend safe containment steps.
        5. Do not claim that you performed any investigation or containment action.
        6. End with this exact statement: "No containment actions were performed. This baseline agent has no tools and only provides recommendations."
        """,
    name: config.AgentName);
    }

    public async Task<string> RunAsync(
        string userQuery,
        CancellationToken cancellationToken = default)
    {
        var response = await _agent.RunAsync(userQuery, cancellationToken: cancellationToken);
        return response.ToString();
    }
}

public record OwaspControlMapping(
    string RiskId,
    string RiskName,
    string PrimaryDefenseLayer,
    string ToolkitPackage);

public static class OwaspToolkitMap
{
    public static readonly IReadOnlyList<OwaspControlMapping> Mappings =
    [
        new("T1", "Memory Poisoning", "data", "N/A"),
        new("T2", "Tool Misuse", "runtime", "Microsoft.AgentGovernance.Policies"),
        new("T3", "Privilege Compromise", "runtime", "Microsoft.AgentGovernance.Runtime"),
        new("T4", "Resource Overload", "runtime", "Microsoft.AgentGovernance.Runtime"),
        new("T5", "Cascading Hallucination Attacks", "human process", "N/A"),
        new("T6", "Intent Breaking and Goal Manipulation", "runtime", "Microsoft.AgentGovernance.Policies"),
        new("T7", "Misaligned and Deceptive Behaviors", "framework", "N/A"),
        new("T8", "Repudiation and Untraceability", "runtime", "Microsoft.AgentGovernance.Audit"),
        new("T9", "Identity Spoofing and Impersonation", "identity", "Microsoft.AgentGovernance.Identity"),
        new("T10", "Overwhelming Human-in-the-Loop", "human process", "N/A")
    ];
}

public static class RiskLookup
{
    public static string ResolvePackage(string riskId)
    {
        var mapping = OwaspToolkitMap.Mappings.FirstOrDefault(
            item => string.Equals(item.RiskId, riskId, StringComparison.OrdinalIgnoreCase));
        return mapping is not null && mapping.PrimaryDefenseLayer == "runtime"
            ? mapping.ToolkitPackage
            : "unmapped";
    }

    public static bool RuntimeCoverageGap(int targetCount) =>
        OwaspToolkitMap.Mappings.Count(item => item.PrimaryDefenseLayer == "runtime") < targetCount;
}

public static class Program
{
    public static async Task Main()
    {
        Console.WriteLine($"T3 package: {RiskLookup.ResolvePackage("T3")}");
        Console.WriteLine($"Coverage gap at 7: {RiskLookup.RuntimeCoverageGap(7)}");

        var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Console.WriteLine("Set OPENAI_API_KEY to run the agent baseline.");
            return;
        }

        var agent = new SecurityIncidentAgent(new AgentConfiguration(), apiKey);
        var response = await agent.RunAsync(
            "A finance employee had five failed logins followed by a successful login from a new country. Explain the risk and recommend next steps.");
        Console.WriteLine(response);
    }
}

