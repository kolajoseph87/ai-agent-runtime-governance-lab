using System.Text.Json;

const int MaxInputBytes = 64 * 1024;
var input = Console.OpenStandardInput();
using var memory = new MemoryStream();
var buffer = new byte[4096];
while (true)
{
    var read = await input.ReadAsync(buffer);
    if (read == 0) break;
    if (memory.Length + read > MaxInputBytes) return await Reject("payload too large");
    await memory.WriteAsync(buffer.AsMemory(0, read));
}

try
{
    using var document = JsonDocument.Parse(memory.ToArray());
    var root = document.RootElement;
    var expected = new HashSet<string> { "tool", "arguments", "correlation_id" };
    if (root.ValueKind != JsonValueKind.Object ||
        root.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(expected) is false ||
        !root.TryGetProperty("tool", out var toolElement) ||
        !root.TryGetProperty("arguments", out var arguments) || arguments.ValueKind != JsonValueKind.Object ||
        !root.TryGetProperty("correlation_id", out var correlationElement))
        return await Reject("invalid schema");

    var tool = toolElement.GetString();
    var allowed = new HashSet<string>
    {
        "repository-reader", "sast-scanner", "unit-test-runner", "dependency-advisory-lookup"
    };
    if (tool is null || !allowed.Contains(tool)) return await Reject("unregistered worker tool");
    var correlationId = correlationElement.GetString();
    if (string.IsNullOrWhiteSpace(correlationId)) return await Reject("missing correlation ID");

    object result = tool switch
    {
        "repository-reader" => new { mode = "mock-read-only", files_examined = 0 },
        "sast-scanner" => new { mode = "mock-no-filesystem", findings = Array.Empty<string>() },
        "unit-test-runner" => new { mode = "mock-no-code-execution", tests_run = 0 },
        _ => new { mode = "mock-no-network", advisories = Array.Empty<string>() }
    };
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        status = "ok", tool, correlation_id = correlationId,
        environment_scrubbed = Environment.GetEnvironmentVariable("OPENAI_API_KEY") is null,
        result,
        received_argument_names = arguments.EnumerateObject().Select(p => p.Name).Order()
    }));
    return 0;
}
catch (JsonException)
{
    return await Reject("invalid JSON");
}

static Task<int> Reject(string reason)
{
    Console.WriteLine(JsonSerializer.Serialize(new { status = "denied", reason }));
    return Task.FromResult(1);
}
