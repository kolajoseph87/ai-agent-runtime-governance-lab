using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Text.Json;

public static class Chapter4Diagnostics
{
    public static async Task RunAsync(ExecutionContext context, GovernedAgentRunner authorizer)
    {
        var workerDll = Path.Combine(AppContext.BaseDirectory, "SandboxWorker.dll");
        var worker = new RestrictedWorkerExecutor(workerDll);
        var libraryName = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
            ? "libhot_path_evaluator.dylib"
            : RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? "hot_path_evaluator.dll" : "libhot_path_evaluator.so";
        var libraryPath = Path.GetFullPath(Path.Combine(
            Directory.GetCurrentDirectory(), "hot_path_evaluator", "target", "release", libraryName));

        RustHotPathInterop? rust = null;
        try
        {
            if (File.Exists(libraryPath)) rust = new RustHotPathInterop(libraryPath);
            var runtime = new RingAwareToolRuntime(authorizer,
                new ToolRingClassifier(SecureCodingRingRegistry.Assignments), rust, worker);
            var calls = new[]
            {
                new ToolInvocation(context, "prompt-code-reader", "code:read",
                    ImmutableDictionary<string, object>.Empty.Add("length", 120)),
                new ToolInvocation(context, "repository-reader", "repo:read",
                    ImmutableDictionary<string, object>.Empty.Add("path", "synthetic")),
                new ToolInvocation(context, "production-deployer", "production:deploy",
                    ImmutableDictionary<string, object>.Empty)
            };
            foreach (var call in calls)
            {
                var result = await runtime.InvokeAsync(call);
                Console.WriteLine(JsonSerializer.Serialize(result,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            if (rust is null)
                Console.WriteLine("Rust library missing: Ring 0 correctly failed closed. Run cargo build --release.");
        }
        finally
        {
            rust?.Dispose();
        }
    }
}

public sealed class DiagnosticAgent : IRunnableAgent
{
    public Task<string> RunAsync(string query, CancellationToken cancellationToken = default) =>
        Task.FromResult("Diagnostic agent does not call a model");
}
