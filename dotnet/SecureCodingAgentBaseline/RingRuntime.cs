using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

public enum ExecutionRing
{
    Ring0InMemory = 0,
    Ring1LocalRestricted = 1,
    Ring2UntrustedOrExternal = 2,
    Ring3Privileged = 3
}

public sealed record ToolRingAssignment(
    string ToolName, ExecutionRing Ring, string Justification);

public sealed class ToolRingClassifier
{
    private readonly ImmutableDictionary<string, ToolRingAssignment> _assignments;

    public ToolRingClassifier(IEnumerable<ToolRingAssignment> assignments)
    {
        _assignments = assignments.ToImmutableDictionary(a => a.ToolName, StringComparer.Ordinal);
        if (_assignments.Count == 0) throw new ArgumentException("Ring assignments are required");
    }

    public ToolRingAssignment Classify(string toolName) =>
        _assignments.TryGetValue(toolName, out var assignment) ? assignment :
        throw new KeyNotFoundException($"Tool '{toolName}' has no execution-ring assignment");
}

public static class SecureCodingRingRegistry
{
    public static readonly ImmutableArray<ToolRingAssignment> Assignments =
    [
        new("prompt-code-reader", ExecutionRing.Ring0InMemory,
            "Reads only code already present in immutable request memory"),
        new("repository-reader", ExecutionRing.Ring1LocalRestricted,
            "Reads sensitive workspace data and therefore uses a restricted worker"),
        new("sast-scanner", ExecutionRing.Ring1LocalRestricted,
            "Analyzes code locally with no network and no mutation"),
        new("unit-test-runner", ExecutionRing.Ring2UntrustedOrExternal,
            "Executes potentially hostile repository code"),
        new("dependency-advisory-lookup", ExecutionRing.Ring2UntrustedOrExternal,
            "Would cross a network trust boundary in production"),
        new("terminal-executor", ExecutionRing.Ring3Privileged,
            "Arbitrary command execution has broad host impact"),
        new("git-push", ExecutionRing.Ring3Privileged,
            "Changes an external source-of-truth repository"),
        new("production-deployer", ExecutionRing.Ring3Privileged,
            "Changes production and requires explicit human approval")
    ];
}

public sealed record ToolInvocation(
    ExecutionContext Context,
    string ToolName,
    string RequiredScope,
    ImmutableDictionary<string, object> Arguments)
{
    public string PrincipalId => Context.Principal.PrincipalId;
}

public enum HotPathVerdict : int { Allow = 0, Deny = 1, Error = 2 }

[StructLayout(LayoutKind.Sequential)]
public struct HotPathRequest
{
    public IntPtr ToolName;
    public int Ring;
    public IntPtr PrincipalId;
}

public interface IHotPathClient
{
    HotPathVerdict Evaluate(string toolName, int ring, string principalId);
}

public sealed class RustHotPathInterop : IHotPathClient, IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int EvaluateDelegate(HotPathRequest request);

    private IntPtr _handle;
    private readonly EvaluateDelegate _evaluate;

    public RustHotPathInterop(string libraryPath)
    {
        var fullPath = Path.GetFullPath(libraryPath);
        if (!File.Exists(fullPath) || !NativeLibrary.TryLoad(fullPath, out _handle))
            throw new DllNotFoundException($"Could not load Rust evaluator: {fullPath}");
        if (!NativeLibrary.TryGetExport(_handle, "evaluate_hot_path", out var export))
        {
            NativeLibrary.Free(_handle);
            _handle = IntPtr.Zero;
            throw new EntryPointNotFoundException("evaluate_hot_path");
        }
        _evaluate = Marshal.GetDelegateForFunctionPointer<EvaluateDelegate>(export);
    }

    public HotPathVerdict Evaluate(string toolName, int ring, string principalId)
    {
        var tool = Marshal.StringToCoTaskMemUTF8(toolName);
        var principal = Marshal.StringToCoTaskMemUTF8(principalId);
        try
        {
            var raw = _evaluate(new HotPathRequest
            {
                ToolName = tool,
                Ring = ring,
                PrincipalId = principal
            });
            return Enum.IsDefined(typeof(HotPathVerdict), raw)
                ? (HotPathVerdict)raw : HotPathVerdict.Error;
        }
        catch
        {
            return HotPathVerdict.Error;
        }
        finally
        {
            Marshal.FreeCoTaskMem(tool);
            Marshal.FreeCoTaskMem(principal);
        }
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        NativeLibrary.Free(_handle);
        _handle = IntPtr.Zero;
        GC.SuppressFinalize(this);
    }
}

public sealed class RestrictedWorkerExecutor
{
    private const int MaxPayloadBytes = 64 * 1024;
    private const int MaxOutputCharacters = 64 * 1024;
    private readonly string _workerDll;
    private readonly TimeSpan _timeout;
    private readonly SemaphoreSlim _concurrency;
    private static readonly ImmutableHashSet<ExecutionRing> AllowedRings =
        ImmutableHashSet.Create(ExecutionRing.Ring1LocalRestricted,
            ExecutionRing.Ring2UntrustedOrExternal);

    public RestrictedWorkerExecutor(string workerDll, TimeSpan? timeout = null,
        int maxConcurrency = 4)
    {
        _workerDll = Path.GetFullPath(workerDll);
        if (!File.Exists(_workerDll)) throw new FileNotFoundException("Worker DLL not found", _workerDll);
        _timeout = timeout ?? TimeSpan.FromSeconds(2);
        if (_timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
        if (maxConcurrency <= 0) throw new ArgumentOutOfRangeException(nameof(maxConcurrency));
        _concurrency = new SemaphoreSlim(maxConcurrency, maxConcurrency);
    }

    public async Task<Dictionary<string, JsonElement>> ExecuteAsync(
        ToolInvocation invocation, ExecutionRing ring,
        CancellationToken cancellationToken = default)
    {
        if (!AllowedRings.Contains(ring))
            throw new InvalidOperationException($"Ring {ring} is not permitted in the worker");
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            tool = invocation.ToolName,
            arguments = invocation.Arguments,
            correlation_id = invocation.Context.CorrelationId
        });
        if (payload.Length > MaxPayloadBytes)
            throw new InvalidOperationException("Worker payload exceeds the 64 KiB limit");

        await _concurrency.WaitAsync(cancellationToken);
        try
        {
            var start = new ProcessStartInfo("dotnet")
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            start.ArgumentList.Add(_workerDll);
            start.Environment.Clear();
            start.Environment["PATH"] = Environment.GetEnvironmentVariable("PATH")
                ?? "/usr/local/bin:/usr/bin:/bin";
            using var process = Process.Start(start) ??
                throw new InvalidOperationException("Restricted worker failed to start");
            await process.StandardInput.BaseStream.WriteAsync(payload, cancellationToken);
            process.StandardInput.Close();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_timeout);
            var stdoutTask = ReadLimitedAsync(process.StandardOutput, timeout.Token);
            var stderrTask = ReadLimitedAsync(process.StandardError, timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                if (cancellationToken.IsCancellationRequested) throw;
                throw new TimeoutException("Worker timed out and was terminated");
            }
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            if (stdout.Length > MaxOutputCharacters || stderr.Length > MaxOutputCharacters)
                throw new InvalidOperationException("Worker output exceeded the 64 KiB limit");
            if (process.ExitCode != 0)
                throw new InvalidOperationException("Worker rejected the invocation");
            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(stdout) ??
                throw new InvalidOperationException("Worker returned invalid JSON");
            if (!result.TryGetValue("status", out var status) || status.GetString() != "ok")
                throw new InvalidOperationException("Worker did not return explicit success");
            if (result["tool"].GetString() != invocation.ToolName ||
                result["correlation_id"].GetString() != invocation.Context.CorrelationId)
                throw new InvalidOperationException("Worker result binding did not match request");
            return result;
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private static async Task<string> ReadLimitedAsync(StreamReader reader,
        CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        var buffer = new char[4096];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0) return output.ToString();
            output.Append(buffer, 0, read);
            if (output.Length > MaxOutputCharacters)
                throw new InvalidOperationException("Worker output exceeded the 64 KiB limit");
        }
    }
}

public sealed record ToolExecutionResult(
    string Status, string ToolName, string? Ring, string? Path,
    string CorrelationId, string Reason, object? Output = null);

public sealed class RingAwareToolRuntime
{
    private readonly GovernedAgentRunner _authorizer;
    private readonly ToolRingClassifier _classifier;
    private readonly IHotPathClient? _hotPath;
    private readonly RestrictedWorkerExecutor _worker;

    public RingAwareToolRuntime(GovernedAgentRunner authorizer,
        ToolRingClassifier classifier, IHotPathClient? hotPath,
        RestrictedWorkerExecutor worker)
    {
        _authorizer = authorizer;
        _classifier = classifier;
        _hotPath = hotPath;
        _worker = worker;
    }

    public async Task<ToolExecutionResult> InvokeAsync(ToolInvocation invocation,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var authorization = await _authorizer.AuthorizeToolAsync(
                invocation.ToolName, invocation.RequiredScope,
                invocation.Context, cancellationToken);
            if (!authorization.Permitted)
                return Deny(invocation, null, "pre-tool-policy", authorization.Reason);

            var assignment = _classifier.Classify(invocation.ToolName);
            if (assignment.Ring == ExecutionRing.Ring3Privileged)
                return Deny(invocation, assignment.Ring, "human-approval-required",
                    "Ring 3 tools are disabled until a human approval service exists");

            if (assignment.Ring == ExecutionRing.Ring0InMemory)
            {
                if (_hotPath is null)
                    return Deny(invocation, assignment.Ring, "rust-hot-path", "Rust evaluator unavailable");
                var verdict = _hotPath.Evaluate(invocation.ToolName,
                    (int)assignment.Ring, invocation.PrincipalId);
                return verdict == HotPathVerdict.Allow
                    ? new("ok", invocation.ToolName, assignment.Ring.ToString(),
                        "rust-hot-path", invocation.Context.CorrelationId,
                        "Authorized in-memory operation", new { mode = "in-memory" })
                    : Deny(invocation, assignment.Ring, "rust-hot-path",
                        $"Hot-path verdict: {verdict}");
            }

            var output = await _worker.ExecuteAsync(invocation, assignment.Ring, cancellationToken);
            return new("ok", invocation.ToolName, assignment.Ring.ToString(),
                "restricted-worker", invocation.Context.CorrelationId,
                "Worker completed exactly one mock operation", output);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Deny(invocation, null, "fail-closed", $"Runtime failure: {ex.GetType().Name}");
        }
    }

    private static ToolExecutionResult Deny(ToolInvocation call, ExecutionRing? ring,
        string path, string reason) => new("denied", call.ToolName, ring?.ToString(), path,
            call.Context.CorrelationId, reason);
}
