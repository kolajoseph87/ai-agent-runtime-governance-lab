using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text.Json;

public enum DelegationScope
{
    ReadRepository,
    CreatePatch,
    RunApprovedTests
}

public enum WorkflowPhase
{
    Intake,
    Analysis,
    PatchCreation,
    Testing,
    HumanReview,
    Completion
}

public enum HandoffStatus
{
    Pending,
    Active,
    Completed,
    Expired,
    Denied
}

public sealed record DelegationEnvelope(
    string TokenId,
    string IssuerId,
    string SubjectId,
    string AudienceId,
    ImmutableArray<string> Scopes,
    string Phase,
    string CorrelationId,
    string RepositoryId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string Nonce,
    string KeyId,
    int DelegationDepth,
    string Signature);

public sealed record VerifiedDelegation(
    string TokenId,
    string IssuerId,
    string SubjectId,
    string AudienceId,
    ImmutableHashSet<DelegationScope> Scopes,
    WorkflowPhase Phase,
    string CorrelationId,
    string RepositoryId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string Nonce,
    string KeyId,
    int DelegationDepth);

/// <summary>
/// Cryptographic verification is an explicit dependency. The receiver cannot
/// accidentally treat deserialization as authentication. The production
/// implementation must verify the same canonical Ed25519 claims as the Go mesh.
/// </summary>
public interface IDelegationTokenVerifier
{
    VerifiedDelegation Verify(DelegationEnvelope envelope);
}

public sealed class DenyAllDelegationTokenVerifier : IDelegationTokenVerifier
{
    public VerifiedDelegation Verify(DelegationEnvelope envelope) =>
        throw new UnauthorizedAccessException(
            "No cryptographic delegation verifier is configured; failed closed");
}

public sealed class DelegationAcceptor
{
    private readonly IDelegationTokenVerifier _verifier;
    private readonly string _expectedSubject;
    private readonly string _expectedAudience;

    public DelegationAcceptor(
        IDelegationTokenVerifier verifier,
        string expectedSubject,
        string expectedAudience)
    {
        _verifier = verifier;
        _expectedSubject = expectedSubject;
        _expectedAudience = expectedAudience;
    }

    public VerifiedDelegation Accept(DelegationEnvelope envelope)
    {
        if (!string.Equals(envelope.SubjectId, _expectedSubject, StringComparison.Ordinal) ||
            !string.Equals(envelope.AudienceId, _expectedAudience, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Delegation receiver binding mismatch");

        return _verifier.Verify(envelope);
    }
}

public static class DelegatedActionAuthorizer
{
    public static void Demand(
        VerifiedDelegation token,
        DelegationScope requiredScope,
        WorkflowPhase requiredPhase,
        string repositoryId)
    {
        if (!token.Scopes.Contains(requiredScope))
            throw new UnauthorizedAccessException($"Delegation lacks {requiredScope} scope");
        if (token.Phase != requiredPhase)
            throw new UnauthorizedAccessException("Delegation is invalid in this workflow phase");
        if (!string.Equals(token.RepositoryId, repositoryId, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Delegation is bound to another repository");
        if (token.DelegationDepth is < 0 or > 1)
            throw new UnauthorizedAccessException("Delegation depth exceeds the permitted limit");
        if (token.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Delegation expired");
    }
}

public sealed record SharedMemoryEntry(
    string Key,
    ImmutableArray<byte> SerializedValue,
    WorkflowPhase WrittenInPhase,
    ImmutableHashSet<WorkflowPhase> ReadablePhases)
{
    public static SharedMemoryEntry FromJson<T>(
        string key,
        T value,
        WorkflowPhase writtenInPhase,
        ImmutableHashSet<WorkflowPhase> readablePhases) =>
        new(key, JsonSerializer.SerializeToUtf8Bytes(value).ToImmutableArray(),
            writtenInPhase, readablePhases);

    public T? ReadJson<T>() => JsonSerializer.Deserialize<T>(SerializedValue.AsSpan());
}

public sealed class GovernedSharedMemorySegment
{
    private readonly ConcurrentDictionary<string, SharedMemoryEntry> _entries = new();
    private readonly ImmutableHashSet<WorkflowPhase> _writePhases;
    private readonly ImmutableHashSet<WorkflowPhase> _readPhases;

    public string SegmentId { get; }
    public string CorrelationId { get; }

    public GovernedSharedMemorySegment(
        string segmentId,
        string correlationId,
        ImmutableHashSet<WorkflowPhase> writePhases,
        ImmutableHashSet<WorkflowPhase> readPhases)
    {
        SegmentId = segmentId;
        CorrelationId = correlationId;
        _writePhases = writePhases;
        _readPhases = readPhases;
    }

    public void Write(
        SharedMemoryEntry entry,
        WorkflowPhase currentPhase,
        string correlationId)
    {
        DemandWorkflow(correlationId);
        if (!_writePhases.Contains(currentPhase) || entry.WrittenInPhase != currentPhase)
            throw new UnauthorizedAccessException("Shared-memory write phase denied");
        _entries[entry.Key] = entry;
    }

    public SharedMemoryEntry? Read(
        string key,
        WorkflowPhase currentPhase,
        string correlationId)
    {
        DemandWorkflow(correlationId);
        if (!_readPhases.Contains(currentPhase))
            throw new UnauthorizedAccessException("Shared-memory segment phase denied");
        if (!_entries.TryGetValue(key, out var entry))
            return null;
        if (!entry.ReadablePhases.Contains(currentPhase))
            throw new UnauthorizedAccessException("Shared-memory entry phase denied");
        return entry;
    }

    private void DemandWorkflow(string correlationId)
    {
        if (!string.Equals(CorrelationId, correlationId, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Shared-memory workflow mismatch");
    }
}

public sealed class CodeChangeReceivingAgent
{
    private readonly DelegationAcceptor _acceptor;
    private readonly GovernedSharedMemorySegment _memory;

    public CodeChangeReceivingAgent(
        DelegationAcceptor acceptor,
        GovernedSharedMemorySegment memory)
    {
        _acceptor = acceptor;
        _memory = memory;
    }

    public JsonElement ReceivePatchRequest(
        DelegationEnvelope envelope,
        string repositoryId)
    {
        var token = _acceptor.Accept(envelope);
        DelegatedActionAuthorizer.Demand(
            token,
            DelegationScope.CreatePatch,
            WorkflowPhase.PatchCreation,
            repositoryId);

        var entry = _memory.Read(
            "finding",
            WorkflowPhase.PatchCreation,
            token.CorrelationId)
            ?? throw new InvalidOperationException("Missing governed handoff context");

        // This lab returns the proposed work item. It still does not change files.
        return entry.ReadJson<JsonElement>();
    }
}

public static class Chapter6Diagnostics
{
    public static void Run()
    {
        var envelope = new DelegationEnvelope(
            "token-demo", "python-security-analyzer", "dotnet-code-change-agent",
            "dotnet-code-change-agent", ["create_patch"], "patch_creation",
            "corr-ch6-demo", "payments-api", DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5), "nonce-demo", "lab-key-1", 0,
            "not-a-real-signature");

        var acceptor = new DelegationAcceptor(
            new DenyAllDelegationTokenVerifier(),
            "dotnet-code-change-agent",
            "dotnet-code-change-agent");
        try
        {
            acceptor.Accept(envelope);
            throw new InvalidOperationException("Chapter 6 fail-closed diagnostic failed");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"Chapter 6 .NET receiver DENY: {ex.Message}");
        }
    }
}
