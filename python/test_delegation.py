from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.delegation import (
    DelegationScope,
    HandoffStatus,
    HandoffStore,
    InMemoryReplayCache,
    SharedMemoryEntry,
    SharedMemorySegment,
    TokenSigner,
    TokenVerifier,
    WorkflowPhase,
    authorize_delegated_action,
    create_token,
)


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def signed_fixture():
    private_key = Ed25519PrivateKey.generate()
    token = create_token(
        issuer_id="python-security-analyzer",
        subject_id="dotnet-code-change-agent",
        audience_id="dotnet-code-change-agent",
        scopes=(DelegationScope.CREATE_PATCH,),
        phase=WorkflowPhase.PATCH_CREATION,
        correlation_id="corr-4821",
        repository_id="payments-api",
        now=NOW,
    )
    envelope = TokenSigner(private_key, token.issuer_id, token.key_id).sign(token)
    verifier = TokenVerifier(
        {(token.issuer_id, token.key_id): private_key.public_key()},
        expected_audience_id=token.audience_id,
        expected_subject_id=token.subject_id,
        replay_cache=InMemoryReplayCache(clock=lambda: NOW),
        clock=lambda: NOW,
    )
    return token, envelope, verifier


def test_valid_scoped_delegation_is_permitted():
    _, envelope, verifier = signed_fixture()
    verified = verifier.verify(envelope)
    authorize_delegated_action(
        verified,
        DelegationScope.CREATE_PATCH,
        WorkflowPhase.PATCH_CREATION,
        "payments-api",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scopes", (DelegationScope.RUN_APPROVED_TESTS.value,)),
        ("phase", WorkflowPhase.TESTING.value),
        ("repository_id", "payroll-api"),
        ("correlation_id", "corr-attacker"),
    ],
)
def test_tampering_with_any_authorization_claim_breaks_signature(field, value):
    _, envelope, verifier = signed_fixture()
    with pytest.raises(PermissionError, match="signature"):
        verifier.verify(replace(envelope, **{field: value}))


def test_wrong_audience_is_denied():
    private_key = Ed25519PrivateKey.generate()
    token = create_token(
        "issuer", "receiver", "wrong-audience",
        (DelegationScope.CREATE_PATCH,), WorkflowPhase.PATCH_CREATION,
        "corr-audience", "payments-api", NOW,
    )
    envelope = TokenSigner(private_key, token.issuer_id, token.key_id).sign(token)
    verifier = TokenVerifier(
        {(token.issuer_id, token.key_id): private_key.public_key()},
        "receiver", "receiver", InMemoryReplayCache(clock=lambda: NOW),
        clock=lambda: NOW,
    )
    with pytest.raises(PermissionError, match="audience"):
        verifier.verify(envelope)


def test_replayed_token_is_denied():
    _, envelope, verifier = signed_fixture()
    verifier.verify(envelope)
    with pytest.raises(PermissionError, match="replay"):
        verifier.verify(envelope)


def test_expired_token_is_denied():
    private_key = Ed25519PrivateKey.generate()
    token = create_token(
        "issuer", "receiver", "receiver",
        (DelegationScope.CREATE_PATCH,),
        WorkflowPhase.PATCH_CREATION,
        "corr-expired", "payments-api", NOW - timedelta(minutes=6),
    )
    envelope = TokenSigner(private_key, "issuer", token.key_id).sign(token)
    verifier = TokenVerifier(
        {("issuer", token.key_id): private_key.public_key()}, "receiver", "receiver",
        InMemoryReplayCache(clock=lambda: NOW), clock=lambda: NOW,
    )
    with pytest.raises(PermissionError, match="expired"):
        verifier.verify(envelope)


def test_empty_scopes_and_excessive_delegation_depth_are_denied():
    _, envelope, verifier = signed_fixture()
    with pytest.raises(PermissionError, match="scopes"):
        verifier.verify(replace(envelope, scopes=()))

    _, envelope, verifier = signed_fixture()
    with pytest.raises(PermissionError, match="depth"):
        verifier.verify(replace(envelope, delegation_depth=2))


def test_scope_phase_and_repository_are_all_required():
    _, envelope, verifier = signed_fixture()
    token = verifier.verify(envelope)
    with pytest.raises(PermissionError, match="scope"):
        authorize_delegated_action(
            token, DelegationScope.RUN_APPROVED_TESTS,
            WorkflowPhase.PATCH_CREATION, "payments-api"
        )
    with pytest.raises(PermissionError, match="phase"):
        authorize_delegated_action(
            token, DelegationScope.CREATE_PATCH,
            WorkflowPhase.TESTING, "payments-api"
        )
    with pytest.raises(PermissionError, match="repository"):
        authorize_delegated_action(
            token, DelegationScope.CREATE_PATCH,
            WorkflowPhase.PATCH_CREATION, "payroll-api"
        )


def test_shared_memory_enforces_workflow_segment_and_entry_phases():
    segment = SharedMemorySegment(
        "patch-4821", "corr-4821",
        write_phases=frozenset({WorkflowPhase.ANALYSIS}),
        read_phases=frozenset({WorkflowPhase.PATCH_CREATION, WorkflowPhase.TESTING}),
    )
    entry = SharedMemoryEntry.from_json(
        "finding",
        {"file": "PaymentService.cs", "risk": "SQL injection"},
        WorkflowPhase.ANALYSIS,
        frozenset({WorkflowPhase.PATCH_CREATION}),
    )
    segment.write(entry, WorkflowPhase.ANALYSIS, "corr-4821")
    assert segment.read(
        "finding", WorkflowPhase.PATCH_CREATION, "corr-4821"
    ).json_value()["risk"] == "SQL injection"

    with pytest.raises(PermissionError, match="entry"):
        segment.read("finding", WorkflowPhase.TESTING, "corr-4821")
    with pytest.raises(PermissionError, match="workflow"):
        segment.read("finding", WorkflowPhase.PATCH_CREATION, "corr-other")


def test_handoff_lifecycle_rejects_invalid_transitions_and_expires():
    current = NOW
    store = HandoffStore(clock=lambda: current)
    store.create("corr-4821", "token-1", timedelta(minutes=5))
    store.transition("corr-4821", HandoffStatus.ACTIVE)
    store.transition("corr-4821", HandoffStatus.COMPLETED)
    with pytest.raises(PermissionError, match="invalid"):
        store.transition("corr-4821", HandoffStatus.ACTIVE)

    clock = [NOW]
    expiring = HandoffStore(clock=lambda: clock[0])
    expiring.create("corr-expire", "token-2", timedelta(minutes=5))
    clock[0] = NOW + timedelta(minutes=6)
    assert expiring.recover_or_expire("corr-expire") is HandoffStatus.EXPIRED
