"""Visible Chapter 6 permit/deny demonstration; no model or real tools used."""

from dataclasses import replace
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.delegation import (
    DelegationScope,
    InMemoryReplayCache,
    TokenSigner,
    TokenVerifier,
    WorkflowPhase,
    authorize_delegated_action,
    create_token,
)


def main() -> None:
    now = datetime.now(timezone.utc)
    key = Ed25519PrivateKey.generate()
    token = create_token(
        "python-security-analyzer",
        "dotnet-code-change-agent",
        "dotnet-code-change-agent",
        (DelegationScope.CREATE_PATCH,),
        WorkflowPhase.PATCH_CREATION,
        "corr-demo-001",
        "payments-api",
        now,
    )
    envelope = TokenSigner(key, token.issuer_id, token.key_id).sign(token)

    def new_verifier() -> TokenVerifier:
        return TokenVerifier(
            {(token.issuer_id, token.key_id): key.public_key()},
            token.audience_id,
            token.subject_id,
            InMemoryReplayCache(),
        )

    verified = new_verifier().verify(envelope)
    authorize_delegated_action(
        verified,
        DelegationScope.CREATE_PATCH,
        WorkflowPhase.PATCH_CREATION,
        "payments-api",
    )
    print("PERMIT: create_patch for payments-api")

    tampered = replace(
        envelope,
        scopes=(DelegationScope.RUN_APPROVED_TESTS.value,),
    )
    try:
        new_verifier().verify(tampered)
    except PermissionError as exc:
        print(f"DENY: {exc}")

    try:
        authorize_delegated_action(
            verified,
            DelegationScope.CREATE_PATCH,
            WorkflowPhase.PATCH_CREATION,
            "production-infrastructure",
        )
    except PermissionError as exc:
        print(f"DENY: {exc}")


if __name__ == "__main__":
    main()
