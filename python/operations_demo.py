"""Visible Chapter 8 promotion, drift, health, and rollback demonstration."""

from pathlib import Path
from tempfile import TemporaryDirectory

from governance.audit import InMemoryAuditStore
from governance.coding_policy_set import SecureCodingPolicySet
from governance.operations import (
    DriftBaseline,
    FileVersionHistoryStore,
    GovernanceHealthProbe,
    OperationalPolicyRegistry,
    PolicyChannel,
    PolicyDriftDetector,
    PolicyPromotionPipeline,
    PolicyVersionResolver,
    RollbackController,
)
from governance.pipeline import PolicyAttachmentPoint
from governance.policy_engine import PolicyRegistry


def main() -> None:
    policies = PolicyRegistry()
    SecureCodingPolicySet.register_all(policies)
    registry = OperationalPolicyRegistry(policies)
    resolver = PolicyVersionResolver(registry)
    audit = InMemoryAuditStore()

    with TemporaryDirectory() as directory:
        history = FileVersionHistoryStore(Path(directory) / "history.jsonl")
        promotion = PolicyPromotionPipeline(registry, history, audit, resolver)

        registry.compare_and_activate(
            "secure-coding-input", PolicyChannel.DEV, "1.0.0", None
        )
        promotion.promote(
            "secure-coding-input", "1.0.0", PolicyChannel.DEV,
            PolicyChannel.STAGING, "corr-stage-100"
        )
        promotion.promote(
            "secure-coding-input", "1.0.0", PolicyChannel.STAGING,
            PolicyChannel.PROD, "corr-prod-100"
        )
        print("PROD active:", resolver.resolve(
            "secure-coding-input", PolicyChannel.PROD
        ))

        baseline = DriftBaseline(
            "secure-coding-input", PolicyChannel.PROD, "1.0.0",
            frozenset({PolicyAttachmentPoint.PRE_INPUT})
        )
        finding = PolicyDriftDetector(registry).detect(
            baseline, frozenset({PolicyAttachmentPoint.PRE_INPUT})
        )
        print("Drift detected:", finding.drifted)

        health = GovernanceHealthProbe({
            "policy-registry": lambda: resolver.resolve(
                "secure-coding-input", PolicyChannel.PROD
            ) is not None,
            "audit-integrity": audit.verify_integrity,
        })
        print("Ready:", health.ready())

        registry.compare_and_activate(
            "secure-coding-input", PolicyChannel.DEV, "1.1.0", "1.0.0"
        )
        promotion.promote(
            "secure-coding-input", "1.1.0", PolicyChannel.DEV,
            PolicyChannel.STAGING, "corr-stage-110"
        )
        promotion.promote(
            "secure-coding-input", "1.1.0", PolicyChannel.STAGING,
            PolicyChannel.PROD, "corr-prod-110"
        )
        restored = RollbackController(
            registry, history, audit, resolver
        ).rollback(
            "secure-coding-input", PolicyChannel.PROD, "1.1.0",
            "corr-rollback-110"
        )
        print("Rolled back to:", restored)
        print("Audit chain valid:", audit.verify_integrity())


if __name__ == "__main__":
    main()
