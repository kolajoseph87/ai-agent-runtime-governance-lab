# SecureCodingAgent — Current Evidence Gap Report

**Matrix:** `secure-coding-lab-2026.3`
**Audit scope:** Chapters 1B–8 educational controls
**Production certification:** No

| Risk | Status | Verified evidence | Remaining gap | Primary owner |
|---|---|---|---|---|
| T1 Memory Poisoning | External required | None | Memory write integrity and provenance | Data |
| T2 Tool Misuse | Verified in lab | Tool allowlist, inventory/scope authorization, ring routing | Production tool integrations still absent | Runtime |
| T3 Privilege Compromise | Partial | Least-privilege scopes and agent-policy binding | Verified workload identity | Runtime + Identity |
| T4 Resource Overload | Partial | Worker bounds, concurrency cap, policy latency budget, component readiness | Agent-wide request budget and kill switch | Infrastructure + Runtime |
| T5 Cascading Hallucinations | External required | None | Multi-agent human review and independent verification | Human process |
| T6 Goal Manipulation | Partial | Tested PRE_INPUT keyword policies | Adversarial semantic detection | Runtime |
| T7 Misaligned/Deceptive Behavior | External required | None | Model evaluation and independent red team | Framework + Human process |
| T8 Untraceability | Partial | Correlation propagation, structured policy events, local hash-chain verification | Durable independently protected audit evidence | Runtime + Infrastructure |
| T9 Identity Spoofing | Partial | Agent-policy binding and tool identity model | Cryptographically verified workload identity | Identity |
| T10 Human Approval Overload | External required | None | Approval risk tiers and queue throttling | Human process |

## Interpretation

`Verified in lab` means all capabilities required by this repository’s versioned matrix have implementation and passing-test references. It does not mean the risk is eliminated or that the project is production certified.

Generate the current machine-readable report and its configuration fingerprint with:

```bash
python python/control_audit.py
```

The fingerprint covers the exact policy rule content, attachment metadata, selected version, and tool-ring assignments. It detects configuration changes but is not a digital signature.

Production-style strict mode intentionally fails while partial findings exist:

```bash
python python/control_audit.py --fail-on-partial
```
