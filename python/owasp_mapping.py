"""Immutable Chapter 1 threat-model metadata."""

from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspControlMapping:
    risk_id: str
    risk_name: str
    primary_defense_layer: str
    toolkit_package: str


OWASP_TOOLKIT_MAP: tuple[OwaspControlMapping, ...] = (
    OwaspControlMapping("T1", "Memory Poisoning", "data", "N/A"),
    OwaspControlMapping("T2", "Tool Misuse", "runtime", "agent-os-kernel"),
    OwaspControlMapping("T3", "Privilege Compromise", "runtime", "agentmesh-runtime"),
    OwaspControlMapping("T4", "Resource Overload", "runtime", "agentmesh-runtime"),
    OwaspControlMapping("T5", "Cascading Hallucination Attacks", "human process", "N/A"),
    OwaspControlMapping("T6", "Intent Breaking and Goal Manipulation", "runtime", "agent-os-kernel"),
    OwaspControlMapping("T7", "Misaligned and Deceptive Behaviors", "framework", "N/A"),
    OwaspControlMapping("T8", "Repudiation and Untraceability", "runtime", "agent-sre"),
    OwaspControlMapping("T9", "Identity Spoofing and Impersonation", "identity", "agentmesh-platform"),
    OwaspControlMapping("T10", "Overwhelming Human-in-the-Loop", "human process", "N/A"),
)

