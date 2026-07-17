from owasp_mapping import OWASP_TOOLKIT_MAP


def resolve_package(risk_id: str) -> str:
    normalized = risk_id.strip().upper()
    for mapping in OWASP_TOOLKIT_MAP:
        if mapping.risk_id == normalized:
            return (
                mapping.toolkit_package
                if mapping.primary_defense_layer == "runtime"
                else "unmapped"
            )
    return "unmapped"


def runtime_coverage_gap(target_count: int) -> bool:
    runtime_count = sum(
        mapping.primary_defense_layer == "runtime"
        for mapping in OWASP_TOOLKIT_MAP
    )
    return runtime_count < target_count


if __name__ == "__main__":
    print(resolve_package("T3"))
    print(runtime_coverage_gap(7))

