from risk_lookup import resolve_package, runtime_coverage_gap


def test_t3_resolves_to_runtime_supervisor() -> None:
    assert resolve_package("T3") == "agentmesh-runtime"


def test_non_runtime_risk_is_unmapped() -> None:
    assert resolve_package("T7") == "unmapped"


def test_unknown_risk_is_unmapped() -> None:
    assert resolve_package("T99") == "unmapped"


def test_target_of_seven_has_a_gap() -> None:
    assert runtime_coverage_gap(7) is True

