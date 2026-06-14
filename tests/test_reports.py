from prompt_injection_harness.reports import compare_reports


def result(case_id: str, status: str, findings: list[dict] | None = None) -> dict:
    return {"id": case_id, "name": case_id, "category": "unit", "status": status, "findings": findings or []}


def test_compare_reports_classifies_all_change_types() -> None:
    before = {
        "summary": {},
        "results": [
            result("fixed", "fail"),
            result("regressed", "pass"),
            result("changed", "review", [{"severity": "review", "check": "warning_pattern", "detail": "old"}]),
            result("removed", "pass"),
            result("unchanged", "pass"),
        ],
    }
    after = {
        "summary": {},
        "results": [
            result("fixed", "pass"),
            result("regressed", "fail"),
            result("changed", "review", [{"severity": "review", "check": "warning_pattern", "detail": "new"}]),
            result("new", "review"),
            result("unchanged", "pass"),
        ],
    }

    comparison = compare_reports(before, after)
    kinds = {change["id"]: change["kind"] for change in comparison["changes"]}

    assert comparison["summary"] == {
        "total": 6,
        "new": 1,
        "removed": 1,
        "fixed": 1,
        "regressed": 1,
        "changed": 1,
        "unchanged": 1,
    }
    assert kinds == {
        "changed": "changed",
        "fixed": "fixed",
        "new": "new",
        "regressed": "regressed",
        "removed": "removed",
        "unchanged": "unchanged",
    }
