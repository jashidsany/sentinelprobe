"""JSON report helpers for SentinelProbe."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def write_report(path: Path, provider: str, results: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "total": len(results),
        "pass": sum(1 for item in results if item["status"] == "pass"),
        "review": sum(1 for item in results if item["status"] == "review"),
        "fail": sum(1 for item in results if item["status"] == "fail"),
    }
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "provider": provider,
        "summary": summary,
        "results": results,
    }
    if metadata:
        report["metadata"] = metadata
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return data


def result_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped = {}
    for result in report.get("results", []) or []:
        if isinstance(result, dict) and result.get("id") is not None:
            mapped[str(result.get("id"))] = result
    return mapped


def status_rank(status: Any) -> int:
    return {"pass": 0, "review": 1, "fail": 2}.get(str(status or "review").lower(), 1)


def finding_signature(result: dict[str, Any] | None) -> list[tuple[str, str, str]]:
    if not result:
        return []
    signatures = []
    for finding in result.get("findings", []) or []:
        if isinstance(finding, dict):
            signatures.append(
                (
                    str(finding.get("severity", "")),
                    str(finding.get("check", "")),
                    str(finding.get("detail", "")),
                )
            )
    return sorted(signatures)


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_results = result_map(before)
    after_results = result_map(after)
    case_ids = sorted(set(before_results) | set(after_results))
    changes = []
    summary = {
        "total": len(case_ids),
        "new": 0,
        "removed": 0,
        "fixed": 0,
        "regressed": 0,
        "changed": 0,
        "unchanged": 0,
    }
    for case_id in case_ids:
        before_item = before_results.get(case_id)
        after_item = after_results.get(case_id)
        if before_item is None:
            kind = "new"
        elif after_item is None:
            kind = "removed"
        else:
            before_status = str(before_item.get("status", "review"))
            after_status = str(after_item.get("status", "review"))
            if status_rank(after_status) > status_rank(before_status):
                kind = "regressed"
            elif status_rank(after_status) < status_rank(before_status):
                kind = "fixed"
            elif finding_signature(before_item) != finding_signature(after_item):
                kind = "changed"
            else:
                kind = "unchanged"
        summary[kind] += 1
        changes.append(
            {
                "id": case_id,
                "name": (after_item or before_item or {}).get("name"),
                "category": (after_item or before_item or {}).get("category"),
                "kind": kind,
                "before_status": before_item.get("status") if before_item else None,
                "after_status": after_item.get("status") if after_item else None,
                "before_findings": before_item.get("findings", []) if before_item else [],
                "after_findings": after_item.get("findings", []) if after_item else [],
            }
        )
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "before_summary": before.get("summary", {}),
        "after_summary": after.get("summary", {}),
        "summary": summary,
        "changes": changes,
    }
