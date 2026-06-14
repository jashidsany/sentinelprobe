"""Target presets for common SentinelProbe workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PRESETS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "name": "claude-code",
        "target_type": "command",
        "summary": "Claude Code response-only prompt injection test.",
        "recommended_test": "direct",
        "safe_starter_command": "sentinelprobe claude-code",
        "setup_checks": ["sentinelprobe doctor --target claude-code"],
        "config": {
            "provider": "command",
            "command": "claude-code-wrapper --mode response-only --model sonnet --max-budget-usd 0.25",
            "timeout": 180,
            "tools": "disabled by wrapper in response-only mode",
        },
        "notes": [
            "Use first for low-risk response-only testing.",
            "This does not test file-based repo poisoning or agent tool behavior.",
        ],
    },
    "claude-code-agent-files": {
        "name": "claude-code-agent-files",
        "target_type": "command",
        "summary": "Claude Code file-based coding-agent prompt injection test.",
        "recommended_test": "agent-files",
        "safe_starter_command": "sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report",
        "setup_checks": ["sentinelprobe doctor --target claude-code"],
        "config": {
            "provider": "command",
            "command": "claude-code-wrapper --mode agent-sandbox --input-mode files --model sonnet --max-budget-usd 0.25",
            "timeout": 180,
            "workdir": "prompt_injection_harness/targets/claude_code_sandbox",
        },
        "notes": [
            "Writes fake test files into disposable per-case directories.",
            "Use only in approved sandboxes with fake documents and fake secrets.",
        ],
    },
    "glean-browser": {
        "name": "glean-browser",
        "target_type": "browser",
        "summary": "Browser-driven testing for an approved Glean tenant.",
        "recommended_test": "indirect",
        "safe_starter_command": (
            "sentinelprobe run --cases indirect --provider browser "
            "--browser-config prompt_injection_harness/browser_targets/glean_template.json --headed --timeout 180"
        ),
        "setup_checks": [
            "sentinelprobe doctor --target browser --browser-config prompt_injection_harness/browser_targets/glean_template.json"
        ],
        "config": {
            "provider": "browser",
            "browser_config": "prompt_injection_harness/browser_targets/glean_template.json",
            "timeout": 180,
            "headed_first_run": True,
        },
        "notes": [
            "Start with send_documents_inline enabled to validate selectors and scoring.",
            "For indexed-source testing, place fake documents in an approved sandbox source and disable inline documents.",
        ],
    },
    "generic-http": {
        "name": "generic-http",
        "target_type": "http",
        "summary": "Approved HTTP endpoint or internal test shim.",
        "recommended_test": "direct",
        "safe_starter_command": (
            "sentinelprobe run --cases direct --provider http "
            "--endpoint http://127.0.0.1:8080/ask --header 'Authorization: Bearer TEST_TOKEN'"
        ),
        "setup_checks": ["Confirm the endpoint is approved for testing and accepts SentinelProbe case JSON."],
        "config": {
            "provider": "http",
            "endpoint": "http://127.0.0.1:8080/ask",
            "headers": ["Authorization: Bearer TEST_TOKEN"],
            "timeout": 45,
        },
        "notes": [
            "The endpoint should return plain text or JSON with answer, response, text, message, content, or output.",
            "Do not put real credentials in preset files.",
        ],
    },
    "generic-browser": {
        "name": "generic-browser",
        "target_type": "browser",
        "summary": "Browser-driven testing for an approved AI web app.",
        "recommended_test": "direct",
        "safe_starter_command": (
            "sentinelprobe init-browser-config --output sentinelprobe-targets/generic_browser.json "
            "--base-url https://app.example.test"
        ),
        "setup_checks": ["sentinelprobe doctor --target browser --browser-config sentinelprobe-targets/generic_browser.json"],
        "config": {
            "provider": "browser",
            "browser_config": "sentinelprobe-targets/generic_browser.json",
            "timeout": 180,
            "headed_first_run": True,
        },
        "notes": [
            "Create and inspect a browser config before running cases.",
            "Use a persistent browser profile only for approved test accounts.",
        ],
    },
    "custom-command": {
        "name": "custom-command",
        "target_type": "command",
        "summary": "Custom local command that reads SentinelProbe case JSON on stdin.",
        "recommended_test": "direct",
        "safe_starter_command": (
            "sentinelprobe run --cases direct --provider command "
            "--command './my-approved-wrapper' --timeout 180 --verbose"
        ),
        "setup_checks": ["Run the wrapper manually with fake input before connecting it to SentinelProbe."],
        "config": {
            "provider": "command",
            "command": "./my-approved-wrapper",
            "timeout": 180,
        },
        "notes": [
            "The command must print the target response on stdout.",
            "Use shell quoting carefully and keep real secrets out of command strings.",
        ],
    },
}


def preset_names() -> list[str]:
    return sorted(PRESETS)


def get_preset(name: str) -> dict[str, Any]:
    try:
        return PRESETS[name]
    except KeyError as exc:
        raise SystemExit(f"Unknown preset {name!r}. Run 'sentinelprobe presets list'.") from exc


def render_preset_list() -> str:
    lines = ["Available presets", "-----------------"]
    for name in preset_names():
        preset = PRESETS[name]
        lines.append(f"{name:<24} {preset['target_type']:<8} {preset['summary']}")
    return "\n".join(lines)


def render_preset(name: str) -> str:
    preset = get_preset(name)
    lines = [
        f"Preset: {preset['name']}",
        f"Target type: {preset['target_type']}",
        f"Recommended test: {preset['recommended_test']}",
        "",
        "Safe starter command:",
        str(preset["safe_starter_command"]),
        "",
        "Setup checks:",
    ]
    lines.extend(f"- {item}" for item in preset.get("setup_checks", []))
    lines.extend(["", "Config:"])
    lines.append(json.dumps(preset.get("config", {}), indent=2, sort_keys=True))
    lines.extend(["", "Notes:"])
    lines.extend(f"- {item}" for item in preset.get("notes", []))
    return "\n".join(lines)


def write_preset(name: str, output: Path, force: bool = False) -> None:
    preset = get_preset(name)
    if output.exists() and not force:
        raise SystemExit(f"{output} already exists. Use --force to overwrite it.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(preset, indent=2, sort_keys=True) + "\n", encoding="utf-8")
