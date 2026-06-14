import json

import pytest

from prompt_injection_harness.presets import get_preset, preset_names, render_preset, render_preset_list, write_preset


def test_preset_names_include_common_targets() -> None:
    assert preset_names() == [
        "claude-code",
        "claude-code-agent-files",
        "custom-command",
        "generic-browser",
        "generic-http",
        "glean-browser",
    ]


def test_render_preset_includes_command_and_setup() -> None:
    rendered = render_preset("claude-code")

    assert "Preset: claude-code" in rendered
    assert "sentinelprobe claude-code" in rendered
    assert "sentinelprobe doctor --target claude-code" in rendered


def test_render_preset_list_includes_summaries() -> None:
    rendered = render_preset_list()

    assert "Available presets" in rendered
    assert "glean-browser" in rendered
    assert "generic-http" in rendered


def test_write_preset_writes_json(tmp_path) -> None:
    output = tmp_path / "preset.json"

    write_preset("generic-http", output)
    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["name"] == "generic-http"
    assert data["target_type"] == "http"
    assert data["config"]["provider"] == "http"


def test_write_preset_refuses_overwrite_without_force(tmp_path) -> None:
    output = tmp_path / "preset.json"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(SystemExit):
        write_preset("generic-http", output)

    write_preset("generic-http", output, force=True)
    assert json.loads(output.read_text(encoding="utf-8"))["name"] == "generic-http"


def test_unknown_preset_fails_cleanly() -> None:
    with pytest.raises(SystemExit) as exc_info:
        get_preset("missing")

    assert "Unknown preset" in str(exc_info.value)
