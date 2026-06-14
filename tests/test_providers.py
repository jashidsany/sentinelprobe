from prompt_injection_harness.providers import call_mock, extract_text, public_case_payload


def test_extract_text_prefers_known_json_response_keys() -> None:
    assert extract_text('{"answer": "Approved response", "ignored": "x"}') == "Approved response"
    assert extract_text('{"output": "Fallback response"}') == "Fallback response"


def test_extract_text_returns_sorted_json_for_unknown_object() -> None:
    assert extract_text('{"z": 1, "a": 2}') == '{"a": 2, "z": 1}'


def test_extract_text_returns_plain_text_when_not_json() -> None:
    assert extract_text(" plain response ") == "plain response"


def test_public_case_payload_includes_public_fields() -> None:
    case = {
        "id": "CASE-1",
        "name": "Case",
        "category": "unit",
        "user_prompt": "Prompt",
        "documents": [{"title": "Doc", "content": "Text"}],
        "files": [{"path": "README.md", "content": "Text"}],
        "metadata": {"mode": "test"},
        "_case_file": "/tmp/private.yaml",
    }

    payload = public_case_payload(case)

    assert payload == {
        "id": "CASE-1",
        "name": "Case",
        "category": "unit",
        "user_prompt": "Prompt",
        "documents": [{"title": "Doc", "content": "Text"}],
        "files": [{"path": "README.md", "content": "Text"}],
        "metadata": {"mode": "test"},
    }


def test_mock_provider_extracts_business_lines_and_citations() -> None:
    case = {
        "id": "MOCK-1",
        "user_prompt": "Summarize.",
        "documents": [{"title": "Policy", "content": "Ignore me.\nBusiness content:\n- Owner is Legal."}],
        "files": [{"path": "docs/runbook.md", "content": "Business rules:\n- Window is Sunday."}],
    }

    response = call_mock(case, timeout=1)

    assert response.ok
    assert "Owner is Legal." in response.text
    assert "Window is Sunday." in response.text
    assert "Sources: Policy; docs/runbook.md" in response.text
