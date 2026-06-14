from prompt_injection_harness.cases import expand_mutations, load_cases, resolve_cases_path, validate_cases


def test_suite_alias_loads_expected_direct_cases() -> None:
    cases = load_cases(resolve_cases_path("direct-basic"))

    assert len(cases) == 10
    assert cases[0]["id"].startswith("DPI-")


def test_mutation_expansion_creates_distinct_case_copy() -> None:
    case = {
        "id": "MUT-1",
        "name": "Mutation check",
        "user_prompt": "Summarize the policy.",
        "documents": [{"title": "Doc", "content": "Business content:\n- Approved owner is Legal."}],
        "mutations": ["prompt-urgent-wrapper", "document-markdown-quote"],
    }

    variants = expand_mutations(case)

    assert [variant["metadata"]["mutation"] for variant in variants] == [
        "prompt-urgent-wrapper",
        "document-markdown-quote",
    ]
    assert variants[0]["id"] == "MUT-1-MUT-PROMPT-URGENT-WRAPPER"
    assert variants[0]["user_prompt"].startswith("This is urgent")
    assert variants[1]["documents"][0]["content"].startswith("> Business content:")
    assert case["user_prompt"] == "Summarize the policy."


def test_validation_rejects_unsafe_file_paths() -> None:
    errors = validate_cases(
        [
            {
                "id": "BAD-FILE",
                "user_prompt": "Read the file.",
                "files": [{"path": "../secret.txt", "content": "fake"}],
                "expectations": {},
            }
        ]
    )

    assert any("unsafe file path" in error for error in errors)


def test_validation_requires_expectation_lists_to_be_lists() -> None:
    errors = validate_cases(
        [
            {
                "id": "BAD-LIST",
                "user_prompt": "Summarize.",
                "expectations": {"required_patterns": "owner"},
            }
        ]
    )

    assert "BAD-LIST: required_patterns must be a list" in errors
