"""Tests for bounded chat context formatting."""

from nova_arsenal.api.routes_chat import _format_history, _truncate_middle


def test_truncate_middle_keeps_both_ends():
    text = "BEGIN-" + ("x" * 200) + "-END"
    result = _truncate_middle(text, 80)

    assert len(result) <= 80
    assert result.startswith("BEGIN-")
    assert result.endswith("-END")
    assert "truncated" in result


def test_history_prefers_recent_turns_within_budget():
    messages = [
        {"role": "user", "content": "old " + ("a" * 100)},
        {"role": "assistant", "content": "middle " + ("b" * 100)},
        {"role": "user", "content": "latest request"},
    ]

    prompt = _format_history(messages, max_messages=10, max_chars=70)

    assert "latest request" in prompt
    assert "old " not in prompt
    assert prompt.endswith("Nova:")


def test_single_oversized_latest_message_is_bounded():
    messages = [
        {
            "role": "user",
            "content": "START " + ("z" * 5000) + " FINISH",
        }
    ]

    prompt = _format_history(messages, max_chars=500)

    assert len(prompt) <= 510  # continuation label adds a few characters
    assert "START " in prompt
    assert " FINISH" in prompt
    assert "truncated" in prompt
    assert prompt.endswith("Nova:")


def test_assistant_latest_does_not_add_continuation_label():
    prompt = _format_history(
        [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
    )

    assert prompt.endswith("Nova: hi")
    assert not prompt.endswith("Nova:\n\nNova:")


def test_history_message_count_limit():
    messages = [
        {"role": "user", "content": f"message-{index}"}
        for index in range(10)
    ]

    prompt = _format_history(messages, max_messages=3, max_chars=10_000)

    assert "message-6" not in prompt
    assert "message-7" in prompt
    assert "message-8" in prompt
    assert "message-9" in prompt
