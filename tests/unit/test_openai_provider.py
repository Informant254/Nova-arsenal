"""Tests for the OpenAI provider's API-mode behavior."""

from nova_arsenal.llm.openai import OpenAIProvider


def test_official_openai_uses_responses_api():
    provider = OpenAIProvider(
        model="gpt-5.6-terra",
        api_key="test-key",
        base_url="https://api.openai.com/v1",
    )
    assert provider.uses_responses_api is True


def test_openai_compatible_server_keeps_chat_completions():
    provider = OpenAIProvider(
        model="local-model",
        api_key="local",
        base_url="http://127.0.0.1:1234/v1",
    )
    assert provider.uses_responses_api is False


def test_api_mode_can_be_forced():
    provider = OpenAIProvider(
        model="custom",
        api_key="x",
        base_url="https://example.invalid/v1",
        api_mode="responses",
    )
    assert provider.uses_responses_api is True


def test_extract_response_text_from_raw_response():
    data = {
        "output": [
            {
                "type": "message",
                "content": [
                    {"type": "output_text", "text": "hello "},
                    {"type": "output_text", "text": "world"},
                ],
            }
        ]
    }
    assert OpenAIProvider._extract_response_text(data) == "hello world"


def test_responses_payload_uses_instructions_and_disables_storage():
    provider = OpenAIProvider(model="gpt-5.6-terra", api_key="x")
    payload = provider._responses_payload(
        "user prompt",
        "system prompt",
        2048,
        reasoning_effort="high",
    )

    assert payload["input"] == "user prompt"
    assert payload["instructions"] == "system prompt"
    assert payload["max_output_tokens"] == 2048
    assert payload["store"] is False
    assert payload["reasoning"] == {"effort": "high"}
