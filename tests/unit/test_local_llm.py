"""Tests for local LLM discovery helpers."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestLocalLLM:
    def test_probe_ollama_healthy(self):
        from nova_arsenal.llm.local_llm import probe_ollama

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [{"name": "llama3.2:latest"}, {"name": "qwen2.5:7b"}]
        }

        with patch("nova_arsenal.llm.local_llm.httpx.Client") as Client:
            client = Client.return_value.__enter__.return_value
            client.get.return_value = mock_resp
            ep = probe_ollama("http://127.0.0.1:11434")
        assert ep.healthy is True
        assert "llama3.2:latest" in ep.models
        assert ep.preferred_model

    def test_probe_ollama_down(self):
        from nova_arsenal.llm.local_llm import probe_ollama

        with patch("nova_arsenal.llm.local_llm.httpx.Client") as Client:
            Client.return_value.__enter__.return_value.get.side_effect = ConnectionError("down")
            ep = probe_ollama("http://127.0.0.1:11434")
        assert ep.healthy is False
        assert ep.error

    def test_login_local_with_mock_probe(self, tmp_path, monkeypatch):
        from nova_arsenal.llm import account_auth as aa
        from nova_arsenal.llm.local_llm import LocalLLMEndpoint

        path = tmp_path / "accounts.json"
        monkeypatch.setattr(aa, "STORE_PATH", path)
        aa.reset_account_store()
        store = aa.AccountAuthStore(path=path)

        fake = LocalLLMEndpoint(
            kind="ollama",
            base_url="http://127.0.0.1:11434",
            models=["llama3.2"],
            healthy=True,
            preferred_model="llama3.2",
        )
        with patch("nova_arsenal.llm.local_llm.discover_local_llms", return_value=[fake]):
            cred = store.login_local_llm()
        assert cred.auth_type == "local"
        assert cred.provider == "ollama"
        assert cred.meta.get("model") == "llama3.2"
        aa.reset_account_store()
