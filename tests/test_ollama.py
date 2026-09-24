"""Tests for environment configuration and Ollama connectivity."""

import pytest
import httpx
from pilot.config import Settings, get_settings


def test_settings_defaults():
    """Verify default settings values."""
    settings = Settings()
    assert settings.model == "qwen3:4b"
    assert settings.ollama_host == "http://localhost:11434"
    assert settings.max_agent_steps == 10
    assert settings.command_timeout == 30
    assert settings.dry_run is False
    assert len(settings.allowed_paths) >= 1


def test_settings_custom_allowed_paths():
    """Verify comma and colon separated paths parsing."""
    settings = Settings(ALLOWED_PATHS="/tmp/test,/home/user/code")
    assert settings.allowed_paths == ["/tmp/test", "/home/user/code"]

    settings_colon = Settings(ALLOWED_PATHS="/tmp/test:/home/user/code")
    assert settings_colon.allowed_paths == ["/tmp/test", "/home/user/code"]


def test_check_ollama_connection_mocked_success(mocker):
    """Test successful Ollama status response when mocked."""
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [
            {"name": "qwen3:4b"},
            {"name": "llama3:latest"},
        ]
    }

    mocker.patch("httpx.Client.get", return_value=mock_response)

    settings = Settings(MODEL="qwen3:4b")
    result = settings.check_ollama_connection()

    assert result["connected"] is True
    assert result["configured_model_found"] is True
    assert "qwen3:4b" in result["models"]
    assert result["error"] is None


def test_check_ollama_connection_mocked_failure(mocker):
    """Test unreachable Ollama response handling."""
    mocker.patch("httpx.Client.get", side_effect=httpx.ConnectError("Connection refused"))

    settings = Settings()
    result = settings.check_ollama_connection()

    assert result["connected"] is False
    assert result["configured_model_found"] is False
    assert result["error"] is not None


@pytest.mark.integration
def test_live_ollama_connectivity():
    """Test live connectivity against the running Ollama daemon."""
    settings = get_settings()
    status = settings.check_ollama_connection(timeout=5.0)

    assert status["connected"] is True, f"Failed to connect to Ollama at {settings.ollama_host}: {status.get('error')}"
    assert len(status["models"]) > 0, "Ollama has no models installed."
    assert status["configured_model_found"] is True, (
        f"Configured model '{settings.model}' was not found in Ollama models: {status['models']}"
    )


@pytest.mark.integration
def test_live_ollama_generate_ping():
    """Send a lightweight request to verify model inference responds."""
    settings = get_settings()
    url = f"{settings.ollama_host.rstrip('/')}/api/generate"

    payload = {
        "model": settings.model,
        "prompt": "Respond with OK",
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 128,
        },
    }

    with httpx.Client(timeout=60.0) as client:
        response = client.post(url, json=payload)
        assert response.status_code == 200, f"Ollama generate returned HTTP {response.status_code}: {response.text}"
        data = response.json()
        assert "response" in data, f"Response payload missing 'response' field: {data}"
        # Model returns either response content or thinking content
        assert len(data.get("response", "").strip()) > 0 or len(data.get("thinking", "").strip()) > 0
