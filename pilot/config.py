"""Configuration module for Linux Command Pilot.

Handles environment variable loading, default values, and runtime settings.
"""

from pathlib import Path
from typing import List, Union
import httpx
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM Settings
    model: str = Field(default="qwen3:4b", validation_alias="MODEL")
    ollama_host: str = Field(default="http://localhost:11434", validation_alias="OLLAMA_HOST")

    # Execution limits
    max_agent_steps: int = Field(default=10, validation_alias="MAX_AGENT_STEPS")
    command_timeout: int = Field(default=30, validation_alias="COMMAND_TIMEOUT")

    # Modes & Flags
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    dry_run: bool = Field(default=False, validation_alias="DRY_RUN")
    verbose: bool = Field(default=False, validation_alias="VERBOSE")

    # Filesystem security defaults
    allowed_paths: List[str] = Field(
        default_factory=lambda: [str(Path.cwd().resolve())],
        validation_alias="ALLOWED_PATHS",
    )

    # SQLite memory store location
    db_path: Path = Field(
        default_factory=lambda: Path.home() / ".config" / "linux-command-pilot" / "pilot.db",
        validation_alias="DB_PATH",
    )

    @field_validator("allowed_paths", mode="before")
    @classmethod
    def parse_allowed_paths(cls, v: Union[str, List[str]]) -> List[str]:
        """Support comma or colon-separated paths in environment variables."""
        if isinstance(v, str):
            delimiter = ":" if ":" in v and not v.startswith("http") else ","
            parts = [p.strip() for p in v.split(delimiter) if p.strip()]
            return parts or [str(Path.cwd().resolve())]
        return v

    def check_ollama_connection(self, timeout: float = 3.0) -> dict:
        """Verify reachability of the Ollama service and configured model.

        Returns:
            dict with 'connected', 'models', 'configured_model_found', and 'error' keys.
        """
        result = {
            "connected": False,
            "models": [],
            "configured_model_found": False,
            "error": None,
        }
        try:
            url = f"{self.ollama_host.rstrip('/')}/api/tags"
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url)
                if response.status_code == 200:
                    result["connected"] = True
                    data = response.json()
                    model_names = [m.get("name", "") for m in data.get("models", [])]
                    result["models"] = model_names

                    # Match exact name or prefix (e.g., 'qwen3:4b' or 'qwen3')
                    cfg_model = self.model
                    found = any(
                        cfg_model == m or m.startswith(f"{cfg_model}:") or cfg_model.startswith(f"{m}:")
                        for m in model_names
                    )
                    result["configured_model_found"] = found
                else:
                    result["error"] = f"HTTP {response.status_code}: {response.text}"
        except Exception as e:
            result["error"] = str(e)
        return result


def get_settings() -> Settings:
    """Retrieve an instantiated Settings object."""
    return Settings()
