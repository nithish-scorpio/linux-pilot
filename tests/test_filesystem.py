"""Unit tests for Phase 8 filesystem tools, path boundary enforcement, and secret redaction."""

from pathlib import Path
import pytest

from pilot.security.path_checker import validate_path_access
from pilot.security.redactor import redact_secrets
from pilot.tools.filesystem import (
    ListDirectoryTool,
    ReadFileTool,
    SearchFilesTool,
    WriteFileTool,
)


def test_secret_redaction():
    """Verify redactor catches private keys, API keys, passwords, and tokens."""
    # 1. Private key
    rsa_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1+simulatedprivatekeydataABC123XYZ==\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert redact_secrets(rsa_key) == "[REDACTED_PRIVATE_KEY]"

    # 2. AWS Key
    aws_text = "Deploying with key AKIAIOSFODNN7EXAMPLE now"
    assert "AKIAIOSFODNN7EXAMPLE" not in redact_secrets(aws_text)
    assert "[REDACTED_AWS_KEY_ID]" in redact_secrets(aws_text)

    # 3. GitHub Token
    gh_text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
    assert "ghp_" not in redact_secrets(gh_text)
    assert "[REDACTED_GITHUB_TOKEN]" in redact_secrets(gh_text)

    # 4. Database URI Password
    db_uri = "postgres://admin:SuperSecretPass123@localhost:5432/mydb"
    sanitized_uri = redact_secrets(db_uri)
    assert "SuperSecretPass123" not in sanitized_uri
    assert "[REDACTED_DB_PASSWORD]" in sanitized_uri

    # 5. Password assignment
    pwd_line = 'database_password = "MyProdPassword99!"'
    sanitized_pwd = redact_secrets(pwd_line)
    assert "MyProdPassword99!" not in sanitized_pwd
    assert "[REDACTED_PASSWORD]" in sanitized_pwd

    # 6. Auth Header
    auth_header = "Authorization: Bearer supersecrettokenvalue123"
    sanitized_auth = redact_secrets(auth_header)
    assert "supersecrettokenvalue123" not in sanitized_auth
    assert "[REDACTED_AUTH_HEADER]" in sanitized_auth

    # 7. Secret Environment Variable
    env_var = "export CLIENT_SECRET=myverysecretclientvalue999"
    sanitized_env = redact_secrets(env_var)
    assert "myverysecretclientvalue999" not in sanitized_env
    assert "[REDACTED_SECRET_VAR]" in sanitized_env

    # 8. API Key with assignment
    api_var = "export STRIPE_API_KEY=sk_live_verysecretstripekey"
    sanitized_api = redact_secrets(api_var)
    assert "sk_live_verysecretstripekey" not in sanitized_api
    assert "[REDACTED_API_TOKEN]" in sanitized_api


def test_path_boundary_enforcement(tmp_path):
    """Verify path boundary restrictions and anti-tampering guards."""
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    forbidden_dir = tmp_path / "forbidden"
    forbidden_dir.mkdir()

    # Allowed path access
    ok, err, path = validate_path_access(str(allowed_dir / "file.txt"), allowed_paths=[str(allowed_dir)])
    assert ok is True
    assert err is None

    # Outside allowed roots
    ok, err, path = validate_path_access(str(forbidden_dir / "file.txt"), allowed_paths=[str(allowed_dir)])
    assert ok is False
    assert "outside allowed directories" in err

    # Path traversal breakout attempt
    traversal = str(allowed_dir / ".." / "forbidden" / "file.txt")
    ok, err, path = validate_path_access(traversal, allowed_paths=[str(allowed_dir)])
    assert ok is False
    assert "outside allowed directories" in err

    # Sensitive system path (/etc/shadow)
    ok, err, path = validate_path_access("/etc/shadow", allowed_paths=["/etc"])
    assert ok is False
    assert "strictly prohibited" in err

    # Anti-tampering: modifying .env
    env_file = allowed_dir / ".env"
    ok, err, path = validate_path_access(str(env_file), allowed_paths=[str(allowed_dir)], for_write=True)
    assert ok is False
    assert "protected configuration file" in err

    # Anti-tampering: modifying pilot/security/validator.py
    sec_code = allowed_dir / "pilot" / "security" / "validator.py"
    sec_code.parent.mkdir(parents=True)
    ok, err, path = validate_path_access(str(sec_code), allowed_paths=[str(allowed_dir)], for_write=True)
    assert ok is False
    assert "Modifying the security layer codebase is strictly prohibited" in err


def test_list_directory_tool(tmp_path, monkeypatch):
    """Verify list_directory returns structured file listings."""
    test_dir = tmp_path / "list_test"
    test_dir.mkdir()
    (test_dir / "a.txt").write_text("file a")
    (test_dir / "b.log").write_text("file b")
    (test_dir / "subdir").mkdir()

    monkeypatch.setenv("ALLOWED_PATHS", str(tmp_path))
    tool = ListDirectoryTool()
    res = tool.execute({"path": str(test_dir)})

    assert res.success is True
    assert res.data["count"] == 3
    names = [e["name"] for e in res.data["entries"]]
    assert "a.txt" in names
    assert "b.log" in names
    assert "subdir" in names


def test_read_file_tool_with_redaction(tmp_path, monkeypatch):
    """Verify read_file bounds lines and redacts embedded secrets."""
    secret_file = tmp_path / "config.ini"
    secret_file.write_text(
        "server=localhost\n"
        "api_key=AKIAIOSFODNN7EXAMPLE\n"
        "admin_pwd='MySecretPassword123'\n"
    )

    monkeypatch.setenv("ALLOWED_PATHS", str(tmp_path))
    tool = ReadFileTool()
    res = tool.execute({"path": str(secret_file), "max_lines": 10})

    assert res.success is True
    assert "AKIAIOSFODNN7EXAMPLE" not in res.stdout
    assert "MySecretPassword123" not in res.stdout
    assert "[REDACTED_AWS_KEY_ID]" in res.stdout
    assert "[REDACTED_PASSWORD]" in res.stdout


def test_search_files_tool(tmp_path, monkeypatch):
    """Verify search_files finds matches by pattern and content."""
    search_dir = tmp_path / "search_test"
    search_dir.mkdir()
    (search_dir / "main.py").write_text("def run_pilot(): pass")
    (search_dir / "helper.py").write_text("def parse_pilot_args(): pass")
    (search_dir / "readme.md").write_text("# Pilot Readme")

    monkeypatch.setenv("ALLOWED_PATHS", str(tmp_path))
    tool = SearchFilesTool()

    # Match by glob pattern
    res_glob = tool.execute({"path": str(search_dir), "pattern": "*.py"})
    assert res_glob.success is True
    assert res_glob.data["count"] == 2

    # Match by content search
    res_content = tool.execute({
        "path": str(search_dir),
        "pattern": "*.py",
        "content_search": "run_pilot",
    })
    assert res_content.success is True
    assert res_content.data["count"] == 1
    assert "main.py" in res_content.data["matches"][0]["path"]


def test_write_file_tool_new_file(tmp_path, monkeypatch):
    """Verify write_file creates new file with verification."""
    target_file = tmp_path / "new_note.txt"
    monkeypatch.setenv("ALLOWED_PATHS", str(tmp_path))

    # Approve write
    tool = WriteFileTool(confirm_handler=lambda cmd, reason, risk: True)
    res = tool.execute({
        "path": str(target_file),
        "content": "Hello Linux Command Pilot\nLine 2",
        "reason": "Create notes",
    })

    assert res.success is True
    assert target_file.exists()
    assert target_file.read_text() == "Hello Linux Command Pilot\nLine 2"
    assert res.data["bytes_written"] == len("Hello Linux Command Pilot\nLine 2")


def test_write_file_tool_modify_with_backup(tmp_path, monkeypatch):
    """Verify modifying an existing file creates a backup copy."""
    target_file = tmp_path / "existing.txt"
    target_file.write_text("Original version content")
    monkeypatch.setenv("ALLOWED_PATHS", str(tmp_path))

    tool = WriteFileTool(confirm_handler=lambda cmd, reason, risk: True)
    res = tool.execute({
        "path": str(target_file),
        "content": "Updated version content",
        "reason": "Update content",
    })

    assert res.success is True
    assert target_file.read_text() == "Updated version content"

    # Verify backup exists and contains original content
    backup_path = Path(res.data["backup_path"])
    assert backup_path.exists()
    assert backup_path.read_text() == "Original version content"


def test_write_file_tool_denied(tmp_path, monkeypatch):
    """Verify rejected write operation preserves original file."""
    target_file = tmp_path / "secure.txt"
    target_file.write_text("Untouchable content")
    monkeypatch.setenv("ALLOWED_PATHS", str(tmp_path))

    # Deny write
    tool = WriteFileTool(confirm_handler=lambda cmd, reason, risk: False)
    res = tool.execute({
        "path": str(target_file),
        "content": "Malicious overwrite",
    })

    assert res.success is False
    assert "User rejected" in res.error
    assert target_file.read_text() == "Untouchable content"


def test_controller_redacts_tool_output_in_messages():
    """Verify AgentController redacts secrets from any tool output before placing into message context."""
    from unittest.mock import MagicMock
    from pilot.agent.controller import AgentController
    from pilot.llm.client import FunctionCall, LLMResponse, ToolCall
    from pilot.tools.base import BaseTool, RiskTier, ToolResult
    from pilot.tools.registry import ToolRegistry

    registry = ToolRegistry()

    class SecretLeakingTool(BaseTool):
        name = "leak_secret"
        description = "Leaking tool"
        risk_tier = RiskTier.SAFE

        @property
        def parameters_schema(self):
            return {"type": "object", "properties": {}}

        def run(self, arguments, timeout=30.0):
            return ToolResult(
                success=True,
                stdout="Server secret: AKIAIOSFODNN7EXAMPLE and password='TopSecretPassword123'",
            )

    registry.register(SecretLeakingTool())

    mock_llm = MagicMock()
    mock_llm.chat.side_effect = [
        LLMResponse(
            content=None,
            tool_calls=[
                ToolCall(
                    id="call_1",
                    function=FunctionCall(name="leak_secret", arguments={}),
                )
            ],
        ),
        LLMResponse(content="Final summary after seeing redacted tool output"),
    ]

    controller = AgentController(llm_provider=mock_llm, tool_registry=registry)
    response = controller.run("Check the server secrets")

    assert response.completed is True
    tool_msg = next(m for m in response.messages if m.role == "tool")
    assert "AKIAIOSFODNN7EXAMPLE" not in tool_msg.content
    assert "TopSecretPassword123" not in tool_msg.content
    assert "[REDACTED_AWS_KEY_ID]" in tool_msg.content
    assert "[REDACTED_PASSWORD]" in tool_msg.content

