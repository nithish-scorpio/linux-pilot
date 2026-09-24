"""Unit tests for Phase 10 Memory: short-term context and SQLite persistence."""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from pilot.llm.client import FunctionCall, Message, ToolCall
from pilot.main import app, execute_prompt
from pilot.memory.store import ConversationMemory, SQLiteMemoryStore


def test_sqlite_memory_store_lifecycle(tmp_path):
    """Verify SQLite database initialization, session creation, and message storage."""
    db_file = tmp_path / "test_pilot.db"
    store = SQLiteMemoryStore(db_path=db_file)
    assert db_file.exists()

    session_id = store.create_session(title="Troubleshoot Disk Space")
    assert session_id is not None

    msg1 = Message(role="user", content="Check my disk usage")
    msg2 = Message(role="assistant", content="Checking disks now...")
    store.save_messages(session_id, [msg1, msg2])

    retrieved = store.get_messages(session_id)
    assert len(retrieved) == 2
    assert retrieved[0].role == "user"
    assert retrieved[0].content == "Check my disk usage"
    assert retrieved[1].role == "assistant"
    assert retrieved[1].content == "Checking disks now..."


def test_sqlite_memory_never_persists_secrets(tmp_path):
    """Verify secrets are redacted before persistence into SQLite database."""
    db_file = tmp_path / "secure_pilot.db"
    store = SQLiteMemoryStore(db_path=db_file)
    session_id = store.create_session(title="Secret session")

    # Message with sensitive API key and DB password
    sensitive_msg = Message(
        role="assistant",
        content="Connecting with key AKIAIOSFODNN7EXAMPLE and postgres://admin:SuperSecretPass123@localhost/db",
    )
    store.save_message(session_id, sensitive_msg)

    # Command record with sensitive argument
    store.record_command(
        session_id=session_id,
        query="Connect to database with password='RootPassword999'",
        tool_name="connect_db",
        arguments={"password": "RootPassword999", "env_secret": "export API_KEY=sk_live_1234567890abcdef"},
        success=True,
    )

    # 1. Verify via store API
    messages = store.get_messages(session_id)
    assert len(messages) == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in messages[0].content
    assert "SuperSecretPass123" not in messages[0].content
    assert "[REDACTED_AWS_KEY_ID]" in messages[0].content
    assert "[REDACTED_DB_PASSWORD]" in messages[0].content

    history = store.get_history()
    assert len(history) == 1
    assert "RootPassword999" not in history[0]["query"]
    assert "[REDACTED_PASSWORD]" in history[0]["query"]
    assert "RootPassword999" not in str(history[0]["arguments"])
    assert "sk_live_1234567890abcdef" not in str(history[0]["arguments"])

    # 2. Raw binary inspection of sqlite file to guarantee secrets were never written to disk
    raw_db_bytes = db_file.read_bytes()
    assert b"AKIAIOSFODNN7EXAMPLE" not in raw_db_bytes
    assert b"SuperSecretPass123" not in raw_db_bytes
    assert b"RootPassword999" not in raw_db_bytes
    assert b"sk_live_1234567890abcdef" not in raw_db_bytes


def test_conversation_memory_short_term_context(tmp_path):
    """Verify ConversationMemory maintains in-memory context across multi-turn interactions."""
    db_file = tmp_path / "conv_pilot.db"
    store = SQLiteMemoryStore(db_path=db_file)
    memory = ConversationMemory(store=store)

    # Turn 1
    turn1_user = Message(role="user", content="Where is /var/log/nginx/error.log?")
    turn1_asst = Message(role="assistant", content="The log file exists and is 50MB.")
    memory.add_message(turn1_user)
    memory.add_message(turn1_asst)

    assert len(memory.messages) == 2
    assert memory.messages[0].content == "Where is /var/log/nginx/error.log?"

    # Turn 2: "remove it" references turn 1's error.log
    turn2_user = Message(role="user", content="Show the last 5 lines of it")
    memory.add_message(turn2_user)

    assert len(memory.messages) == 3
    assert memory.messages[2].content == "Show the last 5 lines of it"

    # Verify session resumption from SQLite
    resumed_memory = ConversationMemory(session_id=memory.session_id, store=store)
    assert len(resumed_memory.messages) == 3
    assert resumed_memory.messages[0].content == "Where is /var/log/nginx/error.log?"


def test_reset_memory(tmp_path):
    """Verify reset_memory purges all records."""
    db_file = tmp_path / "reset_pilot.db"
    store = SQLiteMemoryStore(db_path=db_file)
    sid = store.create_session()
    store.save_message(sid, Message(role="user", content="Temporary message"))
    store.record_command(sid, "temporary query", success=True)

    assert len(store.get_messages(sid)) == 1
    assert len(store.get_history()) == 1

    store.reset_memory()

    assert len(store.get_messages(sid)) == 0
    assert len(store.get_history()) == 0


def test_cli_history_and_reset(tmp_path, monkeypatch):
    """Verify CLI history and reset-memory commands via CliRunner."""
    db_file = tmp_path / "cli_pilot.db"
    monkeypatch.setenv("DB_PATH", str(db_file))

    store = SQLiteMemoryStore(db_path=db_file)
    store.record_command(
        session_id="session-1",
        query="Check memory usage",
        tool_name="memory_usage",
        success=True,
    )

    runner = CliRunner()

    # 1. Test history
    res_hist = runner.invoke(app, ["history"])
    assert res_hist.exit_code == 0
    assert "Check memory usage" in res_hist.stdout
    assert "memory_usage" in res_hist.stdout

    # 2. Test reset-memory
    res_reset = runner.invoke(app, ["reset-memory"])
    assert res_reset.exit_code == 0
    assert "reset successfully" in res_reset.stdout

    # 3. Verify history is now empty
    res_hist_empty = runner.invoke(app, ["history"])
    assert res_hist_empty.exit_code == 0
    assert "No persistent history recorded yet" in res_hist_empty.stdout
