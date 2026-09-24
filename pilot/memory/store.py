"""SQLite-backed persistent memory and short-term conversation manager.

Ensures zero secrets are persisted by running all text through the redaction engine.
Provides session-based storage, command history recording, and memory reset.
"""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional
import uuid

from pilot.config import get_settings
from pilot.llm.client import FunctionCall, Message, ToolCall
from pilot.security.redactor import redact_secrets


def sanitize_data(data: Any) -> Any:
    """Recursively sanitize dictionaries, lists, and strings for sensitive secrets."""
    if isinstance(data, str):
        return redact_secrets(data)
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if isinstance(k, str) and any(s in k.lower() for s in ("password", "passwd", "pwd")):
                sanitized[k] = "[REDACTED_PASSWORD]"
            elif isinstance(k, str) and any(
                s in k.lower() for s in ("secret", "token", "api_key", "apikey", "private_key")
            ):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_data(v)
        return sanitized
    if isinstance(data, list):
        return [sanitize_data(item) for item in data]
    return data


class SQLiteMemoryStore:
    """SQLite-backed persistence for agent conversation sessions and command history."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            settings = get_settings()
            self.db_path = Path(settings.db_path)

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a transactional database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create necessary database tables if they do not exist."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    title TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    name TEXT,
                    tool_call_id TEXT,
                    tool_calls TEXT,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    query TEXT NOT NULL,
                    tool_name TEXT,
                    arguments TEXT,
                    success INTEGER NOT NULL,
                    output_summary TEXT,
                    timestamp REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_history_timestamp ON command_history(timestamp DESC);
                """
            )

    def create_session(self, session_id: Optional[str] = None, title: str = "") -> str:
        """Create or register a conversation session."""
        sid = session_id or str(uuid.uuid4())
        now = time.time()
        clean_title = redact_secrets(title)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sessions (session_id, created_at, updated_at, title)
                VALUES (?, ?, ?, ?);
                """,
                (sid, now, now, clean_title),
            )
        return sid

    def save_message(self, session_id: str, message: Message) -> None:
        """Persist a single message after stripping/redacting any secrets."""
        self.create_session(session_id)
        now = time.time()

        clean_content = redact_secrets(message.content or "")
        clean_name = redact_secrets(message.name) if message.name else None

        tool_calls_json = None
        if message.tool_calls:
            calls_data = []
            for tc in message.tool_calls:
                calls_data.append({
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": sanitize_data(tc.function.arguments),
                    },
                })
            tool_calls_json = json.dumps(calls_data)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO messages (session_id, role, content, name, tool_call_id, tool_calls, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    session_id,
                    message.role,
                    clean_content,
                    clean_name,
                    message.tool_call_id,
                    tool_calls_json,
                    now,
                ),
            )
            conn.execute(
                """
                UPDATE sessions SET updated_at = ? WHERE session_id = ?;
                """,
                (now, session_id),
            )

    def save_messages(self, session_id: str, messages: List[Message]) -> None:
        """Persist a batch of messages for a session."""
        self.create_session(session_id)
        for msg in messages:
            self.save_message(session_id, msg)

    def get_messages(self, session_id: str) -> List[Message]:
        """Retrieve stored messages for a specific session."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT role, content, name, tool_call_id, tool_calls
                FROM messages
                WHERE session_id = ?
                ORDER BY id ASC;
                """,
                (session_id,),
            ).fetchall()

        result: List[Message] = []
        for r in rows:
            tool_calls = None
            if r["tool_calls"]:
                try:
                    raw_calls = json.loads(r["tool_calls"])
                    tool_calls = [
                        ToolCall(
                            id=rc.get("id"),
                            type=rc.get("type", "function"),
                            function=FunctionCall(
                                name=rc["function"]["name"],
                                arguments=rc["function"]["arguments"],
                            ),
                        )
                        for rc in raw_calls
                    ]
                except Exception:
                    tool_calls = None

            result.append(
                Message(
                    role=r["role"],
                    content=r["content"],
                    name=r["name"],
                    tool_call_id=r["tool_call_id"],
                    tool_calls=tool_calls,
                )
            )
        return result

    def record_command(
        self,
        session_id: str,
        query: str,
        tool_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        success: bool = True,
        output_summary: Optional[str] = None,
    ) -> None:
        """Record an executed query and tool interaction into persistent command history."""
        now = time.time()
        clean_query = redact_secrets(query)
        clean_summary = redact_secrets(output_summary or "") if output_summary else None

        args_str = None
        if arguments is not None:
            sanitized_args = sanitize_data(arguments)
            args_str = json.dumps(sanitized_args)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO command_history (session_id, query, tool_name, arguments, success, output_summary, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    session_id,
                    clean_query,
                    tool_name,
                    args_str,
                    1 if success else 0,
                    clean_summary,
                    now,
                ),
            )

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent command executions from history."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, session_id, query, tool_name, arguments, success, output_summary, timestamp
                FROM command_history
                ORDER BY timestamp DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        history = []
        for r in rows:
            args = None
            if r["arguments"]:
                try:
                    args = json.loads(r["arguments"])
                except Exception:
                    args = r["arguments"]

            history.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "query": r["query"],
                "tool_name": r["tool_name"],
                "arguments": args,
                "success": bool(r["success"]),
                "output_summary": r["output_summary"],
                "timestamp": r["timestamp"],
            })
        return history

    def reset_memory(self) -> None:
        """Clear all stored sessions, messages, and command history."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM messages;")
            conn.execute("DELETE FROM sessions;")
            conn.execute("DELETE FROM command_history;")

        # VACUUM outside active transaction using autocommit connection
        try:
            conn = sqlite3.connect(str(self.db_path), autocommit=True)
            conn.execute("VACUUM;")
            conn.close()
        except Exception:
            pass


class ConversationMemory:
    """Manages short-term conversation context for multi-turn dialogues with persistence backing."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        store: Optional[SQLiteMemoryStore] = None,
        enable_persistence: bool = True,
    ):
        self.store = store or SQLiteMemoryStore()
        self.session_id = session_id or self.store.create_session()
        self.enable_persistence = enable_persistence
        self._messages: List[Message] = []

        # Load existing messages if resuming an existing session
        if self.enable_persistence:
            saved = self.store.get_messages(self.session_id)
            if saved:
                self._messages = saved

    @property
    def messages(self) -> List[Message]:
        """Return the current active conversation messages."""
        return list(self._messages)

    def add_message(self, message: Message) -> None:
        """Append a message to short-term context and persist it."""
        self._messages.append(message)
        if self.enable_persistence:
            self.store.save_message(self.session_id, message)

    def update_messages(self, messages: List[Message]) -> None:
        """Update full in-memory message sequence (e.g. from AgentController output)."""
        new_count = len(messages)
        old_count = len(self._messages)
        self._messages = list(messages)

        # Persist newly added messages
        if self.enable_persistence and new_count > old_count:
            for msg in messages[old_count:]:
                self.store.save_message(self.session_id, msg)

    def clear(self) -> None:
        """Clear active short-term conversation context."""
        self._messages.clear()
