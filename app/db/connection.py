from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parents[2] / "sqlite_schema.sql"


def connect_database(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    apply_pragmas(connection)
    return connection


def apply_pragmas(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode = WAL;")
    connection.execute("PRAGMA foreign_keys = ON;")
    connection.execute("PRAGMA busy_timeout = 5000;")
    connection.execute("PRAGMA synchronous = FULL;")


def initialize_database(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _chmod_private(database_path.parent, directory=True)
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect_database(database_path) as connection:
        connection.executescript(schema)
        _apply_lightweight_migrations(connection)
    _chmod_private(database_path)
    _chmod_private(Path(f"{database_path}-wal"))
    _chmod_private(Path(f"{database_path}-shm"))


def _chmod_private(path: Path, *, directory: bool = False) -> None:
    if not path.exists():
        return
    try:
        path.chmod(0o700 if directory else 0o600)
    except OSError:
        return


def _column_names(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _apply_lightweight_migrations(connection: sqlite3.Connection) -> None:
    admin_columns = _column_names(connection, "admins")
    if "must_change_password" not in admin_columns:
        connection.execute(
            """
            ALTER TABLE admins
            ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0
                CHECK (must_change_password IN (0, 1))
            """
        )
    message_columns = _column_names(connection, "messages")
    if "verification_code" not in message_columns:
        connection.execute(
            """
            ALTER TABLE messages
            ADD COLUMN verification_code TEXT
            """
        )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_metric_buckets (
            bucket_ts TEXT PRIMARY KEY,
            deliveries INTEGER NOT NULL DEFAULT 0,
            parse_failures INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS retention_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL CHECK (rule_type IN ('mailbox', 'domain', 'regex')),
            pattern TEXT NOT NULL,
            description TEXT,
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    _backfill_mail_metric_buckets(connection)


def _backfill_mail_metric_buckets(connection: sqlite3.Connection) -> None:
    existing = connection.execute("SELECT COUNT(*) AS count FROM mail_metric_buckets").fetchone()
    if existing is not None and int(existing["count"]) > 0:
        return
    connection.execute(
        """
        INSERT INTO mail_metric_buckets (bucket_ts, deliveries, parse_failures)
        SELECT
            substr(delivered_at, 1, 19) || 'Z' AS bucket_ts,
            COUNT(*) AS deliveries,
            0 AS parse_failures
        FROM message_deliveries
        WHERE status = 'active'
        GROUP BY bucket_ts
        ON CONFLICT(bucket_ts) DO UPDATE SET
            deliveries = mail_metric_buckets.deliveries + excluded.deliveries
        """
    )
    connection.execute(
        """
        INSERT INTO mail_metric_buckets (bucket_ts, deliveries, parse_failures)
        SELECT
            substr(received_at, 1, 19) || 'Z' AS bucket_ts,
            0 AS deliveries,
            COUNT(*) AS parse_failures
        FROM messages
        WHERE parse_status = 'failed'
        GROUP BY bucket_ts
        ON CONFLICT(bucket_ts) DO UPDATE SET
            parse_failures = mail_metric_buckets.parse_failures + excluded.parse_failures
        """
    )
