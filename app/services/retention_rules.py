from __future__ import annotations

import re
import sqlite3
from typing import Any

from app.db.connection import connect_database
from app.ingest.storage import utc_now


class RetentionRuleService:
    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime
        self._rules: list[dict[str, Any]] = []
        self._compiled_patterns: dict[int, re.Pattern[str]] = {}

    def load_rules(self) -> None:
        with connect_database(self._runtime.settings.database_path) as connection:
            rows = connection.execute(
                "SELECT id, rule_type, pattern, description, is_active, created_at, updated_at "
                "FROM retention_rules ORDER BY id ASC"
            ).fetchall()
        self._rules = [dict(row) for row in rows]
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._compiled_patterns.clear()
        for rule in self._rules:
            if rule["rule_type"] == "regex" and rule["is_active"]:
                try:
                    self._compiled_patterns[rule["id"]] = re.compile(rule["pattern"], re.IGNORECASE)
                except re.error:
                    pass

    def list_rules(self) -> list[dict[str, Any]]:
        return list(self._rules)

    def get_rule(self, rule_id: int) -> dict[str, Any] | None:
        for rule in self._rules:
            if rule["id"] == rule_id:
                return rule
        return None

    async def create_rule(self, rule_type: str, pattern: str, description: str = "") -> dict[str, Any]:
        if rule_type not in ("mailbox", "domain", "regex"):
            raise ValueError("无效的规则类型")
        pattern = pattern.strip()
        if not pattern:
            raise ValueError("匹配模式不能为空")
        if rule_type == "regex":
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"无效的正则表达式: {exc}") from exc

        now = utc_now()

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            cursor = connection.execute(
                """
                INSERT INTO retention_rules (rule_type, pattern, description, is_active, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (rule_type, pattern, description or None, now, now),
            )
            return {
                "id": cursor.lastrowid,
                "rule_type": rule_type,
                "pattern": pattern,
                "description": description or None,
                "is_active": 1,
                "created_at": now,
                "updated_at": now,
            }

        result = await self._runtime.writer.execute(operation)
        self.load_rules()
        return result

    async def toggle_rule(self, rule_id: int) -> None:
        rule = self.get_rule(rule_id)
        if rule is None:
            raise ValueError("规则不存在")
        new_status = 0 if rule["is_active"] else 1
        now = utc_now()

        def operation(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE retention_rules SET is_active = ?, updated_at = ? WHERE id = ?",
                (new_status, now, rule_id),
            )

        await self._runtime.writer.execute(operation)
        self.load_rules()

    async def delete_rule(self, rule_id: int) -> None:
        def operation(connection: sqlite3.Connection) -> None:
            connection.execute("DELETE FROM retention_rules WHERE id = ?", (rule_id,))

        await self._runtime.writer.execute(operation)
        self.load_rules()

    def get_retained_message_ids(self, candidate_ids: list[str]) -> set[str]:
        if not candidate_ids:
            return set()
        active_rules = [r for r in self._rules if r["is_active"]]
        if not active_rules:
            return set()

        with connect_database(self._runtime.settings.database_path) as connection:
            placeholders = ",".join("?" for _ in candidate_ids)
            messages = connection.execute(
                f"""
                SELECT id, subject, from_addr
                FROM messages
                WHERE id IN ({placeholders})
                """,
                candidate_ids,
            ).fetchall()
            deliveries = connection.execute(
                f"""
                SELECT message_id, rcpt_to
                FROM message_deliveries
                WHERE message_id IN ({placeholders})
                """,
                candidate_ids,
            ).fetchall()

        delivery_map: dict[str, list[str]] = {}
        for d in deliveries:
            delivery_map.setdefault(str(d["message_id"]), []).append(str(d["rcpt_to"]))

        retained: set[str] = set()
        for msg in messages:
            msg_id = str(msg["id"])
            rcpt_list = delivery_map.get(msg_id, [])
            if self._matches_any_rule(active_rules, msg, rcpt_list):
                retained.add(msg_id)
        return retained

    def _matches_any_rule(
        self, rules: list[dict[str, Any]], msg: sqlite3.Row, rcpt_list: list[str]
    ) -> bool:
        for rule in rules:
            rt = rule["rule_type"]
            pattern = rule["pattern"]
            if rt == "mailbox":
                if any(r.lower() == pattern.lower() for r in rcpt_list):
                    return True
            elif rt == "domain":
                domain_suffix = "@" + pattern.lower()
                if any(r.lower().endswith(domain_suffix) for r in rcpt_list):
                    return True
            elif rt == "regex":
                compiled = self._compiled_patterns.get(rule["id"])
                if compiled is None:
                    continue
                subject = str(msg["subject"] or "")
                from_addr = str(msg["from_addr"] or "")
                match_text = f"{subject} {from_addr} {' '.join(rcpt_list)}"
                if compiled.search(match_text):
                    return True
        return False

    def list_retained_messages(self, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        active_rules = [r for r in self._rules if r["is_active"]]
        if not active_rules:
            return []

        with connect_database(self._runtime.settings.database_path) as connection:
            if query:
                messages = connection.execute(
                    """
                    SELECT id, subject, from_addr, received_at, text_preview
                    FROM messages
                    WHERE subject LIKE ? OR from_addr LIKE ?
                    ORDER BY received_at DESC
                    LIMIT ?
                    """,
                    (f"%{query}%", f"%{query}%", limit * 3),
                ).fetchall()
            else:
                messages = connection.execute(
                    """
                    SELECT id, subject, from_addr, received_at, text_preview
                    FROM messages
                    ORDER BY received_at DESC
                    LIMIT ?
                    """,
                    (limit * 3,),
                ).fetchall()
            if not messages:
                return []
            all_ids = [str(m["id"]) for m in messages]
            placeholders = ",".join("?" for _ in all_ids)
            deliveries = connection.execute(
                f"SELECT message_id, rcpt_to FROM message_deliveries WHERE message_id IN ({placeholders})",
                all_ids,
            ).fetchall()

        delivery_map: dict[str, list[str]] = {}
        for d in deliveries:
            delivery_map.setdefault(str(d["message_id"]), []).append(str(d["rcpt_to"]))

        retained: list[dict[str, Any]] = []
        for msg in messages:
            if len(retained) >= limit:
                break
            msg_id = str(msg["id"])
            rcpt_list = delivery_map.get(msg_id, [])
            matched_rule = self._first_matching_rule(active_rules, msg, rcpt_list)
            if matched_rule:
                retained.append({
                    "id": msg_id,
                    "subject": msg["subject"],
                    "from_addr": msg["from_addr"],
                    "rcpt_to": ", ".join(rcpt_list),
                    "received_at": msg["received_at"],
                    "matched_rule": matched_rule,
                })
        return retained

    def _first_matching_rule(
        self, rules: list[dict[str, Any]], msg: sqlite3.Row, rcpt_list: list[str]
    ) -> dict[str, Any] | None:
        for rule in rules:
            rt = rule["rule_type"]
            pattern = rule["pattern"]
            if rt == "mailbox":
                if any(r.lower() == pattern.lower() for r in rcpt_list):
                    return rule
            elif rt == "domain":
                domain_suffix = "@" + pattern.lower()
                if any(r.lower().endswith(domain_suffix) for r in rcpt_list):
                    return rule
            elif rt == "regex":
                compiled = self._compiled_patterns.get(rule["id"])
                if compiled is None:
                    continue
                subject = str(msg["subject"] or "")
                from_addr = str(msg["from_addr"] or "")
                match_text = f"{subject} {from_addr} {' '.join(rcpt_list)}"
                if compiled.search(match_text):
                    return rule
        return None


__all__ = ["RetentionRuleService"]
