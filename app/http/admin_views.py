from __future__ import annotations

import asyncio
import json
import sqlite3
import shutil
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.auth.sessions import SESSION_DURATION_DAYS
from app.db.connection import connect_database
from app.ingest.storage import utc_now
from app.http.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, build_pagination_context
from app.http.template_helpers import cn_bytes
from app.services.dns_check import DnsCheckService


router = APIRouter()

API_KEY_SCOPE_OPTIONS = (
    {
        "value": "public.read",
        "label": "公开邮件读取",
        "description": "允许读取公开邮箱的列表、详情、原文与附件。",
    },
    {
        "value": "live.read",
        "label": "实时会话查看",
        "description": "允许查看后台实时 SMTP 会话面板。",
    },
    {
        "value": "domains.read",
        "label": "域名只读",
        "description": "允许查看域名列表、详情与 DNS 检查结果。",
    },
    {
        "value": "domains.write",
        "label": "域名管理",
        "description": "允许新增域名并修改域名相关配置。",
    },
    {
        "value": "mailboxes.write",
        "label": "邮箱管理",
        "description": "允许修改邮箱的公开状态和隐藏状态。",
    },
    {
        "value": "mailboxes.read",
        "label": "邮箱只读",
        "description": "允许查看邮箱列表、详情和投递记录。",
    },
    {
        "value": "messages.read",
        "label": "邮件只读",
        "description": "允许查看邮件列表、详情、原文和附件。",
    },
    {
        "value": "messages.write",
        "label": "邮件重解析",
        "description": "允许触发邮件重新解析与修复处理。",
    },
    {
        "value": "smtp.read",
        "label": "SMTP 会话读取",
        "description": "允许查看 SMTP 会话列表和历史事件。",
    },
    {
        "value": "audit.read",
        "label": "审计日志读取",
        "description": "允许查看后台审计日志记录。",
    },
    {
        "value": "system.read",
        "label": "系统设置只读",
        "description": "允许查看当前系统运行配置。",
    },
    {
        "value": "system.write",
        "label": "系统设置修改",
        "description": "允许修改系统级运行参数。",
    },
    {
        "value": "api_keys.write",
        "label": "API 密钥管理",
        "description": "允许创建和吊销 API 密钥。",
    },
    {
        "value": "api_keys.read",
        "label": "API 密钥只读",
        "description": "允许查看 API 密钥元数据，但不会显示密钥 secret。",
    },
)

API_KEY_STATUS_OPTIONS = (
    {"value": "active", "label": "可用"},
    {"value": "disabled", "label": "停用"},
    {"value": "expired", "label": "过期"},
    {"value": "revoked", "label": "吊销"},
)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client is not None else None


def _secure_cookie(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _render(request: Request, template_name: str, context: dict[str, Any], *, status_code: int = 200) -> Response:
    response = request.app.state.templates.TemplateResponse(request, template_name, context)
    response.status_code = status_code
    return response


def _redirect_to_login() -> RedirectResponse:
    return RedirectResponse("/admin/login", status_code=status.HTTP_303_SEE_OTHER)


def _redirect_to_dashboard() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)


def _redirect_to_password_change() -> RedirectResponse:
    return RedirectResponse("/admin/settings?force_password_change=1", status_code=status.HTTP_303_SEE_OTHER)


def _parse_form_body(body: bytes) -> dict[str, str]:
    if not body:
        return {}
    parsed = parse_qs(body.decode("utf-8", errors="ignore"), keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items() if values}


def _parse_form_body_lists(body: bytes) -> dict[str, list[str]]:
    if not body:
        return {}
    parsed = parse_qs(body.decode("utf-8", errors="ignore"), keep_blank_values=True)
    return {key: values for key, values in parsed.items() if values}


def _form_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_optional_query_int(value: str | None, *, field_name: str) -> int | None:
    text = _parse_nullable_text(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"invalid {field_name}") from exc


def _parse_optional_query_bool(value: str | None, *, field_name: str) -> bool | None:
    text = _parse_nullable_text(value)
    if text is None:
        return None
    normalized = text.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"invalid {field_name}")


def _parse_csv_values(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def _parse_int_values(value: str | None) -> list[int]:
    return [int(item) for item in _parse_csv_values(value)]


def _parse_multi_text_values(values: list[str] | None) -> list[str]:
    if not values:
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = value.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def _parse_multi_int_values(values: list[str] | None) -> list[int]:
    return [int(item) for item in _parse_multi_text_values(values)]


def _parse_nullable_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _parse_domain_grant_form(
    form: dict[str, list[str]],
    *,
    default_mode: str = "all",
) -> tuple[str, list[int]]:
    raw_mode = (form.get("domain_grant_mode") or [None])[-1]
    if raw_mode is None:
        mode = "selected" if form.get("domain_ids") else default_mode
    else:
        mode = raw_mode.strip() or default_mode
    if mode not in {"all", "selected"}:
        raise ValueError("invalid domain grant mode")
    if mode == "all":
        return mode, []

    domain_ids = _parse_multi_int_values(form.get("domain_ids"))
    if not domain_ids:
        raise ValueError("empty selected domain grants")
    return mode, domain_ids


def _parse_positive_int(value: str | None, *, default: int, field_name: str) -> int:
    if value is None or not value.strip():
        return default
    try:
        normalized = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}") from exc
    if normalized < 1:
        raise ValueError(f"invalid {field_name}")
    return normalized


def _parse_non_negative_int(value: str | None, *, default: int, field_name: str) -> int:
    if value is None or not value.strip():
        return default
    try:
        normalized = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}") from exc
    if normalized < 0:
        raise ValueError(f"invalid {field_name}")
    return normalized


def _count(connection, query: str, params: tuple[Any, ...] = ()) -> int:
    row = connection.execute(query, params).fetchone()
    if row is None:
        return 0
    return int(row["count"])


def _utc_cutoff(seconds: int) -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


async def _current_admin(request: Request) -> dict[str, Any] | None:
    cookie_name = request.app.state.settings.session_cookie_name
    token = request.cookies.get(cookie_name)
    if not token:
        return None

    try:
        return await request.app.state.runtime.auth.get_session_admin(token, ip=_client_ip(request))
    except LookupError:
        return None


async def _require_admin(request: Request) -> dict[str, Any] | Response:
    admin = await _current_admin(request)
    if admin is None:
        return _redirect_to_login()
    if admin.get("must_change_password") and not (
        (request.url.path == "/admin/settings" and request.method == "GET")
        or request.url.path in {"/admin/settings/password", "/admin/logout"}
    ):
        return _redirect_to_password_change()
    return admin


async def _log_admin_audit(
    request: Request,
    admin: dict[str, Any] | None,
    action: str,
    resource_type: str,
    resource_ref: str | None,
    status_value: str,
    *,
    details: Any | None = None,
) -> None:
    try:
        await request.app.state.runtime.audit.log(
            "admin",
            str((admin or {}).get("username") or (admin or {}).get("id") or "admin"),
            action,
            resource_type,
            resource_ref,
            status_value,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details=details,
        )
    except Exception:
        return


def _delivery_chart(connection: sqlite3.Connection, *, hours: int = 24) -> dict[str, Any]:
    """Build a per-hour delivery histogram for the last ``hours`` hours.

    Returns a structure shaped for SVG curve rendering, with the buckets ordered
    chronologically (oldest → newest). Empty hours are filled with zero so the
    timeline stays continuous.
    """

    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets: list[dict[str, Any]] = []
    bucket_index: dict[str, int] = {}
    for offset in range(hours - 1, -1, -1):
        ts = now - timedelta(hours=offset)
        key = ts.strftime("%Y-%m-%dT%H:00:00Z")
        bucket_index[key] = len(buckets)
        buckets.append({"ts": key, "hour": ts.hour, "value": 0})

    cutoff = (now - timedelta(hours=hours - 1)).strftime("%Y-%m-%dT%H:00:00Z")
    rows = connection.execute(
        """
        SELECT
            substr(bucket_ts, 1, 13) || ':00:00Z' AS bucket,
            SUM(deliveries) AS count
        FROM mail_metric_buckets
        WHERE bucket_ts >= ?
        GROUP BY bucket
        """,
        (cutoff,),
    ).fetchall()
    for row in rows:
        idx = bucket_index.get(row["bucket"])
        if idx is not None:
            buckets[idx]["value"] = int(row["count"])

    values = [item["value"] for item in buckets]
    peak = max(values) if values else 0
    total = sum(values)

    # Build smooth-curve SVG path data on a fixed 1000x240 viewBox so the chart
    # scales fluidly. We use a Catmull-Rom→cubic-Bézier approximation for a
    # natural "curve" feel without depending on any client library.
    width = 1000.0
    height = 240.0
    pad_x = 24.0
    pad_top = 18.0
    pad_bottom = 30.0
    inner_w = width - pad_x * 2
    inner_h = height - pad_top - pad_bottom
    n = len(buckets)
    y_scale_max = max(peak, 1)

    coords: list[tuple[float, float]] = []
    for index, item in enumerate(buckets):
        x = pad_x + (index / max(n - 1, 1)) * inner_w
        y = pad_top + inner_h - (item["value"] / y_scale_max) * inner_h
        coords.append((x, y))
        item["x"] = round(x, 2)
        item["y"] = round(y, 2)

    def _segment(p0, p1, p2, p3) -> str:
        # Catmull-Rom to cubic Bézier conversion (tension = 0.5).
        c1x = p1[0] + (p2[0] - p0[0]) / 6
        c1y = p1[1] + (p2[1] - p0[1]) / 6
        c2x = p2[0] - (p3[0] - p1[0]) / 6
        c2y = p2[1] - (p3[1] - p1[1]) / 6
        return f"C {c1x:.2f} {c1y:.2f}, {c2x:.2f} {c2y:.2f}, {p2[0]:.2f} {p2[1]:.2f}"

    if coords:
        path_parts = [f"M {coords[0][0]:.2f} {coords[0][1]:.2f}"]
        for index in range(len(coords) - 1):
            p0 = coords[index - 1] if index > 0 else coords[index]
            p1 = coords[index]
            p2 = coords[index + 1]
            p3 = coords[index + 2] if index + 2 < len(coords) else p2
            path_parts.append(_segment(p0, p1, p2, p3))
        line_path = " ".join(path_parts)
        baseline = pad_top + inner_h
        area_path = (
            f"{line_path} L {coords[-1][0]:.2f} {baseline:.2f}"
            f" L {coords[0][0]:.2f} {baseline:.2f} Z"
        )
    else:
        line_path = ""
        area_path = ""

    # Reduce x-axis labels to 5 evenly-spaced tick marks for readability.
    tick_indices = sorted({0, n // 4, n // 2, (3 * n) // 4, n - 1}) if n else []
    ticks = [
        {"x": buckets[i]["x"], "label": f"{buckets[i]['hour']:02d}:00"}
        for i in tick_indices
    ]

    return {
        "buckets": buckets,
        "peak": peak,
        "total": total,
        "line_path": line_path,
        "area_path": area_path,
        "ticks": ticks,
        "view_width": int(width),
        "view_height": int(height),
        "baseline_y": round(pad_top + inner_h, 2),
        "pad_top": pad_top,
    }


def _metric_sum(connection: sqlite3.Connection, column: str, cutoff: str) -> int:
    if column not in {"deliveries", "parse_failures"}:
        raise ValueError("invalid metric column")
    row = connection.execute(
        f"SELECT COALESCE(SUM({column}), 0) AS count FROM mail_metric_buckets WHERE bucket_ts >= ?",
        (cutoff,),
    ).fetchone()
    return 0 if row is None else int(row["count"])


def _dashboard_stats(request: Request) -> dict[str, Any]:
    runtime = request.app.state.runtime
    one_minute_cutoff = _utc_cutoff(60)
    five_minute_cutoff = _utc_cutoff(5 * 60)
    day_cutoff = _utc_cutoff(24 * 60 * 60)
    disk_usage = shutil.disk_usage(runtime.settings.storage_root)
    disk_used_percent = 0.0 if disk_usage.total == 0 else (disk_usage.used / disk_usage.total) * 100
    with connect_database(runtime.settings.database_path) as connection:
        stats = {
            "open_sessions": _count(connection, "SELECT COUNT(*) AS count FROM smtp_sessions WHERE status = 'open'"),
            "active_connections": runtime.active_smtp_connection_count(),
            "received_last_minute": _metric_sum(connection, "deliveries", one_minute_cutoff),
            "received_last_five_minutes": _metric_sum(connection, "deliveries", five_minute_cutoff),
            "received_last_day": _metric_sum(connection, "deliveries", day_cutoff),
            "failed_last_day": _metric_sum(connection, "parse_failures", day_cutoff),
            "domains": _count(connection, "SELECT COUNT(*) AS count FROM domains"),
            "mailboxes": _count(connection, "SELECT COUNT(*) AS count FROM mailboxes"),
            "messages": _count(connection, "SELECT COUNT(*) AS count FROM messages"),
            "pending_messages": _count(connection, "SELECT COUNT(*) AS count FROM messages WHERE parse_status = 'pending'"),
            "failed_messages": _count(connection, "SELECT COUNT(*) AS count FROM messages WHERE parse_status = 'failed'"),
            "api_keys": _count(connection, "SELECT COUNT(*) AS count FROM api_keys"),
            "audit_logs": _count(connection, "SELECT COUNT(*) AS count FROM audit_logs"),
        }
        recent_messages = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    m.id,
                    m.subject,
                    m.from_addr,
                    m.received_at,
                    m.parse_status,
                    m.attachment_count
                FROM messages AS m
                ORDER BY m.received_at DESC, m.id DESC
                LIMIT 5
                """
            ).fetchall()
        ]
        recent_domains = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    id,
                    root_domain_ascii,
                    is_active,
                    created_at
                FROM domains
                ORDER BY created_at DESC, id DESC
                LIMIT 5
                """
            ).fetchall()
        ]
        delivery_chart = _delivery_chart(connection, hours=24)

    sessions_value = stats["active_connections"]
    disk_threshold = runtime.settings.disk_warning_threshold_percent
    disk_state = (
        "danger" if disk_used_percent >= disk_threshold
        else ("warning" if disk_used_percent >= max(disk_threshold - 15, 0) else "ok")
    )
    failed_today = stats["failed_last_day"]
    failed_state = "danger" if failed_today > 0 else "ok"
    pending_state = "warning" if stats["pending_messages"] > 0 else "ok"

    return {
        # Layer 1 — live signals (top of dashboard, real-time)
        "live_stats": [
            {
                "label": "当前 SMTP 会话",
                "value": sessions_value,
                "hint": "仍在监听器上保持连接的 SMTP 会话数。",
                "state": "ok" if sessions_value else "idle",
            },
            {
                "label": "1 分钟接收速率",
                "value": f"{stats['received_last_minute']}/min",
                "hint": "最近 60 秒成功投递的邮件数。",
                "state": "ok",
            },
            {
                "label": "5 分钟接收速率",
                "value": f"{stats['received_last_five_minutes'] / 5:.1f}/min",
                "hint": "最近 5 分钟平均每分钟投递数。",
                "state": "ok",
            },
            {
                "label": "24 小时接收量",
                "value": stats["received_last_day"],
                "hint": "过去 24 小时投递到邮箱的邮件数。",
                "state": "ok",
            },
        ],
        # Layer 2 — today's processing health
        "today_stats": [
            {
                "label": "待解析邮件",
                "value": stats["pending_messages"],
                "hint": "已入库、仍在等待 MIME 解析。",
                "state": pending_state,
            },
            {
                "label": "解析失败",
                "value": stats["failed_messages"],
                "hint": "解析出错、需要人工关注。",
                "state": "danger" if stats["failed_messages"] > 0 else "ok",
            },
            {
                "label": "24 小时解析失败",
                "value": failed_today,
                "hint": "过去 24 小时进入解析失败的邮件。",
                "state": failed_state,
            },
            {
                "label": "磁盘使用",
                "value": f"{disk_used_percent:.1f}%",
                "hint": f"已用 {cn_bytes(disk_usage.used)} / {cn_bytes(disk_usage.total)}，阈值 {disk_threshold}%。",
                "state": disk_state,
            },
        ],
        # Layer 3 — totals (small reference at bottom)
        "totals": [
            {"label": "已接入域名", "value": stats["domains"], "icon": "globe"},
            {"label": "已收录邮箱", "value": stats["mailboxes"], "icon": "inbox"},
            {"label": "邮件总数", "value": stats["messages"], "icon": "mail"},
            {"label": "API 密钥", "value": stats["api_keys"], "icon": "key-round"},
            {"label": "审计记录", "value": stats["audit_logs"], "icon": "scroll-text"},
        ],
        "recent_domains": recent_domains,
        "recent_messages": recent_messages,
        "delivery_chart": delivery_chart,
    }


def _list_recent_messages(request: Request, *, limit: int = 100) -> list[dict[str, Any]]:
    with connect_database(request.app.state.runtime.settings.database_path) as connection:
        rows = connection.execute(
            """
            SELECT
                m.id,
                m.subject,
                m.from_addr,
                m.received_at,
                m.parse_status,
                m.parse_error,
                m.has_attachments,
                m.attachment_count,
                COUNT(d.id) AS delivery_count
            FROM messages AS m
            LEFT JOIN message_deliveries AS d ON d.message_id = m.id
            GROUP BY m.id
            ORDER BY m.received_at DESC, m.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _list_messages_page(request: Request, *, limit: int, offset: int) -> list[dict[str, Any]]:
    with connect_database(request.app.state.runtime.settings.database_path) as connection:
        rows = connection.execute(
            """
            SELECT
                m.id,
                m.subject,
                m.from_addr,
                COALESCE(
                    (
                        SELECT GROUP_CONCAT(rcpt_to, ', ')
                        FROM (
                            SELECT DISTINCT rcpt_to
                            FROM message_deliveries
                            WHERE message_id = m.id
                            ORDER BY rcpt_to ASC
                        )
                    ),
                    ''
                ) AS recipients,
                m.received_at,
                m.parse_status,
                m.parse_error,
                m.has_attachments,
                m.attachment_count,
                COUNT(d.id) AS delivery_count
            FROM messages AS m
            LEFT JOIN message_deliveries AS d ON d.message_id = m.id
            GROUP BY m.id
            ORDER BY m.received_at DESC, m.id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def _list_api_keys(request: Request, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with connect_database(request.app.state.runtime.settings.database_path) as connection:
        rows = connection.execute(
            """
            SELECT
                k.id,
                k.public_id,
                k.name,
                k.description,
                k.kind,
                k.status,
                k.allow_header,
                k.allow_query,
                k.rate_limit_per_min,
                k.expires_at,
                k.last_used_at,
                k.last_used_ip,
                k.created_at,
                COALESCE(
                    (
                        SELECT GROUP_CONCAT(scope, ', ')
                        FROM api_key_scopes
                        WHERE api_key_id = k.id
                    ),
                    ''
                ) AS scopes,
                (
                    SELECT COUNT(*)
                    FROM api_key_domain_grants
                    WHERE api_key_id = k.id
                ) AS domain_count,
                (
                    SELECT COUNT(*)
                    FROM api_key_mailbox_grants
                    WHERE api_key_id = k.id
                ) AS mailbox_count
            FROM api_keys AS k
            ORDER BY k.created_at DESC, k.id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def _count_table_rows(request: Request, table_name: str) -> int:
    with connect_database(request.app.state.runtime.settings.database_path) as connection:
        return _count(connection, f"SELECT COUNT(*) AS count FROM {table_name}")


def _api_keys_page_context(
    request: Request,
    admin: dict[str, Any],
    *,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
    created_api_key: dict[str, Any] | None = None,
    error: str | None = None,
    create_form: dict[str, Any] | None = None,
) -> dict[str, Any]:
    api_keys = _list_api_keys(request, limit=limit, offset=offset)
    total_count = _count_table_rows(request, "api_keys")
    return {
        "page_title": "API 密钥",
        "admin": admin,
        "api_keys": api_keys,
        "available_scopes": API_KEY_SCOPE_OPTIONS,
        "available_domains": request.app.state.runtime.list_domains(),
        "created_api_key": created_api_key,
        "create_form": create_form or _api_key_form_values(),
        "error": error,
        "pagination": build_pagination_context(
            path="/admin/api-keys",
            limit=limit,
            offset=offset,
            total_count=total_count,
            item_count=len(api_keys),
        ),
    }


def _api_key_form_values(form: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = form or {}
    scopes = payload.get("scopes", [])
    domain_ids = payload.get("domain_ids", [])
    domain_grant_mode = str(
        payload.get("domain_grant_mode") or ("selected" if domain_ids else "all")
    )
    return {
        "name": str(payload.get("name", "新的 API 密钥") or "新的 API 密钥"),
        "kind": str(payload.get("kind", "admin") or "admin"),
        "scopes": [str(item) for item in scopes],
        "domain_grant_mode": domain_grant_mode,
        "domain_ids": [str(item) for item in domain_ids],
        "mailbox_patterns": str(payload.get("mailbox_patterns", "") or ""),
    }


def _api_key_edit_form_values(api_key: dict[str, Any], form: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = form or api_key
    scopes = payload.get("scopes", [])
    domain_ids = payload.get("domain_ids", [])
    mailbox_patterns = payload.get("mailbox_patterns", [])
    allowed_ip_cidrs = payload.get("allowed_ip_cidrs", [])
    domain_grant_mode = str(
        payload.get("domain_grant_mode") or ("selected" if domain_ids else "all")
    )
    return {
        "name": str(payload.get("name", "") or ""),
        "description": str(payload.get("description", "") or ""),
        "kind": str(payload.get("kind", "admin") or "admin"),
        "status": str(payload.get("status", "active") or "active"),
        "scopes": [str(item) for item in scopes],
        "domain_grant_mode": domain_grant_mode,
        "domain_ids": [str(item) for item in domain_ids],
        "mailbox_patterns": (
            ", ".join(str(item) for item in mailbox_patterns)
            if isinstance(mailbox_patterns, list)
            else str(mailbox_patterns or "")
        ),
        "allow_header": bool(payload.get("allow_header", True)),
        "allow_query": bool(payload.get("allow_query", False)),
        "rate_limit_per_min": str(payload.get("rate_limit_per_min", "3600") or "0"),
        "allowed_ip_cidrs": (
            ", ".join(str(item) for item in allowed_ip_cidrs)
            if isinstance(allowed_ip_cidrs, list)
            else str(allowed_ip_cidrs or "")
        ),
        "expires_at": str(payload.get("expires_at", "") or ""),
    }


def _api_key_edit_context(
    request: Request,
    admin: dict[str, Any],
    api_key_id: int,
    *,
    error: str | None = None,
    form: dict[str, Any] | None = None,
    updated: bool = False,
    rotated_api_key: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        api_key = request.app.state.runtime.api_keys.get_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "page_title": f"编辑 API 密钥：{api_key['name']}",
        "admin": admin,
        "api_key": api_key,
        "available_scopes": API_KEY_SCOPE_OPTIONS,
        "available_statuses": API_KEY_STATUS_OPTIONS,
        "available_domains": request.app.state.runtime.list_domains(),
        "form": form or _api_key_edit_form_values(api_key),
        "error": error,
        "updated": updated,
        "rotated_api_key": rotated_api_key,
    }


def _domain_form_values(request: Request, form: dict[str, str] | None = None) -> dict[str, Any]:
    settings = request.app.state.runtime.get_settings()
    payload = form or {}
    return {
        "root_domain": payload.get("root_domain", ""),
        "accept_exact": _form_bool(payload["accept_exact"]) if "accept_exact" in payload else True,
        "accept_subdomains": _form_bool(payload["accept_subdomains"]) if "accept_subdomains" in payload else True,
        "public_web_enabled": _form_bool(payload["public_web_enabled"]) if "public_web_enabled" in payload else True,
        "public_api_enabled": _form_bool(payload["public_api_enabled"]) if "public_api_enabled" in payload else True,
        "local_part_case_sensitive": (
            _form_bool(payload["local_part_case_sensitive"]) if "local_part_case_sensitive" in payload else False
        ),
        "is_active": _form_bool(payload["is_active"]) if "is_active" in payload else True,
        "plus_addressing_mode": payload.get("plus_addressing_mode", "keep") or "keep",
        "max_message_size_bytes": payload.get(
            "max_message_size_bytes",
            str(settings["max_message_size_bytes"]),
        )
        or str(settings["max_message_size_bytes"]),
    }


def _domain_edit_form_values(domain: dict[str, Any], form: dict[str, str] | None = None) -> dict[str, Any]:
    payload = form or {}
    return {
        "root_domain": payload.get("root_domain", domain["root_domain_ascii"]),
        "accept_exact": _form_bool(payload["accept_exact"]) if "accept_exact" in payload else bool(domain["accept_exact"]),
        "accept_subdomains": (
            _form_bool(payload["accept_subdomains"]) if "accept_subdomains" in payload else bool(domain["accept_subdomains"])
        ),
        "public_web_enabled": (
            _form_bool(payload["public_web_enabled"])
            if "public_web_enabled" in payload
            else bool(domain["public_web_enabled"])
        ),
        "public_api_enabled": (
            _form_bool(payload["public_api_enabled"])
            if "public_api_enabled" in payload
            else bool(domain["public_api_enabled"])
        ),
        "local_part_case_sensitive": (
            _form_bool(payload["local_part_case_sensitive"])
            if "local_part_case_sensitive" in payload
            else bool(domain["local_part_case_sensitive"])
        ),
        "is_active": _form_bool(payload["is_active"]) if "is_active" in payload else bool(domain["is_active"]),
        "plus_addressing_mode": payload.get("plus_addressing_mode", domain["plus_addressing_mode"]) or "keep",
        "max_message_size_bytes": payload.get(
            "max_message_size_bytes",
            str(domain["max_message_size_bytes"]),
        )
        or str(domain["max_message_size_bytes"]),
        "retention_days": payload.get("retention_days", domain.get("retention_days") or ""),
        "notes": payload.get("notes", domain.get("notes") or ""),
    }


def _domain_form_error_message(exc: Exception) -> str:
    if isinstance(exc, sqlite3.IntegrityError):
        return "该域名已经存在，不能重复添加。"

    message = str(exc)
    error_map = {
        "invalid root_domain": "请输入有效的根域名，例如 `adb.com`。",
        "invalid accept_exact": "根域接收选项无效。",
        "invalid accept_subdomains": "子域接收选项无效。",
        "invalid public_web_enabled": "公开网页访问选项无效。",
        "invalid public_api_enabled": "公开接口访问选项无效。",
        "invalid plus_addressing_mode": "加号寻址策略无效。",
        "invalid local_part_case_sensitive": "大小写选项无效。",
        "invalid is_active": "启用状态选项无效。",
        "invalid max_message_size_bytes": "最大邮件大小必须是大于 0 的整数。",
    }
    return error_map.get(message, message or "提交的域名信息无效。")


def _render_domains_page(
    request: Request,
    admin: dict[str, Any],
    *,
    status_code: int = 200,
    create_error: str | None = None,
    create_form: dict[str, Any] | None = None,
) -> Response:
    return _render(
        request,
        "admin/domains.html",
        {
            "page_title": "域名",
            "admin": admin,
            "domains": request.app.state.runtime.list_domains(),
            "create_error": create_error,
            "create_form": create_form or _domain_form_values(request),
        },
        status_code=status_code,
    )


def _domain_mailboxes(request: Request, domain_id: int, *, limit: int = 100) -> list[dict[str, Any]]:
    with connect_database(request.app.state.runtime.settings.database_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                address_canonical,
                message_count,
                latest_message_at,
                public_enabled,
                is_hidden,
                notes
            FROM mailboxes
            WHERE domain_id = ?
            ORDER BY latest_message_at DESC, id DESC
            LIMIT ?
            """,
            (domain_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def _domain_detail_context(
    request: Request,
    admin: dict[str, Any],
    domain_id: int,
    *,
    error: str | None = None,
    updated: bool = False,
    dns_checked: bool = False,
    form: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        domain = request.app.state.runtime.domains.get_domain(domain_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "page_title": f"{domain['root_domain_ascii']}",
        "admin": admin,
        "domain": domain,
        "mailboxes": _domain_mailboxes(request, domain_id),
        "form": form or _domain_edit_form_values(domain),
        "error": error,
        "updated": updated,
        "dns_checked": dns_checked,
    }


@router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    admin = await _current_admin(request)
    if admin is not None:
        return _redirect_to_dashboard()
    return _render(
        request,
        "admin/login.html",
        {
            "page_title": "管理员登录",
            "error": None,
            "username": "",
        },
    )


@router.post("/admin/login")
async def login(request: Request) -> Response:
    form = _parse_form_body(await request.body())
    username = form.get("username", "").strip()
    password = form.get("password", "")
    if not username or not password:
        await _log_admin_audit(
            request,
            None,
            "admin.login",
            "admin",
            None,
            "failure",
            details={"username": username, "reason": "missing_credentials"},
        )
        return _render(
            request,
            "admin/login.html",
            {
                "page_title": "管理员登录",
                "error": "用户名和密码不能为空。",
                "username": username,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        admin = await request.app.state.runtime.auth.authenticate_admin(username, password, ip=_client_ip(request))
    except PermissionError:
        await _log_admin_audit(
            request,
            None,
            "admin.login",
            "admin",
            None,
            "failure",
            details={"username": username, "reason": "rate_limited"},
        )
        return _render(
            request,
            "admin/login.html",
            {
                "page_title": "管理员登录",
                "error": "登录失败次数过多，请稍后再试。",
                "username": username,
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
    except LookupError:
        await _log_admin_audit(
            request,
            None,
            "admin.login",
            "admin",
            None,
            "failure",
            details={"username": username},
        )
        return _render(
            request,
            "admin/login.html",
            {
                "page_title": "管理员登录",
                "error": "用户名或密码不正确。",
                "username": username,
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    session = await request.app.state.runtime.auth.create_session(
        admin_id=admin["id"],
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    await _log_admin_audit(request, admin, "admin.login", "admin", str(admin["id"]), "success")
    response = _redirect_to_password_change() if admin.get("must_change_password") else _redirect_to_dashboard()
    response.set_cookie(
        request.app.state.settings.session_cookie_name,
        session["token"],
        httponly=True,
        samesite="lax",
        secure=_secure_cookie(request),
        max_age=SESSION_DURATION_DAYS * 24 * 60 * 60,
        path="/",
    )
    return response


@router.post("/admin/logout")
async def logout(request: Request) -> Response:
    cookie_name = request.app.state.settings.session_cookie_name
    admin = await _current_admin(request)
    if admin is not None:
        try:
            await request.app.state.runtime.auth.revoke_session(admin["session_id"])
        except Exception:
            pass
        await _log_admin_audit(request, admin, "admin.logout", "admin_session", str(admin.get("session_id")), "success")

    response = _redirect_to_login()
    response.delete_cookie(cookie_name, path="/", secure=_secure_cookie(request), samesite="lax")
    return response


@router.get("/admin", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    summary = _dashboard_stats(request)
    return _render(
        request,
        "admin/dashboard.html",
        {
            "page_title": "仪表盘",
            "admin": admin_or_response,
            **summary,
        },
    )


@router.get("/admin/domains", response_class=HTMLResponse)
async def domains_page(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    return _render_domains_page(request, admin_or_response)


@router.post("/admin/domains")
async def create_domain_from_form(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    form_values = _domain_form_values(request, form)
    try:
        created = await request.app.state.runtime.create_domain(
            form.get("root_domain", "").strip(),
            accept_exact=_form_bool(form.get("accept_exact")),
            accept_subdomains=_form_bool(form.get("accept_subdomains")),
            public_web_enabled=_form_bool(form.get("public_web_enabled")),
            public_api_enabled=_form_bool(form.get("public_api_enabled")),
            plus_addressing_mode=form.get("plus_addressing_mode", "keep").strip() or "keep",
            local_part_case_sensitive=_form_bool(form.get("local_part_case_sensitive")),
            is_active=_form_bool(form.get("is_active")),
            max_message_size_bytes=_parse_positive_int(
                form.get("max_message_size_bytes"),
                default=int(request.app.state.runtime.get_settings()["max_message_size_bytes"]),
                field_name="max_message_size_bytes",
            ),
        )
    except (ValueError, sqlite3.IntegrityError) as exc:
        return _render_domains_page(
            request,
            admin_or_response,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            create_error=_domain_form_error_message(exc),
            create_form=form_values,
        )

    await _log_admin_audit(request, admin_or_response, "domains.create", "domain", str(created["id"]), "success")
    return RedirectResponse(f"/admin/domains/{created['id']}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/admin/domains/{domain_id}", response_class=HTMLResponse)
async def domain_detail_page(domain_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    return _render(
        request,
        "admin/domain_detail.html",
        _domain_detail_context(
            request,
            admin_or_response,
            domain_id,
            updated=bool(request.query_params.get("updated")),
            dns_checked=bool(request.query_params.get("dns_checked")),
        ),
    )


@router.post("/admin/domains/{domain_id}")
async def update_domain_from_form(domain_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    try:
        payload = {
            "root_domain": form.get("root_domain", "").strip(),
            "accept_exact": _form_bool(form.get("accept_exact")),
            "accept_subdomains": _form_bool(form.get("accept_subdomains")),
            "public_web_enabled": _form_bool(form.get("public_web_enabled")),
            "public_api_enabled": _form_bool(form.get("public_api_enabled")),
            "plus_addressing_mode": form.get("plus_addressing_mode", "keep").strip() or "keep",
            "local_part_case_sensitive": _form_bool(form.get("local_part_case_sensitive")),
            "is_active": _form_bool(form.get("is_active")),
            "max_message_size_bytes": _parse_positive_int(
                form.get("max_message_size_bytes"),
                default=int(request.app.state.runtime.get_settings()["max_message_size_bytes"]),
                field_name="max_message_size_bytes",
            ),
            "retention_days": form.get("retention_days") or None,
            "notes": form.get("notes"),
        }
        await request.app.state.runtime.domains.update_domain(domain_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (ValueError, sqlite3.IntegrityError) as exc:
        current = request.app.state.runtime.domains.get_domain(domain_id)
        return _render(
            request,
            "admin/domain_detail.html",
            _domain_detail_context(
                request,
                admin_or_response,
                domain_id,
                error=_domain_form_error_message(exc),
                form=_domain_edit_form_values(current, form),
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    await _log_admin_audit(request, admin_or_response, "domains.update", "domain", str(domain_id), "success")
    return RedirectResponse(f"/admin/domains/{domain_id}?updated=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/domains/{domain_id}/dns-check")
async def run_domain_dns_check_from_form(domain_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    try:
        domain = request.app.state.runtime.domains.get_domain(domain_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    check_result = await DnsCheckService().run_dns_check(domain["root_domain_ascii"])
    checked_at = utc_now()
    stored_result = {
        "domain_id": domain_id,
        "root_domain_ascii": domain["root_domain_ascii"],
        "checked_at": checked_at,
        **check_result,
    }

    def operation(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            UPDATE domains
            SET dns_status = ?,
                dns_last_checked_at = ?,
                dns_details_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                check_result["status"],
                checked_at,
                json.dumps(stored_result, ensure_ascii=False),
                checked_at,
                domain_id,
            ),
        )

    await request.app.state.runtime.writer.execute(operation)
    await _log_admin_audit(request, admin_or_response, "domains.dns_check", "domain", str(domain_id), "success")
    return RedirectResponse(f"/admin/domains/{domain_id}?dns_checked=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/domains/{domain_id}/delete")
async def delete_domain_from_form(domain_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    form = _parse_form_body(await request.body())
    if form.get("confirm") != "delete-domain":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="confirmation required")
    try:
        await request.app.state.runtime.domains.delete_domain(domain_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        return _render(
            request,
            "admin/domain_detail.html",
            _domain_detail_context(
                request,
                admin_or_response,
                domain_id,
                error="该域名仍有关联邮箱、投递记录或 API 授权，无法直接删除。请先清理相关数据或停用域名。",
            ),
            status_code=status.HTTP_409_CONFLICT,
        )
    await _log_admin_audit(request, admin_or_response, "domains.delete", "domain", str(domain_id), "success")
    return RedirectResponse("/admin/domains", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/admin/mailboxes", response_class=HTMLResponse)
async def mailboxes_page(
    request: Request,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    q: str | None = Query(default=None),
    domain_id: str | None = Query(default=None),
    public_enabled: str | None = Query(default=None),
    is_hidden: str | None = Query(default=None),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    query = _parse_nullable_text(q)
    domain_filter = _parse_optional_query_int(domain_id, field_name="domain_id")
    public_enabled_filter = _parse_optional_query_bool(public_enabled, field_name="public_enabled")
    is_hidden_filter = _parse_optional_query_bool(is_hidden, field_name="is_hidden")

    mailboxes = request.app.state.runtime.mailboxes.list_mailboxes(
        limit=limit,
        offset=offset,
        query=query,
        domain_id=domain_filter,
        public_enabled=public_enabled_filter,
        is_hidden=is_hidden_filter,
    )["items"]
    total_count = request.app.state.runtime.mailboxes.count_mailboxes(
        query=query,
        domain_id=domain_filter,
        public_enabled=public_enabled_filter,
        is_hidden=is_hidden_filter,
    )
    filters = {
        "q": query or "",
        "domain_id": "" if domain_filter is None else str(domain_filter),
        "public_enabled": "" if public_enabled_filter is None else str(int(public_enabled_filter)),
        "is_hidden": "" if is_hidden_filter is None else str(int(is_hidden_filter)),
    }
    return _render(
        request,
        "admin/mailboxes.html",
        {
            "page_title": "邮箱",
            "admin": admin_or_response,
            "mailboxes": mailboxes,
            "domains": request.app.state.runtime.list_domains(),
            "filters": filters,
            "pagination": build_pagination_context(
                path="/admin/mailboxes",
                limit=limit,
                offset=offset,
                total_count=total_count,
                item_count=len(mailboxes),
                extra_params={key: value for key, value in filters.items() if value != ""},
            ),
        },
    )


@router.get("/admin/mailboxes/{mailbox_id}", response_class=HTMLResponse)
async def mailbox_detail_page(
    mailbox_id: int,
    request: Request,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    try:
        mailbox = request.app.state.runtime.mailboxes.get_mailbox(mailbox_id)
        deliveries = request.app.state.runtime.mailboxes.list_mailbox_deliveries(
            mailbox_id,
            limit=limit,
            offset=offset,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _render(
        request,
        "admin/mailbox_detail.html",
        {
            "page_title": mailbox["address_canonical"],
            "admin": admin_or_response,
            "mailbox": mailbox,
            "deliveries": deliveries["items"],
            "pagination": build_pagination_context(
                path=f"/admin/mailboxes/{mailbox_id}",
                limit=limit,
                offset=offset,
                total_count=deliveries["total_count"],
                item_count=len(deliveries["items"]),
            ),
        },
    )


@router.post("/admin/mailboxes/{mailbox_id}")
async def update_mailbox_visibility(mailbox_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    updates: dict[str, Any] = {}
    if "public_enabled" in form:
        updates["public_enabled"] = _form_bool(form.get("public_enabled"))
    if "is_hidden" in form:
        updates["is_hidden"] = _form_bool(form.get("is_hidden"))
    limit = _parse_positive_int(form.get("limit"), default=DEFAULT_PAGE_SIZE, field_name="limit")
    offset = _parse_non_negative_int(form.get("offset"), default=0, field_name="offset")

    try:
        await request.app.state.runtime.mailboxes.update_mailbox(mailbox_id, updates)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    await _log_admin_audit(request, admin_or_response, "mailboxes.update", "mailbox", str(mailbox_id), "success")
    return RedirectResponse(
        f"/admin/mailboxes?limit={limit}&offset={offset}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/mailboxes/{mailbox_id}/delete-deliveries")
async def delete_mailbox_deliveries_from_form(mailbox_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    form = _parse_form_body_lists(await request.body())
    selected_ids = _parse_multi_text_values(form.get("delivery_ids"))
    if not selected_ids:
        result = await request.app.state.runtime.mailboxes.soft_delete_mailbox_deliveries(mailbox_id)
    else:
        result = await request.app.state.runtime.mailboxes.soft_delete_mailbox_deliveries(
            mailbox_id,
            delivery_ids=selected_ids,
        )
    await _log_admin_audit(
        request,
        admin_or_response,
        "deliveries.bulk_delete" if result["deleted"] != 1 else "deliveries.delete",
        "mailbox",
        str(mailbox_id),
        "success",
        details=result,
    )
    return RedirectResponse(f"/admin/mailboxes/{mailbox_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/admin/messages", response_class=HTMLResponse)
async def messages_page(
    request: Request,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    q: str | None = Query(default=None),
    parse_status: str | None = Query(default=None),
    mailbox_id: int | None = Query(default=None),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    try:
        result = request.app.state.runtime.messages.list_messages(
            limit=limit,
            offset=offset,
            query=q,
            parse_status=parse_status,
            mailbox_id=mailbox_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    messages = result["items"]
    filters = {
        "q": q or "",
        "parse_status": parse_status or "",
        "mailbox_id": "" if mailbox_id is None else str(mailbox_id),
    }
    return _render(
        request,
        "admin/messages.html",
        {
            "page_title": "邮件",
            "admin": admin_or_response,
            "messages": messages,
            "mailboxes": request.app.state.runtime.mailboxes.list_mailboxes(limit=1000)["items"],
            "filters": filters,
            "deleted_count": request.query_params.get("deleted", ""),
            "pagination": build_pagination_context(
                path="/admin/messages",
                limit=limit,
                offset=offset,
                total_count=result["total_count"],
                item_count=len(messages),
                extra_params={key: value for key, value in filters.items() if value},
            ),
        },
    )


@router.get("/admin/messages/{message_id}", response_class=HTMLResponse)
async def message_detail_page(message_id: str, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    try:
        message = request.app.state.runtime.messages.get_admin_message_detail(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _render(
        request,
        "admin/message_detail.html",
        {
            "page_title": message["subject"] or message["id"],
            "admin": admin_or_response,
            "message": message,
        },
    )


@router.get("/admin/messages/{message_id}/raw")
async def admin_message_raw(message_id: str, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    try:
        raw = request.app.state.runtime.messages.get_admin_raw_message(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return Response(raw, media_type="message/rfc822")


@router.get("/admin/messages/{message_id}/attachments/{attachment_id}")
async def admin_message_attachment(message_id: str, attachment_id: str, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    try:
        attachment = request.app.state.runtime.messages.get_admin_attachment(message_id, attachment_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    safe_filename = attachment.get("safe_filename") or "attachment.bin"
    return Response(
        attachment["content"],
        media_type=attachment.get("content_type") or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


@router.post("/admin/messages/{message_id}/reparse")
async def reparse_message_from_form(message_id: str, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    try:
        await request.app.state.runtime.messages.reparse_message(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    await _log_admin_audit(request, admin_or_response, "messages.reparse", "message", message_id, "success")
    return RedirectResponse(f"/admin/messages/{message_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/messages/{message_id}/delete-deliveries")
async def delete_message_deliveries_from_form(message_id: str, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response
    form = _parse_form_body_lists(await request.body())
    selected_ids = _parse_multi_text_values(form.get("delivery_ids"))
    if not selected_ids:
        detail = request.app.state.runtime.messages.get_admin_message_detail(message_id)
        selected_ids = [str(item["delivery_id"]) for item in detail["deliveries"] if item["status"] == "active"]
    result = await request.app.state.runtime.messages.soft_delete_deliveries(selected_ids)
    await _log_admin_audit(
        request,
        admin_or_response,
        "deliveries.bulk_delete" if result["deleted"] != 1 else "deliveries.delete",
        "message",
        message_id,
        "success",
        details=result,
    )
    return RedirectResponse(f"/admin/messages/{message_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/messages/{message_id}/delete")
async def delete_message_from_form(message_id: str, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    runtime = request.app.state.runtime
    async with runtime._mail_store_lock:
        result = await runtime.writer.execute(
            lambda connection: runtime._delete_messages_by_ids(connection, [message_id])
        )
        storage_paths = result.pop("storage_paths", [])
        await asyncio.to_thread(runtime._delete_storage_files, storage_paths)

    await _log_admin_audit(request, admin_or_response, "messages.delete", "message", message_id, "success")
    return RedirectResponse("/admin/messages?deleted=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/messages/bulk-delete")
async def bulk_delete_messages_from_form(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body_lists(await request.body())
    message_ids = form.get("message_ids", [])
    if not message_ids:
        return RedirectResponse("/admin/messages", status_code=status.HTTP_303_SEE_OTHER)

    runtime = request.app.state.runtime
    async with runtime._mail_store_lock:
        result = await runtime.writer.execute(
            lambda connection: runtime._delete_messages_by_ids(connection, message_ids)
        )
        storage_paths = result.pop("storage_paths", [])
        await asyncio.to_thread(runtime._delete_storage_files, storage_paths)

    await _log_admin_audit(
        request, admin_or_response, "messages.bulk_delete", "messages", None, "success",
        details={"count": result["messages"], "message_ids": message_ids[:20]},
    )
    return RedirectResponse(f"/admin/messages?deleted={result['messages']}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/admin/api-keys", response_class=HTMLResponse)
async def api_keys_page(
    request: Request,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    return _render(
        request,
        "admin/api_keys.html",
        _api_keys_page_context(request, admin_or_response, limit=limit, offset=offset),
    )


@router.post("/admin/api-keys", response_class=HTMLResponse)
async def create_api_key(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body_lists(await request.body())
    name = (form.get("name") or [""])[-1].strip()
    kind = ((form.get("kind") or ["admin"])[-1].strip() or "admin")
    scopes = _parse_multi_text_values(form.get("scopes"))
    mailbox_patterns = _parse_csv_values((form.get("mailbox_patterns") or [""])[-1])
    try:
        domain_grant_mode, domain_ids = _parse_domain_grant_form(form)
    except ValueError as exc:
        domain_ids = []
        domain_grant_mode = (form.get("domain_grant_mode") or ["all"])[-1]
        error_message = (
            "请选择至少一个授权域名，或切换为授权所有可用域名。"
            if str(exc) == "empty selected domain grants"
            else "授权域名选择无效。"
        )
        create_form = _api_key_form_values(
            {
                "name": name,
                "kind": kind,
                "scopes": scopes,
                "domain_grant_mode": domain_grant_mode,
                "domain_ids": [],
                "mailbox_patterns": (form.get("mailbox_patterns") or [""])[-1],
            }
        )
        return _render(
            request,
            "admin/api_keys.html",
            _api_keys_page_context(request, admin_or_response, error=error_message, create_form=create_form),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    create_form = _api_key_form_values(
        {
            "name": name,
            "kind": kind,
            "scopes": scopes,
            "domain_grant_mode": domain_grant_mode,
            "domain_ids": domain_ids,
            "mailbox_patterns": (form.get("mailbox_patterns") or [""])[-1],
        }
    )

    if not name:
        return _render(
            request,
            "admin/api_keys.html",
            _api_keys_page_context(request, admin_or_response, error="名称不能为空。", create_form=create_form),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    try:
        created = await request.app.state.runtime.api_keys.create_key(
            name=name,
            kind=kind,
            scopes=scopes,
            domain_ids=domain_ids,
            mailbox_patterns=mailbox_patterns,
        )
    except (ValueError, sqlite3.IntegrityError) as exc:
        return _render(
            request,
            "admin/api_keys.html",
            _api_keys_page_context(request, admin_or_response, error=str(exc), create_form=create_form),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    await _log_admin_audit(request, admin_or_response, "api_keys.create", "api_key", str(created["id"]), "success")
    return _render(
        request,
        "admin/api_keys.html",
        _api_keys_page_context(request, admin_or_response, created_api_key=created),
        status_code=status.HTTP_200_OK,
    )


@router.get("/admin/api-keys/{api_key_id}", response_class=HTMLResponse)
async def api_key_detail_page(
    api_key_id: int,
    request: Request,
    updated: int = Query(default=0, ge=0, le=1),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    return _render(
        request,
        "admin/api_key_detail.html",
        _api_key_edit_context(request, admin_or_response, api_key_id, updated=bool(updated)),
    )


@router.post("/admin/api-keys/{api_key_id}", response_class=HTMLResponse)
async def update_api_key_from_form(api_key_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    try:
        current_api_key = request.app.state.runtime.api_keys.get_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    form = _parse_form_body_lists(await request.body())
    name = (form.get("name") or [""])[-1].strip()
    kind = ((form.get("kind") or [current_api_key["kind"]])[-1].strip() or current_api_key["kind"])
    status_value = ((form.get("status") or ["active"])[-1].strip() or "active")
    scopes = _parse_multi_text_values(form.get("scopes"))
    mailbox_patterns_raw = (form.get("mailbox_patterns") or [""])[-1]
    allowed_ip_cidrs_raw = (form.get("allowed_ip_cidrs") or [""])[-1]
    expires_at = _parse_nullable_text((form.get("expires_at") or [""])[-1])
    try:
        domain_grant_mode, domain_ids = _parse_domain_grant_form(form)
        rate_limit_per_min = _parse_non_negative_int(
            (form.get("rate_limit_per_min") or ["3600"])[-1],
            default=3600,
            field_name="rate_limit_per_min",
        )
    except ValueError as exc:
        domain_grant_mode = (form.get("domain_grant_mode") or ["all"])[-1]
        domain_ids = []
        error_message = (
            "请选择至少一个授权域名，或切换为授权所有可用域名。"
            if str(exc) == "empty selected domain grants"
            else "提交的密钥配置无效。"
        )
        edit_form = _api_key_edit_form_values(
            current_api_key,
            {
                "name": name,
                "description": (form.get("description") or [""])[-1],
                "kind": kind,
                "status": status_value,
                "scopes": scopes,
                "domain_grant_mode": domain_grant_mode,
                "domain_ids": domain_ids,
                "mailbox_patterns": mailbox_patterns_raw,
                "allow_header": _form_bool((form.get("allow_header") or [None])[-1]),
                "allow_query": _form_bool((form.get("allow_query") or [None])[-1]),
                "rate_limit_per_min": (form.get("rate_limit_per_min") or ["3600"])[-1],
                "allowed_ip_cidrs": allowed_ip_cidrs_raw,
                "expires_at": expires_at or "",
            },
        )
        return _render(
            request,
            "admin/api_key_detail.html",
            _api_key_edit_context(
                request,
                admin_or_response,
                api_key_id,
                error=error_message,
                form=edit_form,
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    edit_form = {
        "name": name,
        "description": (form.get("description") or [""])[-1],
        "kind": kind,
        "status": status_value,
        "scopes": scopes,
        "domain_grant_mode": domain_grant_mode,
        "domain_ids": domain_ids,
        "mailbox_patterns": mailbox_patterns_raw,
        "allow_header": _form_bool((form.get("allow_header") or [None])[-1]),
        "allow_query": _form_bool((form.get("allow_query") or [None])[-1]),
        "rate_limit_per_min": str(rate_limit_per_min),
        "allowed_ip_cidrs": allowed_ip_cidrs_raw,
        "expires_at": expires_at or "",
    }

    if not name:
        return _render(
            request,
            "admin/api_key_detail.html",
            _api_key_edit_context(
                request,
                admin_or_response,
                api_key_id,
                error="名称不能为空。",
                form=_api_key_edit_form_values(current_api_key, edit_form),
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    try:
        await request.app.state.runtime.api_keys.update_key(
            api_key_id,
            name=name,
            description=_parse_nullable_text((form.get("description") or [""])[-1]),
            kind=kind,
            status=status_value,
            scopes=scopes,
            domain_ids=domain_ids,
            mailbox_patterns=_parse_csv_values(mailbox_patterns_raw),
            allow_header=edit_form["allow_header"],
            allow_query=edit_form["allow_query"],
            rate_limit_per_min=rate_limit_per_min,
            allowed_ip_cidrs=_parse_csv_values(allowed_ip_cidrs_raw),
            expires_at=expires_at,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (ValueError, sqlite3.IntegrityError) as exc:
        return _render(
            request,
            "admin/api_key_detail.html",
            _api_key_edit_context(
                request,
                admin_or_response,
                api_key_id,
                error=str(exc),
                form=_api_key_edit_form_values(current_api_key, edit_form),
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    await _log_admin_audit(request, admin_or_response, "api_keys.update", "api_key", str(api_key_id), "success")
    return RedirectResponse(f"/admin/api-keys/{api_key_id}?updated=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/api-keys/{api_key_id}/rotate", response_class=HTMLResponse)
async def rotate_api_key_from_form(api_key_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    try:
        rotated = await request.app.state.runtime.api_keys.rotate_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    await _log_admin_audit(request, admin_or_response, "api_keys.rotate", "api_key", str(api_key_id), "success")
    return _render(
        request,
        "admin/api_key_detail.html",
        _api_key_edit_context(request, admin_or_response, api_key_id, rotated_api_key=rotated),
        status_code=status.HTTP_200_OK,
    )


@router.post("/admin/api-keys/{api_key_id}/revoke")
async def revoke_api_key(api_key_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    try:
        await request.app.state.runtime.api_keys.revoke_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    await _log_admin_audit(request, admin_or_response, "api_keys.revoke", "api_key", str(api_key_id), "success")
    form = _parse_form_body(await request.body())
    limit = _parse_positive_int(form.get("limit"), default=DEFAULT_PAGE_SIZE, field_name="limit")
    offset = _parse_non_negative_int(form.get("offset"), default=0, field_name="offset")
    return RedirectResponse(
        f"/admin/api-keys?limit={limit}&offset={offset}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/api-keys/{api_key_id}/delete")
async def delete_api_key_from_form(api_key_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    try:
        await request.app.state.runtime.api_keys.delete_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    await _log_admin_audit(request, admin_or_response, "api_keys.delete", "api_key", str(api_key_id), "success")
    form = _parse_form_body(await request.body())
    limit = _parse_positive_int(form.get("limit"), default=DEFAULT_PAGE_SIZE, field_name="limit")
    offset = _parse_non_negative_int(form.get("offset"), default=0, field_name="offset")
    return RedirectResponse(
        f"/admin/api-keys?limit={limit}&offset={offset}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource: str | None = Query(default=None),
    start_time: str | None = Query(default=None),
    end_time: str | None = Query(default=None),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    audit_result = request.app.state.runtime.audit.list_logs(
        limit=limit,
        offset=offset,
        actor=actor,
        action=action,
        resource=resource,
        start_time=start_time,
        end_time=end_time,
    )
    logs = audit_result["items"]
    filters = {
        "actor": actor or "",
        "action": action or "",
        "resource": resource or "",
        "start_time": start_time or "",
        "end_time": end_time or "",
    }
    return _render(
        request,
        "admin/audit.html",
        {
            "page_title": "审计日志",
            "admin": admin_or_response,
            "logs": logs,
            "filters": filters,
            "pagination": build_pagination_context(
                path="/admin/audit",
                limit=limit,
                offset=offset,
                total_count=audit_result["total_count"],
                item_count=len(logs),
                extra_params={key: value for key, value in filters.items() if value},
            ),
        },
    )


def _mail_store_stats(request: Request) -> dict[str, int]:
    with connect_database(request.app.state.runtime.settings.database_path) as connection:
        return {
            "messages": _count(connection, "SELECT COUNT(*) AS count FROM messages"),
            "deliveries": _count(connection, "SELECT COUNT(*) AS count FROM message_deliveries"),
            "mailboxes": _count(connection, "SELECT COUNT(*) AS count FROM mailboxes"),
            "attachments": _count(connection, "SELECT COUNT(*) AS count FROM attachments"),
            "smtp_sessions": _count(connection, "SELECT COUNT(*) AS count FROM smtp_sessions"),
        }


def _settings_items(request: Request) -> list[dict[str, Any]]:
    runtime_settings = request.app.state.runtime.get_settings()
    app_settings = request.app.state.settings
    return [
        {
            "label": "最大邮件大小",
            "value": runtime_settings["max_message_size_bytes"],
            "hint": "系统允许接收的单封邮件大小上限（字节）。",
        },
        {
            "label": "单封邮件最大收件人数",
            "value": runtime_settings["max_recipients_per_message"],
            "hint": "单次 SMTP 事务允许的 RCPT TO 数量上限。",
        },
        {
            "label": "SMTP 空闲超时",
            "value": runtime_settings["smtp_idle_timeout_seconds"],
            "hint": "SMTP 会话无命令时的空闲断开时间（秒）。",
        },
        {
            "label": "SMTP 并发连接上限",
            "value": runtime_settings["smtp_max_concurrent_connections"],
            "hint": "同一进程允许同时保持的 SMTP 连接数上限。",
        },
        {
            "label": "每 IP 短窗口连接上限",
            "value": runtime_settings["smtp_connection_rate_limit_count"],
            "hint": "单个 IP 在短窗口内允许建立的 SMTP 连接数。",
        },
        {
            "label": "SMTP 连接限流窗口",
            "value": runtime_settings["smtp_connection_rate_limit_window_seconds"],
            "hint": "每 IP SMTP 连接限流统计窗口（秒）。",
        },
        {
            "label": "磁盘告警阈值",
            "value": f"{runtime_settings['disk_warning_threshold_percent']}%",
            "hint": "Dashboard 磁盘使用率超过该百分比时需要关注。",
        },
        {
            "label": "会话 Cookie 名称",
            "value": app_settings.session_cookie_name,
            "hint": "管理后台 HTML 会话使用的 Cookie 名称。",
        },
        {
            "label": "初始管理员账号",
            "value": app_settings.bootstrap_admin_username,
            "hint": "系统启动时自动创建的管理员用户名。",
        },
    ]


def _settings_form_values(request: Request, form: dict[str, str] | None = None) -> dict[str, Any]:
    values = request.app.state.runtime.get_settings()
    payload = form or {}
    return {
        "max_message_size_bytes": payload.get("max_message_size_bytes", str(values["max_message_size_bytes"])),
        "max_recipients_per_message": payload.get("max_recipients_per_message", str(values["max_recipients_per_message"])),
        "smtp_idle_timeout_seconds": payload.get("smtp_idle_timeout_seconds", str(values["smtp_idle_timeout_seconds"])),
        "smtp_max_concurrent_connections": payload.get(
            "smtp_max_concurrent_connections",
            str(values["smtp_max_concurrent_connections"]),
        ),
        "smtp_connection_rate_limit_count": payload.get(
            "smtp_connection_rate_limit_count",
            str(values["smtp_connection_rate_limit_count"]),
        ),
        "smtp_connection_rate_limit_window_seconds": payload.get(
            "smtp_connection_rate_limit_window_seconds",
            str(values["smtp_connection_rate_limit_window_seconds"]),
        ),
        "disk_warning_threshold_percent": payload.get(
            "disk_warning_threshold_percent",
            str(values["disk_warning_threshold_percent"]),
        ),
    }


def _settings_context(
    request: Request,
    admin: dict[str, Any],
    *,
    mail_clear_result: dict[str, int] | None = None,
    settings_updated: bool = False,
    settings_error: str | None = None,
    settings_form: dict[str, Any] | None = None,
    password_changed: bool = False,
    password_error: str | None = None,
    force_password_change: bool = False,
) -> dict[str, Any]:
    return {
        "page_title": "系统设置",
        "admin": admin,
        "settings_items": _settings_items(request),
        "settings_form": settings_form or _settings_form_values(request),
        "settings_updated": settings_updated,
        "settings_error": settings_error,
        "mail_store_stats": _mail_store_stats(request),
        "mail_clear_result": mail_clear_result,
        "password_changed": password_changed,
        "password_error": password_error,
        "force_password_change": force_password_change or bool(admin.get("must_change_password")),
    }


@router.get("/admin/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    mail_cleared: int = Query(default=0, ge=0, le=1),
    cleared_messages: int = Query(default=0, ge=0),
    cleared_mailboxes: int = Query(default=0, ge=0),
    cleared_sessions: int = Query(default=0, ge=0),
    database_size_before_bytes: int = Query(default=0, ge=0),
    database_size_after_bytes: int = Query(default=0, ge=0),
    database_vacuumed: int = Query(default=0, ge=0, le=1),
    settings_updated: int = Query(default=0, ge=0, le=1),
    password_changed: int = Query(default=0, ge=0, le=1),
    force_password_change: int = Query(default=0, ge=0, le=1),
) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    return _render(
        request,
        "admin/settings.html",
        _settings_context(
            request,
            admin_or_response,
            mail_clear_result={
                "messages": cleared_messages,
                "mailboxes": cleared_mailboxes,
                "smtp_sessions": cleared_sessions,
                "database_size_before_bytes": database_size_before_bytes,
                "database_size_after_bytes": database_size_after_bytes,
                "database_vacuumed": database_vacuumed,
            } if mail_cleared else None,
            settings_updated=bool(settings_updated),
            password_changed=bool(password_changed),
            force_password_change=bool(force_password_change),
        ),
    )


@router.post("/admin/settings")
async def update_system_settings_from_form(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    payload = _settings_form_values(request, form)
    try:
        updated = await request.app.state.runtime.system_settings.update_settings(payload)
    except ValueError as exc:
        return _render(
            request,
            "admin/settings.html",
            _settings_context(
                request,
                admin_or_response,
                settings_error=str(exc),
                settings_form=payload,
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    await _log_admin_audit(
        request,
        admin_or_response,
        "settings.update",
        "system_settings",
        None,
        "success",
        details=updated,
    )
    return RedirectResponse("/admin/settings?settings_updated=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/settings/password")
async def change_admin_password(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    current_password = form.get("current_password", "")
    new_password = form.get("new_password", "")
    confirm_password = form.get("confirm_password", "")

    password_error: str | None = None
    if not current_password or not new_password or not confirm_password:
        password_error = "请填写当前密码和新密码。"
    elif len(new_password) < 8:
        password_error = "新密码至少需要 8 个字符。"
    elif new_password != confirm_password:
        password_error = "两次输入的新密码不一致。"

    if password_error is not None:
        return _render(
            request,
            "admin/settings.html",
            _settings_context(request, admin_or_response, password_error=password_error),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        await request.app.state.runtime.auth.change_admin_password(
            int(admin_or_response["id"]),
            current_password,
            new_password,
        )
    except ValueError as exc:
        error_map = {
            "password must not use the default bootstrap value": "新密码不能继续使用默认初始密码。",
            "password must be changed": "新密码不能与当前密码相同。",
        }
        return _render(
            request,
            "admin/settings.html",
            _settings_context(request, admin_or_response, password_error=error_map.get(str(exc), "新密码不符合安全要求。")),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except LookupError:
        return _render(
            request,
            "admin/settings.html",
            _settings_context(request, admin_or_response, password_error="当前密码不正确。"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    await _log_admin_audit(
        request,
        admin_or_response,
        "admin.password_change",
        "admin",
        str(admin_or_response.get("id")),
        "success",
    )
    return RedirectResponse("/admin/settings?password_changed=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/settings/clear-mail")
async def clear_mail_store(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    if form.get("confirm") != "clear-all-mail":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="confirmation required")

    result = await request.app.state.runtime.clear_all_mail()
    await request.app.state.runtime.audit.log(
        "admin",
        str(admin_or_response.get("username") or admin_or_response.get("id") or "admin"),
        "mail.clear_all",
        "mail_store",
        None,
        "success",
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details=result,
    )
    return RedirectResponse(
        (
            "/admin/settings"
            f"?mail_cleared=1&cleared_messages={result['messages']}"
            f"&cleared_mailboxes={result['mailboxes']}"
            f"&cleared_sessions={result['smtp_sessions']}"
            f"&database_size_before_bytes={result.get('database_size_before_bytes', 0)}"
            f"&database_size_after_bytes={result.get('database_size_after_bytes', 0)}"
            f"&database_vacuumed={result.get('database_vacuumed', 0)}"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ─── Retention Rules ───────────────────────────────────────────────────────────


@router.get("/admin/retention", response_class=HTMLResponse)
async def retention_rules_page(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    runtime = request.app.state.runtime
    rules = runtime.retention_rules.list_rules()

    search_query = request.query_params.get("q", "").strip()
    retained_messages = runtime.retention_rules.list_retained_messages(query=search_query) if search_query else []

    notice = None
    if request.query_params.get("created"):
        notice = {"type": "success", "text": "保留规则已创建"}
    elif request.query_params.get("deleted"):
        notice = {"type": "success", "text": "规则已删除"}
    elif request.query_params.get("toggled"):
        notice = {"type": "success", "text": "规则状态已更新"}
    elif request.query_params.get("messages_deleted"):
        count = request.query_params.get("messages_deleted", "0")
        notice = {"type": "success", "text": f"已删除 {count} 封邮件"}

    error = request.query_params.get("error")
    if error:
        notice = {"type": "warning", "text": error}

    return _render(request, "admin/retention.html", {
        "page_title": "保留规则",
        "admin": admin_or_response,
        "rules": rules,
        "retained_messages": retained_messages,
        "search_query": search_query,
        "notice": notice,
    })


@router.post("/admin/retention")
async def create_retention_rule(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body(await request.body())
    rule_type = form.get("rule_type", "").strip()
    pattern = form.get("pattern", "").strip()
    description = form.get("description", "").strip()

    runtime = request.app.state.runtime
    try:
        rule = await runtime.retention_rules.create_rule(rule_type, pattern, description)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/retention?error={str(exc)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    admin_ref = str(admin_or_response.get("username") or admin_or_response.get("id") or "admin")
    await runtime.audit.log(
        "admin", admin_ref, "retention_rules.create", "retention_rule",
        str(rule["id"]), "success",
        ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
    )
    return RedirectResponse("/admin/retention?created=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/retention/{rule_id}/toggle")
async def toggle_retention_rule(rule_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    runtime = request.app.state.runtime
    try:
        await runtime.retention_rules.toggle_rule(rule_id)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/retention?error={str(exc)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    admin_ref = str(admin_or_response.get("username") or admin_or_response.get("id") or "admin")
    await runtime.audit.log(
        "admin", admin_ref, "retention_rules.toggle", "retention_rule",
        str(rule_id), "success",
        ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
    )
    return RedirectResponse("/admin/retention?toggled=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/retention/{rule_id}/delete")
async def delete_retention_rule(rule_id: int, request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    runtime = request.app.state.runtime
    await runtime.retention_rules.delete_rule(rule_id)

    admin_ref = str(admin_or_response.get("username") or admin_or_response.get("id") or "admin")
    await runtime.audit.log(
        "admin", admin_ref, "retention_rules.delete", "retention_rule",
        str(rule_id), "success",
        ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
    )
    return RedirectResponse("/admin/retention?deleted=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/retention/delete-messages")
async def delete_retained_messages(request: Request) -> Response:
    admin_or_response = await _require_admin(request)
    if isinstance(admin_or_response, Response):
        return admin_or_response

    form = _parse_form_body_lists(await request.body())
    message_ids = form.get("message_ids", [])
    if not message_ids:
        return RedirectResponse("/admin/retention?error=未选择邮件", status_code=status.HTTP_303_SEE_OTHER)

    runtime = request.app.state.runtime

    async with runtime._mail_store_lock:
        result = await runtime.writer.execute(
            lambda connection: runtime._delete_messages_by_ids(connection, message_ids)
        )
        storage_paths = result.pop("storage_paths", [])
        await asyncio.to_thread(runtime._delete_storage_files, storage_paths)

    admin_ref = str(admin_or_response.get("username") or admin_or_response.get("id") or "admin")
    await runtime.audit.log(
        "admin", admin_ref, "retention_rules.delete_messages", "messages",
        None, "success",
        ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
        details={"count": result["messages"], "message_ids": message_ids[:20]},
    )
    return RedirectResponse(
        f"/admin/retention?messages_deleted={result['messages']}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
