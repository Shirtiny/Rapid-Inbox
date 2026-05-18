from __future__ import annotations

import hmac
import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse

from app.auth.permissions import PermissionContext
from app.http.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, build_pagination_context
from app.http.sse import (
    LIVE_SSE_EVENT_TYPES,
    count_smtp_sessions,
    recent_smtp_sessions,
    smtp_live_snapshot,
    stream_smtp_live_events,
)
from app.ingest.storage import utc_now
from app.services.dns_check import DnsCheckService


router = APIRouter()


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client is not None else None


async def _current_admin_session(request: Request) -> dict[str, Any] | None:
    cookie_name = request.app.state.settings.session_cookie_name
    token = request.cookies.get(cookie_name)
    if not token:
        return None

    try:
        return await request.app.state.runtime.auth.get_session_admin(token, ip=_client_ip(request))
    except LookupError:
        return None


def _session_permission_context(admin: dict[str, Any]) -> PermissionContext:
    return PermissionContext(
        scopes=("live.read",),
        domain_ids=(),
        mailbox_patterns=(),
        api_key_id=None,
        public_id=str(admin.get("session_id") or admin.get("username") or "admin-session"),
        name=str(admin.get("display_name") or admin.get("username") or "admin-session"),
        kind="admin",
        legacy_credential=True,
    )


def _render_template(request: Request, template_name: str, context: dict[str, Any], *, status_code: int = 200) -> Response:
    response = request.app.state.templates.TemplateResponse(request, template_name, context)
    response.status_code = status_code
    return response


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _coerce_text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_values = value.replace("\n", ",").split(",")
    elif isinstance(value, (list, tuple)):
        raw_values = [str(item) for item in value]
    else:
        raw_values = [str(value)]
    return [item.strip() for item in raw_values if item and item.strip()]


def _coerce_int_list(value: Any) -> list[int]:
    return [int(item) for item in _coerce_text_list(value)]


def _coerce_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"invalid {field_name}")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"invalid {field_name}")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field_name}") from exc
    if normalized < 0:
        raise ValueError(f"invalid {field_name}")
    return normalized


def _nullable_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


async def require_admin_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> PermissionContext:
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="invalid admin api key")

    settings = request.app.state.settings
    if settings.legacy_admin_token_enabled and hmac.compare_digest(x_api_key, settings.admin_token):
        return PermissionContext(
            scopes=(),
            domain_ids=(),
            mailbox_patterns=(),
            api_key_id=None,
            public_id="legacy-admin-token",
            name="legacy-admin-token",
            kind="admin",
            legacy_credential=True,
        )

    try:
        context = request.app.state.runtime.api_keys.authenticate_plain_text(x_api_key)
    except LookupError as exc:
        raise HTTPException(status_code=401, detail="invalid admin api key") from exc

    if context.kind not in {"admin", "service"}:
        raise HTTPException(status_code=403, detail="invalid admin api key")

    return context


require_admin_api_key = require_admin_key


def require_admin_scope(admin: PermissionContext, required_scope: str) -> None:
    if admin.legacy_credential:
        return
    if required_scope not in admin.scopes:
        if required_scope.endswith(".read"):
            write_scope = f"{required_scope[:-5]}.write"
            if write_scope in admin.scopes:
                return
        raise HTTPException(status_code=403, detail=required_scope)


async def _record_admin_key_usage(request: Request, admin: PermissionContext) -> None:
    if admin.api_key_id is None:
        return
    request_ip = request.client.host if request.client is not None else None
    await request.app.state.runtime.api_keys.record_usage(admin, ip=request_ip)


def _audit_actor_ref(admin: PermissionContext) -> str:
    if admin.api_key_id is not None:
        return str(admin.api_key_id)
    return admin.public_id or "legacy-admin-token"


async def _write_audit_best_effort(
    request: Request,
    admin: PermissionContext,
    action: str,
    resource_type: str,
    resource_ref: str | None,
    status_value: str,
) -> None:
    try:
        await request.app.state.runtime.audit.log(
            "api_key",
            _audit_actor_ref(admin),
            action,
            resource_type,
            resource_ref,
            status_value,
        )
    except Exception:
        # Mutation already completed; audit writes are best-effort here.
        return


async def require_admin_live_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> PermissionContext:
    if x_api_key is not None:
        admin = await require_admin_key(request, x_api_key)
        require_admin_scope(admin, "live.read")
        await _record_admin_key_usage(request, admin)
        return admin

    admin_session = await _current_admin_session(request)
    if admin_session is None:
        raise HTTPException(status_code=404, detail="live page not found")
    if admin_session.get("must_change_password"):
        raise HTTPException(status_code=403, detail="password change required")
    return _session_permission_context(admin_session)


@router.get("/admin/live", response_class=HTMLResponse)
async def live_page(
    request: Request,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Response:
    admin = await _current_admin_session(request)
    if admin is None:
        raise HTTPException(status_code=404, detail="live page not found")
    if admin.get("must_change_password"):
        return RedirectResponse("/admin/settings?force_password_change=1", status_code=status.HTTP_303_SEE_OTHER)

    runtime = request.app.state.runtime
    live_events, live_cursor = runtime.live_state.snapshot_state()
    initial_events = live_events[-DEFAULT_PAGE_SIZE:] if live_events else smtp_live_snapshot(runtime, history_limit=DEFAULT_PAGE_SIZE)
    sessions = recent_smtp_sessions(runtime, limit=limit, offset=offset)
    return _render_template(
        request,
        "admin/live.html",
        {
            "page_title": "实时活动",
            "admin": admin,
            "events": initial_events,
            "sessions": sessions,
            "stream_url": f"/api/v1/admin/live/smtp/stream?after_cursor={live_cursor}",
            "live_event_types": LIVE_SSE_EVENT_TYPES,
            "stream_item_limit": DEFAULT_PAGE_SIZE,
            "sessions_pagination": build_pagination_context(
                path="/admin/live",
                limit=limit,
                offset=offset,
                total_count=count_smtp_sessions(runtime),
                item_count=len(sessions),
            ),
        },
    )


@router.get("/api/v1/admin/live/smtp/stream")
async def smtp_stream(
    request: Request,
    _admin: PermissionContext = Depends(require_admin_live_access),
    after_cursor: str | None = Query(default=None),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
) -> StreamingResponse:
    return StreamingResponse(
        stream_smtp_live_events(
            request.app.state.runtime,
            after_cursor=after_cursor,
            last_event_id=last_event_id,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/admin/domains/{domain_id}/dns-check")
async def run_domain_dns_check(
    domain_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "domains.write")
    await _record_admin_key_usage(request, admin)
    runtime = request.app.state.runtime

    try:
        domain = runtime.domains.get_domain(domain_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    dns_check = DnsCheckService()
    check_result = await dns_check.run_dns_check(domain["root_domain_ascii"])
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

    await runtime.writer.execute(operation)
    updated_domain = runtime.domains.get_domain(domain_id)
    updated_domain["dns_check"] = stored_result
    await _write_audit_best_effort(request, admin, "domains.dns_check", "domain", str(domain_id), "success")
    return updated_domain


@router.get("/api/v1/admin/domains")
async def list_domains(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict:
    require_admin_scope(admin, "domains.read")
    await _record_admin_key_usage(request, admin)
    runtime = request.app.state.runtime
    return {"items": runtime.list_domains()}


@router.post("/api/v1/admin/domains", status_code=status.HTTP_201_CREATED)
async def create_domain(
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict:
    require_admin_scope(admin, "domains.write")
    await _record_admin_key_usage(request, admin)
    runtime = request.app.state.runtime
    root_domain = payload.get("root_domain")
    if not isinstance(root_domain, str) or not root_domain.strip():
        raise HTTPException(status_code=422, detail="root_domain is required")
    settings = runtime.get_settings()

    try:
        created = await runtime.create_domain(
            root_domain,
            accept_exact=payload.get("accept_exact", True),
            accept_subdomains=payload.get("accept_subdomains", True),
            public_web_enabled=payload.get("public_web_enabled", True),
            public_api_enabled=payload.get("public_api_enabled", True),
            plus_addressing_mode=payload.get("plus_addressing_mode", "keep"),
            local_part_case_sensitive=payload.get("local_part_case_sensitive", False),
            is_active=payload.get("is_active", True),
            max_message_size_bytes=payload.get("max_message_size_bytes", settings["max_message_size_bytes"]),
        )
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await _write_audit_best_effort(request, admin, "domains.create", "domain", str(created["id"]), "success")
    return created


@router.get("/api/v1/admin/domains/{domain_id}")
async def get_domain(
    domain_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "domains.read")
    await _record_admin_key_usage(request, admin)
    try:
        return request.app.state.runtime.domains.get_domain(domain_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/api/v1/admin/domains/{domain_id}")
async def update_domain(
    domain_id: int,
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "domains.write")
    await _record_admin_key_usage(request, admin)
    try:
        updated = await request.app.state.runtime.domains.update_domain(domain_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await _write_audit_best_effort(request, admin, "domains.update", "domain", str(domain_id), "success")
    return updated


@router.delete("/api/v1/admin/domains/{domain_id}")
async def delete_domain(
    domain_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "domains.write")
    await _record_admin_key_usage(request, admin)
    try:
        deleted = await request.app.state.runtime.domains.delete_domain(domain_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="domain has dependent mailboxes or grants") from exc
    await _write_audit_best_effort(request, admin, "domains.delete", "domain", str(domain_id), "success")
    return {"deleted": True, "domain": deleted}


@router.get("/api/v1/admin/mailboxes")
async def list_mailboxes(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    q: str | None = Query(default=None),
    domain_id: int | None = Query(default=None),
    public_enabled: bool | None = Query(default=None),
    is_hidden: bool | None = Query(default=None),
) -> dict[str, Any]:
    require_admin_scope(admin, "mailboxes.read")
    await _record_admin_key_usage(request, admin)
    service = request.app.state.runtime.mailboxes
    result = service.list_mailboxes(
        limit=limit,
        offset=offset,
        query=q,
        domain_id=domain_id,
        public_enabled=public_enabled,
        is_hidden=is_hidden,
    )
    result["total_count"] = service.count_mailboxes(
        query=q,
        domain_id=domain_id,
        public_enabled=public_enabled,
        is_hidden=is_hidden,
    )
    return result


@router.get("/api/v1/admin/mailboxes/{mailbox_id}")
async def get_mailbox(
    mailbox_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    require_admin_scope(admin, "mailboxes.read")
    await _record_admin_key_usage(request, admin)
    try:
        mailbox = request.app.state.runtime.mailboxes.get_mailbox(mailbox_id)
        deliveries = request.app.state.runtime.mailboxes.list_mailbox_deliveries(
            mailbox_id,
            limit=limit,
            offset=offset,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {**mailbox, "deliveries": deliveries["items"], "delivery_count": deliveries["total_count"]}


@router.patch("/api/v1/admin/mailboxes/{mailbox_id}")
async def update_mailbox(
    mailbox_id: int,
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "mailboxes.write")
    await _record_admin_key_usage(request, admin)

    updates: dict[str, Any] = {}
    if "public_enabled" in payload:
        updates["public_enabled"] = _coerce_bool(payload["public_enabled"])
    if "is_hidden" in payload:
        updates["is_hidden"] = _coerce_bool(payload["is_hidden"])
    if not updates:
        raise HTTPException(status_code=422, detail="public_enabled or is_hidden is required")

    try:
        updated = await request.app.state.runtime.mailboxes.update_mailbox(mailbox_id, updates)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await _write_audit_best_effort(request, admin, "mailboxes.update", "mailbox", str(mailbox_id), "success")
    return updated


@router.delete("/api/v1/admin/mailboxes/{mailbox_id}")
async def delete_mailbox_deliveries(
    mailbox_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "mailboxes.write")
    await _record_admin_key_usage(request, admin)
    try:
        result = await request.app.state.runtime.mailboxes.soft_delete_mailbox_deliveries(mailbox_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await _write_audit_best_effort(
        request,
        admin,
        "deliveries.bulk_delete",
        "mailbox",
        str(mailbox_id),
        "success",
    )
    return result


@router.get("/api/v1/admin/messages")
async def list_messages(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    q: str | None = Query(default=None),
    parse_status: str | None = Query(default=None),
    mailbox_id: str | None = Query(default=None),
) -> dict[str, Any]:
    require_admin_scope(admin, "messages.read")
    await _record_admin_key_usage(request, admin)
    resolved_mailbox_id: int | None = None
    if mailbox_id:
        try:
            resolved_mailbox_id = int(mailbox_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="mailbox_id must be a valid integer")
    try:
        return request.app.state.runtime.messages.list_messages(
            limit=limit,
            offset=offset,
            query=q,
            parse_status=parse_status,
            mailbox_id=resolved_mailbox_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/v1/admin/messages/bulk-delete")
async def bulk_delete_deliveries(
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "messages.write")
    await _record_admin_key_usage(request, admin)
    delivery_ids = _coerce_text_list(payload.get("delivery_ids"))
    result = await request.app.state.runtime.messages.soft_delete_deliveries(delivery_ids)
    await _write_audit_best_effort(
        request,
        admin,
        "deliveries.bulk_delete",
        "delivery",
        None,
        "success",
    )
    return result


@router.post("/api/v1/admin/messages/{message_id}/reparse", status_code=status.HTTP_202_ACCEPTED)
async def reparse_message(
    message_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict:
    require_admin_scope(admin, "messages.write")
    await _record_admin_key_usage(request, admin)
    try:
        await request.app.state.runtime.messages.reparse_message(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await _write_audit_best_effort(request, admin, "messages.reparse", "message", message_id, "success")
    return {"queued": True, "message_id": message_id}


@router.get("/api/v1/admin/messages/{message_id}")
async def get_message(
    message_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "messages.read")
    await _record_admin_key_usage(request, admin)
    try:
        return request.app.state.runtime.messages.get_admin_message_detail(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/admin/messages/{message_id}/raw")
async def download_message_raw(
    message_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> Response:
    require_admin_scope(admin, "messages.read")
    await _record_admin_key_usage(request, admin)
    try:
        raw = request.app.state.runtime.messages.get_admin_raw_message(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(raw, media_type="message/rfc822")


@router.get("/api/v1/admin/messages/{message_id}/attachments/{attachment_id}")
async def download_message_attachment(
    message_id: str,
    attachment_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> Response:
    require_admin_scope(admin, "messages.read")
    await _record_admin_key_usage(request, admin)
    try:
        attachment = request.app.state.runtime.messages.get_admin_attachment(message_id, attachment_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    safe_filename = attachment.get("safe_filename") or "attachment.bin"
    return Response(
        attachment["content"],
        media_type=attachment.get("content_type") or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/api/v1/admin/messages/{message_id}")
async def delete_message_deliveries(
    message_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "messages.write")
    await _record_admin_key_usage(request, admin)
    try:
        detail = request.app.state.runtime.messages.get_admin_message_detail(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    delivery_ids = [str(item["delivery_id"]) for item in detail["deliveries"]]
    result = await request.app.state.runtime.messages.soft_delete_deliveries(delivery_ids)
    await _write_audit_best_effort(request, admin, "deliveries.bulk_delete", "message", message_id, "success")
    return result


@router.delete("/api/v1/admin/messages/{message_id}/deliveries/{delivery_id}")
async def delete_message_delivery(
    message_id: str,
    delivery_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "messages.write")
    await _record_admin_key_usage(request, admin)
    try:
        detail = request.app.state.runtime.messages.get_admin_message_detail(message_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if delivery_id not in {str(item["delivery_id"]) for item in detail["deliveries"]}:
        raise HTTPException(status_code=404, detail="delivery not found")
    result = await request.app.state.runtime.messages.soft_delete_delivery(delivery_id)
    await _write_audit_best_effort(request, admin, "deliveries.delete", "delivery", delivery_id, "success")
    return result


@router.get("/api/v1/admin/smtp-sessions")
async def list_smtp_sessions(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    require_admin_scope(admin, "smtp.read")
    await _record_admin_key_usage(request, admin)
    runtime = request.app.state.runtime
    return {
        "items": recent_smtp_sessions(runtime, limit=limit, offset=offset),
        "total_count": count_smtp_sessions(runtime),
    }


@router.get("/api/v1/admin/smtp-sessions/{session_id}")
async def get_smtp_session(
    session_id: str,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "smtp.read")
    await _record_admin_key_usage(request, admin)
    runtime = request.app.state.runtime
    with sqlite3.connect(runtime.settings.database_path, check_same_thread=False) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM smtp_sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="smtp session not found")
        events = connection.execute(
            """
            SELECT id, seq, event_type, ts, payload_json
            FROM smtp_events
            WHERE session_id = ?
            ORDER BY seq ASC
            """,
            (session_id,),
        ).fetchall()
    return {
        **dict(row),
        "tls_used": bool(row["tls_used"]),
        "events": [dict(event) for event in events],
    }


@router.get("/api/v1/admin/audit-logs")
async def list_audit_logs(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
    limit: int = Query(default=100, ge=0, le=1000),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource: str | None = Query(default=None),
    start_time: str | None = Query(default=None),
    end_time: str | None = Query(default=None),
) -> dict:
    require_admin_scope(admin, "audit.read")
    await _record_admin_key_usage(request, admin)
    return request.app.state.runtime.audit.list_logs(
        limit=limit,
        offset=offset,
        actor=actor,
        action=action,
        resource=resource,
        start_time=start_time,
        end_time=end_time,
    )


@router.get("/api/v1/admin/settings")
async def get_settings(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict:
    require_admin_scope(admin, "system.read")
    await _record_admin_key_usage(request, admin)
    return request.app.state.runtime.system_settings.get_settings()


@router.patch("/api/v1/admin/settings")
async def update_settings(
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict:
    require_admin_scope(admin, "system.write")
    await _record_admin_key_usage(request, admin)
    try:
        updated = await request.app.state.runtime.system_settings.update_settings(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await _write_audit_best_effort(request, admin, "settings.update", "system_settings", None, "success")
    return updated


@router.get("/api/v1/admin/api-keys")
async def list_api_keys(
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.read")
    await _record_admin_key_usage(request, admin)
    return request.app.state.runtime.api_keys.list_keys(limit=limit, offset=offset)


@router.post("/api/v1/admin/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.write")
    await _record_admin_key_usage(request, admin)

    name = str(payload.get("name", "")).strip()
    kind = str(payload.get("kind", "")).strip()
    scopes = _coerce_text_list(payload.get("scopes"))
    grant_all_domains = _coerce_bool(payload.get("grant_all_domains")) if "grant_all_domains" in payload else False
    domain_ids = [] if grant_all_domains else _coerce_int_list(payload.get("domain_ids"))
    mailbox_patterns = _coerce_text_list(payload.get("mailbox_patterns"))

    if not name:
        raise HTTPException(status_code=422, detail="name is required")
    if not kind:
        raise HTTPException(status_code=422, detail="kind is required")
    if not scopes:
        raise HTTPException(status_code=422, detail="scopes are required")

    try:
        created = await request.app.state.runtime.api_keys.create_key(
            name=name,
            kind=kind,
            scopes=scopes,
            domain_ids=domain_ids,
            mailbox_patterns=mailbox_patterns,
        )
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await _write_audit_best_effort(request, admin, "api_keys.create", "api_key", str(created["id"]), "success")
    return created


@router.get("/api/v1/admin/api-keys/{api_key_id}")
async def get_api_key(
    api_key_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.read")
    await _record_admin_key_usage(request, admin)
    try:
        return request.app.state.runtime.api_keys.get_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/api/v1/admin/api-keys/{api_key_id}")
async def update_api_key(
    api_key_id: int,
    payload: dict[str, Any],
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.write")
    await _record_admin_key_usage(request, admin)

    updates: dict[str, Any] = {}
    if "name" in payload:
        updates["name"] = str(payload.get("name", "")).strip()
    if "description" in payload:
        updates["description"] = _nullable_text(payload.get("description"))
    if "kind" in payload:
        updates["kind"] = str(payload.get("kind", "")).strip()
    if "status" in payload:
        updates["status"] = str(payload.get("status", "")).strip()
    if "allow_header" in payload:
        updates["allow_header"] = _coerce_bool(payload.get("allow_header"))
    if "allow_query" in payload:
        updates["allow_query"] = _coerce_bool(payload.get("allow_query"))
    if "rate_limit_per_min" in payload:
        try:
            updates["rate_limit_per_min"] = _coerce_non_negative_int(
                payload.get("rate_limit_per_min"),
                "rate_limit_per_min",
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "allowed_ip_cidrs" in payload:
        updates["allowed_ip_cidrs"] = _coerce_text_list(payload.get("allowed_ip_cidrs"))
    if "expires_at" in payload:
        updates["expires_at"] = _nullable_text(payload.get("expires_at"))
    if "scopes" in payload:
        updates["scopes"] = _coerce_text_list(payload.get("scopes"))
    grant_all_domains = _coerce_bool(payload.get("grant_all_domains")) if "grant_all_domains" in payload else False
    if grant_all_domains:
        updates["domain_ids"] = []
    elif "domain_ids" in payload:
        try:
            updates["domain_ids"] = _coerce_int_list(payload.get("domain_ids"))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid domain_ids") from exc
    if "mailbox_patterns" in payload:
        updates["mailbox_patterns"] = _coerce_text_list(payload.get("mailbox_patterns"))

    try:
        updated = await request.app.state.runtime.api_keys.update_key(api_key_id, **updates)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await _write_audit_best_effort(request, admin, "api_keys.update", "api_key", str(api_key_id), "success")
    return updated


@router.post("/api/v1/admin/api-keys/{api_key_id}/rotate")
async def rotate_api_key(
    api_key_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.write")
    await _record_admin_key_usage(request, admin)

    try:
        rotated = await request.app.state.runtime.api_keys.rotate_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="api key rotation conflict") from exc

    await _write_audit_best_effort(request, admin, "api_keys.rotate", "api_key", str(api_key_id), "success")
    return rotated


@router.post("/api/v1/admin/api-keys/{api_key_id}/revoke")
async def revoke_api_key(
    api_key_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.write")
    await _record_admin_key_usage(request, admin)

    try:
        revoked = await request.app.state.runtime.api_keys.revoke_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    await _write_audit_best_effort(request, admin, "api_keys.revoke", "api_key", str(api_key_id), "success")
    return revoked


@router.delete("/api/v1/admin/api-keys/{api_key_id}")
async def delete_api_key(
    api_key_id: int,
    request: Request,
    admin: PermissionContext = Depends(require_admin_key),
) -> dict[str, Any]:
    require_admin_scope(admin, "api_keys.write")
    await _record_admin_key_usage(request, admin)

    try:
        deleted = await request.app.state.runtime.api_keys.delete_key(api_key_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await _write_audit_best_effort(request, admin, "api_keys.delete", "api_key", str(api_key_id), "success")
    return {"deleted": True, "api_key_id": api_key_id}
