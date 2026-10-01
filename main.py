"""
授權系統後端 (FastAPI + Supabase + WebSockets)
包含：
  - 核心驗證 (Verify / Heartbeat / WebSocket)
  - HWID / IP 黑名單系統 (Blacklist System)
  - 多裝置 HWID 動態綁定 (max_devices)
  - 伺服器時間校驗與 HMAC 簽名 (Anti-Clock Manipulation)
  - 動態記憶體 Key / 參數注入 (Dynamic Memory Injection)
  - 即時廣播公告彈窗推播 (Real-time Broadcast Popup)
  - API 速率限制 (Rate Limiting)
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, Dict, List

from fastapi import (
    FastAPI, HTTPException, Header, Depends, WebSocket,
    WebSocketDisconnect, Query, UploadFile, File, Form, Response, Request
)
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel
from supabase import create_client, Client

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

# ------------------------------------------------------------------
# 環境設定
# ------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY") or os.environ.get("SUPABASE_KEY") or ""
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

supabase: Optional[Client] = create_client(SUPABASE_URL, SUPABASE_KEY) if (SUPABASE_URL and SUPABASE_KEY) else None

app = FastAPI(title="YangEnx License System Pro", version="2.0.0")

# ------------------------------------------------------------------
# API 速率限制 (Simple Sliding Window Rate Limiter)
# ------------------------------------------------------------------
ip_request_timestamps: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_MAX = 30     # 每分鐘最多 30 次驗證請求
RATE_LIMIT_WINDOW = 60  # 秒

def check_rate_limit(request: Request):
    client_ip = get_client_ip(request)
    now = time.time()
    ip_request_timestamps[client_ip] = [t for t in ip_request_timestamps[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(ip_request_timestamps[client_ip]) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="請求過於頻繁，請稍後再試 (Rate limit exceeded)")
    ip_request_timestamps[client_ip].append(now)

# ------------------------------------------------------------------
# WebSocket 連線註冊表
# key = license_key, value = {"ws": WebSocket, "app_id": str, "username": str, "hwid": str, "ip": str, "connected_at": iso}
# ------------------------------------------------------------------
active_connections: Dict[str, dict] = {}

async def push_status_to_key(license_key: str, status: str, message: str, extra: Optional[dict] = None):
    """如果這把卡密目前在線上，推播狀態訊息給它並斷開連線。"""
    entry = active_connections.get(license_key)
    if entry is None:
        return
    ws = entry["ws"]
    payload = {"status": status, "message": message}
    if extra:
        payload.update(extra)
    try:
        await ws.send_json(payload)
        await ws.close()
    except Exception as e:
        print(f"[WebSocket Push Error] {e}")
    active_connections.pop(license_key, None)

async def broadcast_to_app(app_id: Optional[str], status: str, message: str, extra: Optional[dict] = None):
    """推播給指定 app_id 或所有在線連線。"""
    for license_key, entry in list(active_connections.items()):
        if not app_id or entry.get("app_id") == app_id:
            await push_status_to_key(license_key, status, message, extra)

# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------
class VerifyRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str
    version: str
    owner_id: Optional[str] = None
    app_name: Optional[str] = None

class HeartbeatRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str
    owner_id: Optional[str] = None

class VerifyResponse(BaseModel):
    status: str          # ok / invalid / expired / disabled / hwid_mismatch / maintenance / version_mismatch / blacklisted
    message: str
    username: Optional[str] = None
    expires_at: Optional[str] = None
    server_timestamp: Optional[str] = None
    server_time_ms: Optional[int] = None
    signature: Optional[str] = None
    dynamic_payload: Optional[str] = None

class CreateKeyRequest(BaseModel):
    app_id: str
    license_key: Optional[str] = None
    username: str
    max_devices: int = 1
    expires_at: str  # ISO datetime string

class CreateApplicationRequest(BaseModel):
    name: str

class MaintenanceSettingsRequest(BaseModel):
    app_id: str
    maintenance_mode: bool
    maintenance_message: str = "卡密系統維護中"
    latest_version: str = "v1.0.0"

class DynamicPayloadRequest(BaseModel):
    app_id: str
    dynamic_payload: str

class BroadcastRequest(BaseModel):
    app_id: Optional[str] = None
    title: str
    message: str
    level: str = "info"

class BlacklistCreateRequest(BaseModel):
    app_id: Optional[str] = None
    type: str                     # hwid 或 ip
    value: str
    reason: Optional[str] = "管理者手動封禁"

class SaveInternalSettingsRequest(BaseModel):
    app_id: str
    latest_version: str = "v1.0.0"
    update_changelog: str = ""
    stopped: bool = False
    stop_message: str = "YangEnx Internal 停服維護中"

# ------------------------------------------------------------------
# 工具函式
# ------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def log_event(actor: str, event: str, detail: str = "", hwid: str = "", ip_address: str = ""):
    if not supabase:
        return
    try:
        supabase.table("system_logs").insert({
            "actor": actor,
            "event": event,
            "detail": detail,
            "hwid": hwid,
            "ip_address": ip_address,
        }).execute()
    except Exception as e:
        print(f"[Log Event Warning] {e}")

DEFAULT_APP_SETTINGS = {
    "maintenance_mode": False,
    "maintenance_message": "卡密系統維護中",
    "latest_version": "v1.0.0",
    "update_changelog": "",
    "dynamic_payload": "",
}

def get_app_settings(app_id: str) -> dict:
    settings = dict(DEFAULT_APP_SETTINGS)
    if not supabase:
        return settings
    try:
        res = supabase.table("app_settings").select("*").eq("app_id", app_id).execute()
        if res.data:
            row = res.data[0]
            settings["maintenance_mode"] = bool(row.get("maintenance_mode", False))
            settings["maintenance_message"] = row.get("maintenance_message") or DEFAULT_APP_SETTINGS["maintenance_message"]
            settings["latest_version"] = row.get("latest_version") or DEFAULT_APP_SETTINGS["latest_version"]
            if row.get("update_changelog"):
                settings["update_changelog"] = row["update_changelog"]
            if row.get("dynamic_payload"):
                settings["dynamic_payload"] = row["dynamic_payload"]
    except Exception as e:
        print(f"[Supabase Select Warning] {e}")
    return settings

def set_app_settings(app_id: str, maintenance_mode: bool, maintenance_message: str, latest_version: str, update_changelog: str = "", dynamic_payload: str = ""):
    if not supabase:
        return
    try:
        supabase.table("app_settings").upsert({
            "app_id": app_id,
            "maintenance_mode": maintenance_mode,
            "maintenance_message": maintenance_message,
            "latest_version": latest_version,
            "update_changelog": update_changelog,
            "dynamic_payload": dynamic_payload,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        print(f"[Supabase Upsert Error] {e}")

def require_admin(x_admin_token: str = Header(...)):
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid Admin Token")

def _random_token(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))

def generate_owner_id() -> str:
    alphabet = string.ascii_letters + string.digits
    return _random_token(10, alphabet)

def generate_app_secret() -> str:
    return secrets.token_hex(20)

def resolve_app(app_secret: str) -> dict:
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection missing")
    res = supabase.table("license_applications").select("*").eq("app_secret", app_secret).execute()
    if not res.data:
        raise HTTPException(status_code=403, detail="Invalid app secret")
    return res.data[0]

def get_application_or_404(app_id: str) -> dict:
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection missing")
    res = supabase.table("license_applications").select("*").eq("id", app_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Application not found")
    return res.data[0]

# ------------------------------------------------------------------
# 黑名單與 HWID 多裝置解析功能
# ------------------------------------------------------------------
def check_blacklist(app_id: str, hwid: str, client_ip: str) -> tuple[bool, str]:
    """檢查 HWID 或 IP 是否在黑名單中 (支援全域與 App 專屬黑名單)。"""
    if not supabase:
        return False, ""
    try:
        res = supabase.table("blacklists").select("*").execute()
        for row in res.data or []:
            row_app = row.get("app_id")
            if row_app and str(row_app).strip() not in ["", "null", "undefined", "None"] and row_app != app_id:
                continue
            b_type = (row.get("type") or "").lower().strip()
            b_val = (row.get("value") or "").strip()
            reason = row.get("reason") or "已被管理者列入黑名單"
            
            if b_type == "hwid" and hwid and b_val.lower() == hwid.lower():
                return True, f"此裝置已封禁 ({reason})"
            if b_type == "ip" and client_ip and b_val == client_ip:
                return True, f"此 IP 位址已封禁 ({reason})"
    except Exception as e:
        print(f"[Check Blacklist Warning] {e}")
    return False, ""

def parse_hwids(hwid_str: Optional[str]) -> List[str]:
    if not hwid_str:
        return []
    try:
        if hwid_str.startswith("["):
            return json.loads(hwid_str)
    except Exception:
        pass
    return [hwid_str]

def check_and_bind_hwid(row: dict, input_hwid: str) -> tuple[str, str, Optional[List[str]]]:
    bound = parse_hwids(row.get("hwid"))
    max_dev = row.get("max_devices", 1)

    if input_hwid in bound:
        return "ok", "驗證成功", None

    if len(bound) < max_dev:
        new_bound = bound + [input_hwid]
        return "ok", "新裝置綁定成功", new_bound

    return "hwid_mismatch", f"此卡密已綁定滿 {max_dev} 台裝置 (現有: {len(bound)} 台)", None

def generate_server_verification(app_secret: str, license_key: str, hwid: str) -> tuple[str, int, str]:
    now = datetime.now(timezone.utc)
    server_timestamp = now.isoformat()
    server_time_ms = int(now.timestamp() * 1000)
    msg = f"{server_time_ms}:{license_key}:{hwid}"
    sig = hmac.new(app_secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return server_timestamp, server_time_ms, sig

# ------------------------------------------------------------------
# FastAPI 根路由與 Health
# ------------------------------------------------------------------
@app.get("/", include_in_schema=False)
@app.head("/", include_in_schema=False)
async def root():
    return {"status": "ok", "service": "YangEnx License System Pro"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/admin")
def admin_panel():
    return FileResponse(os.path.join(os.path.dirname(__file__), "admin.html"))

# ------------------------------------------------------------------
# 卡密驗證：POST /api/verify
# ------------------------------------------------------------------
@app.post("/api/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest, request: Request, _: None = Depends(check_rate_limit)):
    client_ip = get_client_ip(request)
    application = resolve_app(req.app_secret)
    app_id = application["id"]

    if req.owner_id and application.get("owner_id") != req.owner_id:
        return VerifyResponse(status="invalid", message="應用程式憑證 (Owner ID) 錯誤")
    if req.app_name and application.get("name") != req.app_name:
        return VerifyResponse(status="invalid", message="應用程式名稱不匹配")

    # 1. 檢查黑名單
    is_blacklisted, bl_msg = check_blacklist(app_id, req.hwid, client_ip)
    if is_blacklisted:
        log_event(req.license_key or "UNKNOWN", "BLACKLISTED", bl_msg, req.hwid, client_ip)
        return VerifyResponse(status="blacklisted", message=bl_msg)

    # 2. 檢查維護模式與版本號
    settings = get_app_settings(app_id)
    if req.version != settings["latest_version"]:
        return VerifyResponse(status="version_mismatch", message=f"偵測到新版本，請更新至 {settings['latest_version']}。")
    if settings["maintenance_mode"]:
        return VerifyResponse(status="maintenance", message=settings["maintenance_message"])

    # 3. 查詢卡密
    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", req.license_key)
        .eq("app_id", app_id)
        .execute()
    )
    if not res.data:
        log_event("UNKNOWN_KEY", "LOGIN_FAILED", f"卡密不存在: [{req.license_key}]", req.hwid, client_ip)
        return VerifyResponse(status="invalid", message="卡密不存在")

    row = res.data[0]

    # 4. 檢查狀態與過期時間
    if row["status"] != "active":
        log_event(row["username"], "LOGIN_FAILED", "此卡密已被停用", req.hwid, client_ip)
        return VerifyResponse(status="disabled", message="此卡密已被停用")

    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        log_event(row["username"], "LOGIN_FAILED", "此卡密已過期", req.hwid, client_ip)
        return VerifyResponse(status="expired", message="此卡密已過期")

    # 5. 多裝置 HWID 比對與動態綁定
    hwid_status, hwid_msg, new_bound = check_and_bind_hwid(row, req.hwid)
    if hwid_status != "ok":
        log_event(row["username"], "LOGIN_FAILED", hwid_msg, req.hwid, client_ip)
        return VerifyResponse(status="hwid_mismatch", message=hwid_msg)

    update_data = {"last_seen_at": datetime.now(timezone.utc).isoformat()}
    if new_bound is not None:
        update_data["hwid"] = json.dumps(new_bound)
    supabase.table("license_keys").update(update_data).eq("id", row["id"]).execute()

    server_ts, server_ms, sig = generate_server_verification(req.app_secret, req.license_key, req.hwid)
    dynamic_payload = settings.get("dynamic_payload", "")

    log_event(row["username"], "VERIFY_SUCCESS", "認證成功登入主程式", req.hwid, client_ip)
    return VerifyResponse(
        status="ok",
        message="驗證成功",
        username=row["username"],
        expires_at=row["expires_at"],
        server_timestamp=server_ts,
        server_time_ms=server_ms,
        signature=sig,
        dynamic_payload=dynamic_payload,
    )

# ------------------------------------------------------------------
# WebSocket 即時推播與心跳維持: WS /ws/license
# ------------------------------------------------------------------
@app.websocket("/ws/license")
async def ws_license(
    websocket: WebSocket,
    license_key: str = Query(...),
    hwid: str = Query(...),
    app_secret: str = Query(...),
    version: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    app_name: Optional[str] = Query(None),
):
    client_ip = websocket.client.host if websocket.client else "127.0.0.1"

    res_app = supabase.table("license_applications").select("*").eq("app_secret", app_secret).execute()
    if not res_app.data:
        await websocket.close(code=4003)
        return
    application = res_app.data[0]
    app_id = application["id"]

    if owner_id and application.get("owner_id") != owner_id:
        await websocket.close(code=4003)
        return

    await websocket.accept()

    # 1. 檢查黑名單
    is_bl, bl_msg = check_blacklist(app_id, hwid, client_ip)
    if is_bl:
        await websocket.send_json({"status": "blacklisted", "message": bl_msg})
        await websocket.close()
        return

    # 2. 檢查維護模式與版本
    settings = get_app_settings(app_id)
    if version and version != settings["latest_version"]:
        await websocket.send_json({"status": "version_mismatch", "message": f"請更新至 {settings['latest_version']}"})
        await websocket.close()
        return

    if settings["maintenance_mode"]:
        await websocket.send_json({"status": "maintenance", "message": settings["maintenance_message"]})
        await websocket.close()
        return

    # 3. 檢查卡密狀態
    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", license_key)
        .eq("app_id", app_id)
        .execute()
    )
    if not res.data:
        await websocket.send_json({"status": "invalid", "message": "卡密不存在或已被刪除"})
        await websocket.close()
        return

    row = res.data[0]
    if row["status"] != "active":
        await websocket.send_json({"status": "disabled", "message": "此卡密已被停用"})
        await websocket.close()
        return

    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        await websocket.send_json({"status": "expired", "message": "此卡密已過期"})
        await websocket.close()
        return

    hwid_status, hwid_msg, _ = check_and_bind_hwid(row, hwid)
    if hwid_status != "ok":
        await websocket.send_json({"status": "hwid_mismatch", "message": hwid_msg})
        await websocket.close()
        return

    # 4. 註冊在線連線
    server_ts, server_ms, sig = generate_server_verification(app_secret, license_key, hwid)
    active_connections[license_key] = {
        "ws": websocket,
        "app_id": app_id,
        "username": row["username"],
        "hwid": hwid,
        "ip": client_ip,
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }

    await websocket.send_json({
        "status": "ok",
        "message": "已建立即時連線",
        "server_timestamp": server_ts,
        "server_time_ms": server_ms,
        "signature": sig,
        "dynamic_payload": settings.get("dynamic_payload", "")
    })

    try:
        while True:
            text = await websocket.receive_text()
            if "ping" in text.lower():
                _, ts_ms, _ = generate_server_verification(app_secret, license_key, hwid)
                await websocket.send_json({"status": "pong", "message": "pong", "server_time_ms": ts_ms})
    except WebSocketDisconnect:
        pass
    finally:
        entry = active_connections.get(license_key)
        if entry is not None and entry["ws"] is websocket:
            active_connections.pop(license_key, None)

# ------------------------------------------------------------------
# 相容性心跳 API: POST /api/heartbeat
# ------------------------------------------------------------------
@app.post("/api/heartbeat", response_model=VerifyResponse)
def heartbeat(req: HeartbeatRequest, request: Request):
    client_ip = get_client_ip(request)
    application = resolve_app(req.app_secret)
    app_id = application["id"]

    is_bl, bl_msg = check_blacklist(app_id, req.hwid, client_ip)
    if is_bl:
        return VerifyResponse(status="blacklisted", message=bl_msg)

    settings = get_app_settings(app_id)
    if settings["maintenance_mode"]:
        return VerifyResponse(status="maintenance", message=settings["maintenance_message"])

    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", req.license_key)
        .eq("app_id", app_id)
        .execute()
    )
    if not res.data:
        return VerifyResponse(status="invalid", message="卡密不存在或已被刪除")

    row = res.data[0]
    if row["status"] != "active":
        return VerifyResponse(status="disabled", message="此卡密已被停用")

    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        return VerifyResponse(status="expired", message="此卡密已過期")

    hwid_status, hwid_msg, _ = check_and_bind_hwid(row, req.hwid)
    if hwid_status != "ok":
        return VerifyResponse(status="hwid_mismatch", message=hwid_msg)

    supabase.table("license_keys").update({
        "last_seen_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row["id"]).execute()

    server_ts, server_ms, sig = generate_server_verification(req.app_secret, req.license_key, req.hwid)
    return VerifyResponse(
        status="ok",
        message="心跳成功",
        username=row["username"],
        server_timestamp=server_ts,
        server_time_ms=server_ms,
        signature=sig,
        dynamic_payload=settings.get("dynamic_payload", "")
    )

# ------------------------------------------------------------------
# 後台管理 API - 應用程式與 key 管理
# ------------------------------------------------------------------
@app.post("/api/admin/apps", dependencies=[Depends(require_admin)])
def create_application(req: CreateApplicationRequest):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="應用程式名稱不可為空")

    for _ in range(5):
        data = {
            "name": name,
            "owner_id": generate_owner_id(),
            "app_secret": generate_app_secret(),
        }
        try:
            res = supabase.table("license_applications").insert(data).execute()
            return res.data[0]
        except Exception as e:
            if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                continue
            raise HTTPException(status_code=500, detail=f"建立失敗：{e}")
    raise HTTPException(status_code=500, detail="產生唯一識別碼失敗，請再試一次")

@app.get("/api/admin/apps", dependencies=[Depends(require_admin)])
def list_applications():
    res = supabase.table("license_applications").select("*").order("created_at", desc=True).execute()
    return res.data

@app.delete("/api/admin/apps/{app_id}", dependencies=[Depends(require_admin)])
async def delete_application(app_id: str):
    get_application_or_404(app_id)
    keys_res = supabase.table("license_keys").select("license_key").eq("app_id", app_id).execute()
    for row in keys_res.data or []:
        await push_status_to_key(row["license_key"], "invalid", "此應用程式已被管理員刪除")

    supabase.table("license_keys").delete().eq("app_id", app_id).execute()
    supabase.table("license_applications").delete().eq("id", app_id).execute()
    return {"ok": True}

@app.patch("/api/admin/apps/{app_id}/rotate-secret", dependencies=[Depends(require_admin)])
async def rotate_app_secret(app_id: str):
    get_application_or_404(app_id)
    new_secret = generate_app_secret()
    res = supabase.table("license_applications").update({"app_secret": new_secret}).eq("id", app_id).execute()

    keys_res = supabase.table("license_keys").select("license_key").eq("app_id", app_id).execute()
    for row in keys_res.data or []:
        await push_status_to_key(row["license_key"], "invalid", "應用程式金鑰已重設，請重新登入")

    return res.data[0]

@app.post("/api/admin/keys", dependencies=[Depends(require_admin)])
def create_key(req: CreateKeyRequest):
    get_application_or_404(req.app_id)
    key = req.license_key or "-".join(str(uuid.uuid4()).upper().split("-")[:3])
    data = {
        "license_key": key,
        "app_id": req.app_id,
        "username": req.username,
        "max_devices": req.max_devices,
        "expires_at": req.expires_at,
        "status": "active",
    }
    try:
        res = supabase.table("license_keys").insert(data).execute()
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail="這把卡密在此應用程式底下已經存在")
        raise HTTPException(status_code=500, detail=f"建立失敗：{e}")
    return res.data[0]

@app.get("/api/admin/keys", dependencies=[Depends(require_admin)])
def list_keys(app_id: Optional[str] = Query(None)):
    query = supabase.table("license_keys").select("*, applications:license_applications(name, owner_id)").order("id", desc=True)
    if app_id:
        query = query.eq("app_id", app_id)
    res = query.execute()
    return res.data

@app.patch("/api/admin/keys/{key_id}/disable", dependencies=[Depends(require_admin)])
async def disable_key(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    supabase.table("license_keys").update({"status": "disabled"}).eq("id", key_id).execute()
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "disabled", "此卡密已被停用")
    return {"ok": True}

@app.patch("/api/admin/keys/{key_id}/enable", dependencies=[Depends(require_admin)])
def enable_key(key_id: int):
    supabase.table("license_keys").update({"status": "active"}).eq("id", key_id).execute()
    return {"ok": True}

@app.patch("/api/admin/keys/{key_id}/reset-hwid", dependencies=[Depends(require_admin)])
async def reset_hwid(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    supabase.table("license_keys").update({"hwid": None}).eq("id", key_id).execute()
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "hwid_mismatch", "裝置綁定已被管理者重設，請重新登入")
    return {"ok": True}

@app.delete("/api/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def delete_key(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "invalid", "此卡密已被刪除")
    supabase.table("license_keys").delete().eq("id", key_id).execute()
    return {"ok": True}

@app.get("/api/admin/online", dependencies=[Depends(require_admin)])
def get_online():
    return [
        {
            "license_key": license_key,
            "app_id": entry.get("app_id"),
            "username": entry["username"],
            "hwid": entry.get("hwid"),
            "ip": entry.get("ip"),
            "connected_at": entry["connected_at"],
        }
        for license_key, entry in active_connections.items()
    ]

# ------------------------------------------------------------------
# 維護模式 / 動態記憶體 Key (Dynamic Payload) API
# ------------------------------------------------------------------
@app.get("/api/admin/settings", dependencies=[Depends(require_admin)])
def get_settings(app_id: str = Query(...)):
    get_application_or_404(app_id)
    return get_app_settings(app_id)

@app.put("/api/admin/settings", dependencies=[Depends(require_admin)])
async def update_settings(req: MaintenanceSettingsRequest):
    get_application_or_404(req.app_id)
    current = get_app_settings(req.app_id)
    was_on = current["maintenance_mode"]

    set_app_settings(req.app_id, req.maintenance_mode, req.maintenance_message, req.latest_version, current.get("update_changelog", ""), current.get("dynamic_payload", ""))

    if req.maintenance_mode and not was_on:
        await broadcast_to_app(req.app_id, "maintenance", req.maintenance_message)

    return {"ok": True}

@app.put("/api/admin/apps/{app_id}/dynamic-payload", dependencies=[Depends(require_admin)])
def set_dynamic_payload(app_id: str, req: DynamicPayloadRequest):
    get_application_or_404(app_id)
    current = get_app_settings(app_id)
    set_app_settings(
        app_id,
        current["maintenance_mode"],
        current["maintenance_message"],
        current["latest_version"],
        current.get("update_changelog", ""),
        req.dynamic_payload
    )
    return {"ok": True, "message": "已成功更新動態 Payload"}

# ------------------------------------------------------------------
# 即時廣播彈窗 API (Real-time Broadcast Announcement)
# ------------------------------------------------------------------
@app.post("/api/admin/broadcast", dependencies=[Depends(require_admin)])
async def send_broadcast(req: BroadcastRequest):
    if not req.title.strip() or not req.message.strip():
        raise HTTPException(status_code=400, detail="廣播標題與內容不可為空")

    target_app_id = req.app_id.strip() if req.app_id and str(req.app_id).strip() not in ["", "null", "undefined", "None"] else None

    announcement_payload = {
        "type": "announcement",
        "status": "announcement",
        "title": req.title,
        "message": req.message,
        "level": req.level,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    count = 0
    for license_key, entry in list(active_connections.items()):
        if not target_app_id or entry.get("app_id") == target_app_id:
            try:
                await entry["ws"].send_json(announcement_payload)
                count += 1
            except Exception:
                pass

    if supabase:
        try:
            supabase.table("system_announcements").insert({
                "app_id": target_app_id,
                "title": req.title,
                "message": req.message,
                "level": req.level,
            }).execute()
        except Exception as e:
            print(f"[Announcement Insert Warning] {e}")

    return {"ok": True, "pushed_count": count, "message": f"已成功推送至 {count} 個線上用戶"}

@app.get("/api/admin/announcements", dependencies=[Depends(require_admin)])
def list_announcements():
    if not supabase:
        return []
    res = supabase.table("system_announcements").select("*").order("created_at", desc=True).limit(50).execute()
    return res.data

# ------------------------------------------------------------------
# HWID / IP 黑名單管理 API (Blacklist System)
# ------------------------------------------------------------------
@app.get("/api/admin/blacklists", dependencies=[Depends(require_admin)])
def list_blacklists(app_id: Optional[str] = Query(None)):
    if not supabase:
        return []
    try:
        query = supabase.table("blacklists").select("*").order("id", desc=True)
        if app_id:
            query = query.eq("app_id", app_id)
        res = query.execute()
        return res.data
    except Exception as e:
        print(f"[List Blacklist Warning] {e}")
        return []

@app.post("/api/admin/blacklists", dependencies=[Depends(require_admin)])
async def add_blacklist(req: BlacklistCreateRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database missing")

    b_type = req.type.lower().strip()
    val = req.value.strip()
    if b_type not in ["hwid", "ip"]:
        raise HTTPException(status_code=400, detail="黑名單類型必須為 'hwid' 或 'ip'")
    if not val:
        raise HTTPException(status_code=400, detail="封禁數值不可為空")

    target_app_id = req.app_id.strip() if req.app_id and str(req.app_id).strip() not in ["", "null", "undefined", "None"] else None

    data = {
        "app_id": target_app_id,
        "type": b_type,
        "value": val,
        "reason": req.reason or "管理者手動封禁"
    }

    try:
        res = supabase.table("blacklists").insert(data).execute()
    except Exception as e:
        print(f"[Blacklist Insert Error] {e}")
        raise HTTPException(status_code=500, detail=f"寫入 Supabase 失敗：請確認在 Supabase SQL Editor 中已執行 SQL 建立 blacklists 資料表！錯誤詳情：{e}")

    # 即時踢掉所有符合此黑名單的線上用戶
    kicked_count = 0
    for license_key, entry in list(active_connections.items()):
        if target_app_id and entry.get("app_id") != target_app_id:
            continue
        user_hwid = (entry.get("hwid") or "").lower()
        user_ip = entry.get("ip") or ""
        if (b_type == "hwid" and user_hwid == val.lower()) or (b_type == "ip" and user_ip == val):
            await push_status_to_key(license_key, "blacklisted", f"已被系統封禁: {req.reason}")
            kicked_count += 1

    return {"ok": True, "data": res.data[0] if res.data else {}, "kicked_count": kicked_count}

@app.delete("/api/admin/blacklists/{blacklist_id}", dependencies=[Depends(require_admin)])
def delete_blacklist(blacklist_id: int):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database missing")
    try:
        supabase.table("blacklists").delete().eq("id", blacklist_id).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"刪除失敗：{e}")
    return {"ok": True}

# ------------------------------------------------------------------
# Client / Internal DLL 檔案與下載 API
# ------------------------------------------------------------------
BUCKET_NAME = "client-files"

def ensure_bucket_exists():
    if not supabase:
        return
    try:
        buckets = supabase.storage.list_buckets()
        exists = any(b.name == BUCKET_NAME for b in buckets)
        if not exists:
            supabase.storage.create_bucket(BUCKET_NAME, options={"public": True})
    except Exception:
        pass

@app.post("/api/admin/apps/{app_id}/upload-client", dependencies=[Depends(require_admin)])
async def upload_client_file(
    app_id: str,
    file: UploadFile = File(...),
    version: Optional[str] = Form(None),
    changelog: Optional[str] = Form(None)
):
    get_application_or_404(app_id)
    settings = get_app_settings(app_id)
    latest_version = version.strip() if version and version.strip() else settings["latest_version"]
    update_changelog = changelog.strip() if changelog is not None else settings.get("update_changelog", "")

    set_app_settings(app_id, settings["maintenance_mode"], settings["maintenance_message"], latest_version, update_changelog, settings.get("dynamic_payload", ""))

    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")
    file_size = 0
    with open(local_path, "wb") as f:
        while chunk := await file.read(65536):
            f.write(chunk)
            file_size += len(chunk)

    ensure_bucket_exists()
    try:
        with open(local_path, "rb") as f:
            supabase.storage.from_(BUCKET_NAME).upload(
                path=f"{app_id}/Client.dll",
                file=f,
                file_options={"upsert": "true", "content-type": "application/octet-stream"}
            )
    except Exception as e:
        print(f"[Storage Upload Warning] {e}")

    return {
        "ok": True,
        "filename": file.filename or "Client.dll",
        "size": file_size,
        "version": latest_version,
        "changelog": update_changelog
    }

@app.delete("/api/admin/apps/{app_id}/delete-client", dependencies=[Depends(require_admin)])
async def delete_client_file(app_id: str):
    get_application_or_404(app_id)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")
    if os.path.exists(local_path):
        try:
            os.remove(local_path)
        except Exception:
            pass

    try:
        supabase.storage.from_(BUCKET_NAME).remove([f"{app_id}/Client.dll"])
    except Exception:
        pass

    return {"ok": True, "message": "已刪除 Client.dll 檔案"}

@app.get("/api/admin/apps/{app_id}/client-info", dependencies=[Depends(require_admin)])
def get_client_file_info(app_id: str):
    get_application_or_404(app_id)
    settings = get_app_settings(app_id)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")
    size = os.path.getsize(local_path) if os.path.exists(local_path) else 0

    return {
        "has_file": size > 0,
        "filename": "Client.dll" if size > 0 else None,
        "size": size,
        "version": settings["latest_version"],
        "changelog": settings.get("update_changelog", ""),
        "dynamic_payload": settings.get("dynamic_payload", "")
    }

@app.get("/api/client/info")
def get_client_public_info(app_secret: str = Query(...)):
    application = resolve_app(app_secret)
    app_id = application["id"]
    settings = get_app_settings(app_id)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")
    size = os.path.getsize(local_path) if os.path.exists(local_path) else 0

    return {
        "status": "ok" if size > 0 else "no_file",
        "version": settings["latest_version"],
        "size": size,
        "changelog": settings.get("update_changelog", "")
    }

@app.get("/api/client/download")
def download_client_file(app_secret: str = Query(...)):
    application = resolve_app(app_secret)
    app_id = application["id"]
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")
    if os.path.exists(local_path):
        return FileResponse(local_path, filename="Client.dll", media_type="application/octet-stream")

    try:
        data = supabase.storage.from_(BUCKET_NAME).download(f"{app_id}/Client.dll")
        if data:
            return Response(content=data, media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="Client.dll"'})
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Client file not uploaded yet")

# ------------------------------------------------------------------
# Internal.dll 相關 APIs
# ------------------------------------------------------------------
DEFAULT_INTERNAL_SETTINGS = {
    "latest_version": "v1.0.0",
    "update_changelog": "",
    "stopped": False,
    "stop_message": "YangEnx Internal 停服維護中",
}

def get_internal_settings(app_id: str) -> dict:
    settings = dict(DEFAULT_INTERNAL_SETTINGS)
    json_file = os.path.join(UPLOADS_DIR, f"{app_id}_internal_settings.json")
    if os.path.exists(json_file):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                settings["latest_version"] = data.get("latest_version") or DEFAULT_INTERNAL_SETTINGS["latest_version"]
                settings["update_changelog"] = data.get("update_changelog", "")
                settings["stopped"] = bool(data.get("stopped", False))
                settings["stop_message"] = data.get("stop_message") or DEFAULT_INTERNAL_SETTINGS["stop_message"]
        except Exception:
            pass
    return settings

def set_internal_settings(app_id: str, latest_version: str, update_changelog: str = "", stopped: Optional[bool] = None, stop_message: Optional[str] = None):
    current = get_internal_settings(app_id)
    new_stopped = current["stopped"] if stopped is None else bool(stopped)
    new_stop_message = current["stop_message"] if stop_message is None else stop_message.strip()

    json_file = os.path.join(UPLOADS_DIR, f"{app_id}_internal_settings.json")
    try:
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "latest_version": latest_version,
                "update_changelog": update_changelog,
                "stopped": new_stopped,
                "stop_message": new_stop_message or DEFAULT_INTERNAL_SETTINGS["stop_message"],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

@app.post("/api/admin/apps/{app_id}/upload-internal", dependencies=[Depends(require_admin)])
async def upload_internal_file(
    app_id: str,
    file: UploadFile = File(...),
    version: Optional[str] = Form(None),
    changelog: Optional[str] = Form(None)
):
    get_application_or_404(app_id)
    settings = get_internal_settings(app_id)
    latest_version = version.strip() if version and version.strip() else settings["latest_version"]
    update_changelog = changelog.strip() if changelog is not None else settings.get("update_changelog", "")

    set_internal_settings(app_id, latest_version, update_changelog)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    file_size = 0
    with open(local_path, "wb") as f:
        while chunk := await file.read(65536):
            f.write(chunk)
            file_size += len(chunk)

    ensure_bucket_exists()
    try:
        with open(local_path, "rb") as f:
            supabase.storage.from_(BUCKET_NAME).upload(
                path=f"{app_id}/YangEnx Internal.dll",
                file=f,
                file_options={"upsert": "true", "content-type": "application/octet-stream"}
            )
    except Exception as e:
        print(f"[Storage Upload Warning] {e}")

    return {
        "ok": True,
        "filename": file.filename or "YangEnx Internal.dll",
        "size": file_size,
        "version": latest_version,
        "changelog": update_changelog
    }

@app.put("/api/admin/apps/{app_id}/internal-settings", dependencies=[Depends(require_admin)])
def update_internal_settings_api(app_id: str, req: SaveInternalSettingsRequest):
    get_application_or_404(app_id)
    set_internal_settings(
        app_id,
        latest_version=req.latest_version,
        update_changelog=req.update_changelog,
        stopped=req.stopped,
        stop_message=req.stop_message
    )
    return {"ok": True}

@app.delete("/api/admin/apps/{app_id}/delete-internal", dependencies=[Depends(require_admin)])
async def delete_internal_file(app_id: str):
    get_application_or_404(app_id)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    if os.path.exists(local_path):
        try:
            os.remove(local_path)
        except Exception:
            pass

    try:
        supabase.storage.from_(BUCKET_NAME).remove([f"{app_id}/YangEnx Internal.dll"])
    except Exception:
        pass

    set_internal_settings(app_id, "v1.0.0", "", False, "YangEnx Internal 停服維護中")
    return {"ok": True, "message": "已成功刪除 Internal.dll 檔案"}

@app.get("/api/admin/apps/{app_id}/internal-info", dependencies=[Depends(require_admin)])
def get_internal_file_info(app_id: str):
    get_application_or_404(app_id)
    settings = get_internal_settings(app_id)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    size = os.path.getsize(local_path) if os.path.exists(local_path) else 0

    return {
        "has_file": size > 0,
        "filename": "YangEnx Internal.dll" if size > 0 else None,
        "size": size,
        "version": settings["latest_version"],
        "changelog": settings.get("update_changelog", ""),
        "stopped": settings.get("stopped", False),
        "stop_message": settings.get("stop_message", "YangEnx Internal 停服維護中")
    }

@app.get("/api/internal/info")
def get_internal_public_info(app_secret: str = Query(...)):
    application = resolve_app(app_secret)
    app_id = application["id"]
    settings = get_internal_settings(app_id)

    if settings.get("stopped", False):
        return {
            "status": "stopped",
            "message": settings.get("stop_message") or "YangEnx Internal 停服維護中",
            "version": settings["latest_version"],
            "size": 0,
            "changelog": settings.get("update_changelog", "")
        }

    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    size = os.path.getsize(local_path) if os.path.exists(local_path) else 0

    return {
        "status": "ok" if size > 0 else "no_file",
        "version": settings["latest_version"],
        "size": size,
        "changelog": settings.get("update_changelog", "")
    }

@app.get("/api/internal/download")
def download_internal_file(app_secret: str = Query(...)):
    application = resolve_app(app_secret)
    app_id = application["id"]
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    if os.path.exists(local_path):
        return FileResponse(local_path, filename="YangEnx Internal.dll", media_type="application/octet-stream")

    try:
        data = supabase.storage.from_(BUCKET_NAME).download(f"{app_id}/YangEnx Internal.dll")
        if data:
            return Response(content=data, media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="YangEnx Internal.dll"'})
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="YangEnx Internal.dll file not uploaded yet")
