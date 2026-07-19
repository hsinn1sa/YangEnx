import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict

from fastapi import FastAPI, HTTPException, Header, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from supabase import create_client, Client

# ------------------------------------------------------------------
# 環境設定
# ------------------------------------------------------------------
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]
APP_SECRET = os.environ["APP_SECRET"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="License System")

@app.get("/", include_in_schema=False)
@app.head("/", include_in_schema=False)
async def root():
    return {"status": "ok", "message": "License System is running"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/admin")
def admin_panel():
    return FileResponse(os.path.join(os.path.dirname(__file__), "admin.html"))

# ------------------------------------------------------------------
# WebSocket 連線註冊表
# ------------------------------------------------------------------
active_connections: Dict[str, dict] = {}

async def push_status_to_key(license_key: str, status: str, message: str):
    entry = active_connections.get(license_key)
    if entry is None:
        return
    ws = entry["ws"]
    try:
        await ws.send_json({"status": status, "message": message})
        await ws.close()
    except Exception:
        pass
    active_connections.pop(license_key, None)

async def broadcast_to_all(status: str, message: str):
    for license_key in list(active_connections.keys()):
        await push_status_to_key(license_key, status, message)

# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------
class VerifyRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str

class HeartbeatRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str

class VerifyResponse(BaseModel):
    status: str
    message: str
    username: Optional[str] = None
    expires_at: Optional[str] = None
    latest_version: Optional[str] = None

class CreateKeyRequest(BaseModel):
    license_key: Optional[str] = None
    username: str
    max_devices: int = 1
    expires_at: str

class MaintenanceSettingsRequest(BaseModel):
    maintenance_mode: bool
    maintenance_message: str = "卡密網站維護中，請稍後再試。"

class VersionSettingsRequest(BaseModel):
    latest_version: str

# ------------------------------------------------------------------
# 工具函式
# ------------------------------------------------------------------
def log_event(actor: str, event: str, detail: str = "", hwid: str = ""):
    supabase.table("system_logs").insert({
        "actor": actor,
        "event": event,
        "detail": detail,
        "hwid": hwid,
    }).execute()

def get_setting(key: str) -> Optional[str]:
    res = supabase.table("system_settings").select("value").eq("key", key).execute()
    if res.data:
        return res.data[0]["value"]
    return None

def set_setting(key: str, value: str):
    supabase.table("system_settings").upsert({
        "key": key,
        "value": value,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

def require_admin(x_admin_token: str = Header(...)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

def check_app_secret(provided: str):
    if provided != APP_SECRET:
        raise HTTPException(status_code=403, detail="Invalid app secret")

def check_key_status(row: dict, hwid: str) -> tuple[str, str]:
    if row["status"] != "active":
        return "disabled", "此卡密已被停用"
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        return "expired", "此卡密已過期"
    if row["hwid"] and row["hwid"] != hwid:
        return "hwid_mismatch", "此卡密已綁定其他裝置"
    return "ok", "驗證成功"

def is_maintenance_mode() -> bool:
    return get_setting("maintenance_mode") == "true"

# ------------------------------------------------------------------
# 卡密驗證
# ------------------------------------------------------------------
@app.post("/api/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    check_app_secret(req.app_secret)
    if is_maintenance_mode():
        msg = get_setting("maintenance_message") or "系統維護中"
        return VerifyResponse(status="maintenance", message=msg)

    res = supabase.table("license_keys").select("*").eq("license_key", req.license_key).execute()
    if not res.data:
        log_event("UNKNOWN_KEY", "LOGIN_FAILED", f"嘗試帳密不存在: [{req.license_key}]", req.hwid)
        return VerifyResponse(status="invalid", message="卡密不存在")

    row = res.data[0]
    status, message = check_key_status(row, req.hwid)

    if status != "ok":
        log_event(row["username"], "LOGIN_FAILED", message, req.hwid)
        return VerifyResponse(status=status, message=message)

    if not row["hwid"]:
        supabase.table("license_keys").update({
            "hwid": req.hwid,
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", row["id"]).execute()
    else:
        supabase.table("license_keys").update({
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", row["id"]).execute()

    log_event(row["username"], "VERIFY_SUCCESS", "使用者認證成功進入主程式", req.hwid)
    return VerifyResponse(
        status="ok",
        message="驗證成功",
        username=row["username"],
        expires_at=row["expires_at"],
        latest_version=get_setting("latest_version") or "1.0.0"
    )

# ------------------------------------------------------------------
# WebSocket
# ------------------------------------------------------------------
@app.websocket("/ws/license")
async def ws_license(
    websocket: WebSocket,
    license_key: str = Query(...),
    hwid: str = Query(...),
    app_secret: str = Query(...),
):
    if app_secret != APP_SECRET:
        await websocket.close(code=4003)
        return
    await websocket.accept()
    if is_maintenance_mode():
        msg = get_setting("maintenance_message") or "系統維護中"
        await websocket.send_json({"status": "maintenance", "message": msg})
        await websocket.close()
        return
    res = supabase.table("license_keys").select("*").eq("license_key", license_key).execute()
    if not res.data:
        await websocket.send_json({"status": "invalid", "message": "卡密不存在或已被刪除"})
        await websocket.close()
        return
    row = res.data[0]
    status, message = check_key_status(row, hwid)
    if status != "ok":
        await websocket.send_json({"status": status, "message": message})
        await websocket.close()
        return
    active_connections[license_key] = {
        "ws": websocket,
        "username": row["username"],
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }
    await websocket.send_json({"status": "ok", "message": "已建立即時連線"})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        entry = active_connections.get(license_key)
        if entry is not None and entry["ws"] is websocket:
            active_connections.pop(license_key, None)

# ------------------------------------------------------------------
# 心跳與其他管理 API
# ------------------------------------------------------------------
@app.post("/api/heartbeat", response_model=VerifyResponse)
def heartbeat(req: HeartbeatRequest):
    check_app_secret(req.app_secret)
    if is_maintenance_mode():
        msg = get_setting("maintenance_message") or "系統維護中"
        return VerifyResponse(status="maintenance", message=msg)
    res = supabase.table("license_keys").select("*").eq("license_key", req.license_key).execute()
    if not res.data:
        return VerifyResponse(status="invalid", message="卡密不存在或已被刪除")
    row = res.data[0]
    status, message = check_key_status(row, req.hwid)
    if status == "ok":
        supabase.table("license_keys").update({"last_seen_at": datetime.now(timezone.utc).isoformat()}).eq("id", row["id"]).execute()
    return VerifyResponse(status=status, message=message, username=row["username"])

@app.post("/api/admin/keys", dependencies=[Depends(require_admin)])
def create_key(req: CreateKeyRequest):
    key = req.license_key or "-".join(str(uuid.uuid4()).upper().split("-")[:3])
    data = {"license_key": key, "username": req.username, "max_devices": req.max_devices, "expires_at": req.expires_at, "status": "active"}
    res = supabase.table("license_keys").insert(data).execute()
    return res.data[0]

@app.get("/api/admin/keys", dependencies=[Depends(require_admin)])
def list_keys():
    res = supabase.table("license_keys").select("*").order("id", desc=True).execute()
    return res.data

@app.patch("/api/admin/keys/{key_id}/disable", dependencies=[Depends(require_admin)])
async def disable_key(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    supabase.table("license_keys").update({"status": "disabled"}).eq("id", key_id).execute()
    if res.data: await push_status_to_key(res.data[0]["license_key"], "disabled", "此卡密被停用")
    return {"ok": True}

@app.patch("/api/admin/keys/{key_id}/enable", dependencies=[Depends(require_admin)])
def enable_key(key_id: int):
    supabase.table("license_keys").update({"status": "active"}).eq("id", key_id).execute()
    return {"ok": True}

@app.patch("/api/admin/keys/{key_id}/reset-hwid", dependencies=[Depends(require_admin)])
async def reset_hwid(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    supabase.table("license_keys").update({"hwid": None}).eq("id", key_id).execute()
    if res.data: await push_status_to_key(res.data[0]["license_key"], "hwid_mismatch", "裝置綁定已被重設，請重新登入")
    return {"ok": True}

@app.delete("/api/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def delete_key(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    if res.data: await push_status_to_key(res.data[0]["license_key"], "invalid", "此卡密已被刪除")
    supabase.table("license_keys").delete().eq("id", key_id).execute()
    return {"ok": True}

@app.get("/api/admin/online", dependencies=[Depends(require_admin)])
def get_online():
    return [{"license_key": k, "username": e["username"], "connected_at": e["connected_at"]} for k, e in active_connections.items()]

@app.get("/api/admin/settings", dependencies=[Depends(require_admin)])
def get_settings():
    return {"maintenance_mode": is_maintenance_mode(), "maintenance_message": get_setting("maintenance_message") or "卡密網站維護中，請稍後再試。"}

@app.put("/api/admin/settings", dependencies=[Depends(require_admin)])
async def update_settings(req: MaintenanceSettingsRequest):
    was_on = is_maintenance_mode()
    set_setting("maintenance_mode", "true" if req.maintenance_mode else "false")
    set_setting("maintenance_message", req.maintenance_message)
    if req.maintenance_mode and not was_on:
        await broadcast_to_all("maintenance", req.maintenance_message)
    return {"ok": True}

@app.get("/api/admin/version", dependencies=[Depends(require_admin)])
def get_version():
    return {"latest_version": get_setting("latest_version") or "1.0.0"}

@app.put("/api/admin/version", dependencies=[Depends(require_admin)])
def update_version(req: VersionSettingsRequest):
    set_setting("latest_version", req.latest_version)
    return {"ok": True, "new_version": req.latest_version}