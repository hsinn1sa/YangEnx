import os
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict

from fastapi import FastAPI, HTTPException, Header, Depends, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel
from supabase import create_client, Client

# ------------------------------------------------------------------
# 環境設定
# ------------------------------------------------------------------
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]  # 用 service_role key，後端專用
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]  # 你自己的後台呼叫這組 API 用的密鑰
APP_SECRET = os.environ["APP_SECRET"]  # 寫死在你 C# 軟體裡的那組密鑰，用來擋非法呼叫

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="License System")

# ------------------------------------------------------------------
# WebSocket 連線註冊表
# key = license_key, value = 目前連著的 WebSocket 連線
# 注意：這是存在記憶體裡的，只適用「單一伺服器實例」(Render 免費方案本來就是單一實例，沒問題)
# ------------------------------------------------------------------
active_connections: Dict[str, WebSocket] = {}


async def push_status_to_key(license_key: str, status: str, message: str):
    """如果這把卡密目前有連線在線上，推播一則狀態訊息給它，然後關閉連線。"""
    ws = active_connections.get(license_key)
    if ws is None:
        return
    try:
        await ws.send_json({"status": status, "message": message})
        await ws.close()
    except Exception:
        pass
    active_connections.pop(license_key, None)


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
    status: str          # ok / invalid / expired / disabled / hwid_mismatch / maintenance
    message: str
    username: Optional[str] = None
    expires_at: Optional[str] = None


class CreateKeyRequest(BaseModel):
    license_key: Optional[str] = None
    username: str
    max_devices: int = 1
    expires_at: str  # ISO datetime string


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


def require_admin(x_admin_token: str = Header(...)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


def check_app_secret(provided: str):
    if provided != APP_SECRET:
        raise HTTPException(status_code=403, detail="Invalid app secret")


def check_key_status(row: dict, hwid: str) -> tuple[str, str]:
    """回傳 (status, message)，共用在 verify / heartbeat"""
    if row["status"] != "active":
        return "disabled", "此卡密已被停用"

    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        return "expired", "此卡密已過期"

    if row["hwid"] and row["hwid"] != hwid:
        return "hwid_mismatch", "此卡密已綁定其他裝置"

    return "ok", "驗證成功"


# ------------------------------------------------------------------
# 卡密驗證：軟體開機呼叫，第一次會自動綁定 HWID
# ------------------------------------------------------------------
@app.post("/api/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    check_app_secret(req.app_secret)

    # 維護模式檢查
    if get_setting("maintenance_mode") == "true":
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

    # 第一次使用，綁定 HWID
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
    )


# ------------------------------------------------------------------
# WebSocket：軟體開機驗證成功後改連這條，伺服器只有在卡密被停用/刪除/
# 過期/HWID被重設時才會主動推播一則訊息，平常完全不用你的軟體主動發請求
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

    # 先做一次驗證，不合格就直接告知並斷線
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

    # 驗證通過，註冊連線，之後管理員的操作會透過 push_status_to_key 主動推播
    active_connections[license_key] = websocket
    await websocket.send_json({"status": "ok", "message": "已建立即時連線"})

    try:
        # 保持連線開著，等待管理員那邊主動推播，或偵測到斷線
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        # 只有目前註冊的連線就是自己時才移除，避免競態情況下誤刪新連線
        if active_connections.get(license_key) is websocket:
            active_connections.pop(license_key, None)



@app.post("/api/heartbeat", response_model=VerifyResponse)
def heartbeat(req: HeartbeatRequest):
    check_app_secret(req.app_secret)

    if get_setting("maintenance_mode") == "true":
        msg = get_setting("maintenance_message") or "系統維護中"
        return VerifyResponse(status="maintenance", message=msg)

    res = supabase.table("license_keys").select("*").eq("license_key", req.license_key).execute()
    if not res.data:
        # 卡密已被管理員刪除
        return VerifyResponse(status="invalid", message="卡密不存在或已被刪除")

    row = res.data[0]
    status, message = check_key_status(row, req.hwid)

    if status == "ok":
        supabase.table("license_keys").update({
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", row["id"]).execute()

    return VerifyResponse(status=status, message=message, username=row["username"])


# ------------------------------------------------------------------
# 後台管理 API (給你自己的 admin 面板用，非 C# 軟體呼叫)
# ------------------------------------------------------------------
@app.post("/api/admin/keys", dependencies=[Depends(require_admin)])
def create_key(req: CreateKeyRequest):
    key = req.license_key or "-".join(
        str(uuid.uuid4()).upper().split("-")[:3]
    )
    data = {
        "license_key": key,
        "username": req.username,
        "max_devices": req.max_devices,
        "expires_at": req.expires_at,
        "status": "active",
    }
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
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "disabled", "此卡密已被管理員停用")
    return {"ok": True}


@app.patch("/api/admin/keys/{key_id}/enable", dependencies=[Depends(require_admin)])
def enable_key(key_id: int):
    supabase.table("license_keys").update({"status": "active"}).eq("id", key_id).execute()
    return {"ok": True}


@app.patch("/api/admin/keys/{key_id}/reset-hwid", dependencies=[Depends(require_admin)])
async def reset_hwid(key_id: int):
    """管理員重設 HWID，讓卡密可以在新裝置上重新綁定"""
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    supabase.table("license_keys").update({"hwid": None}).eq("id", key_id).execute()
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "hwid_mismatch", "裝置綁定已被管理員重設，請重新登入")
    return {"ok": True}


@app.delete("/api/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def delete_key(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "invalid", "此卡密已被管理員刪除")
    supabase.table("license_keys").delete().eq("id", key_id).execute()
    return {"ok": True}