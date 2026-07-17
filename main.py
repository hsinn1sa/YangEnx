"""
授權系統後端 (FastAPI + Supabase)

端點總覽：
  POST /api/verify     -> C# 軟體開機時呼叫，首次使用會綁定 HWID
  POST /api/heartbeat   -> C# 軟體執行期間每 5 秒呼叫一次，確認卡密仍然有效
  POST /api/admin/keys  -> 管理員新增卡密 (需帶 admin token)
  GET  /api/admin/keys  -> 管理員查詢卡密列表
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
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
# 心跳：軟體執行期間每 5 秒呼叫一次
# 只要卡密被刪除 / 停用 / 過期 / HWID 不符，回傳非 ok，C# 端就要立刻關閉面板
# ------------------------------------------------------------------
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
def disable_key(key_id: int):
    supabase.table("license_keys").update({"status": "disabled"}).eq("id", key_id).execute()
    return {"ok": True}


@app.patch("/api/admin/keys/{key_id}/enable", dependencies=[Depends(require_admin)])
def enable_key(key_id: int):
    supabase.table("license_keys").update({"status": "active"}).eq("id", key_id).execute()
    return {"ok": True}


@app.patch("/api/admin/keys/{key_id}/reset-hwid", dependencies=[Depends(require_admin)])
def reset_hwid(key_id: int):
    """管理員重設 HWID，讓卡密可以在新裝置上重新綁定"""
    supabase.table("license_keys").update({"hwid": None}).eq("id", key_id).execute()
    return {"ok": True}


@app.delete("/api/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
def delete_key(key_id: int):
    supabase.table("license_keys").delete().eq("id", key_id).execute()
    return {"ok": True}