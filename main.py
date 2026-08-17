"""
授權系統後端 (FastAPI + Supabase)

端點總覽：
  POST /api/verify              -> C# 軟體開機時呼叫，首次使用會綁定 HWID
  WS   /ws/license               -> C# 軟體開機驗證成功後改連這條，伺服器有狀態變化才會推播，不用一直輪詢
  POST /api/heartbeat            -> (備用/相容) 舊版輪詢方式，新專案建議直接用 WebSocket

  管理員 - 應用程式 (多應用程式支援，類似 KeyAuth 的 App)：
  POST   /api/admin/apps                    -> 建立新應用程式 (回傳 owner_id / app_secret)
  GET    /api/admin/apps                    -> 查詢所有應用程式列表
  DELETE /api/admin/apps/{app_id}           -> 刪除應用程式 (連同底下所有卡密一起刪除)
  PATCH  /api/admin/apps/{app_id}/rotate-secret -> 重新產生該應用程式的 App Secret (舊的立刻失效)

  管理員 - 卡密 (每把卡密都歸屬於某個應用程式)：
  POST /api/admin/keys           -> 管理員新增卡密 (需帶 admin token，body 需帶 app_id)
  GET  /api/admin/keys           -> 管理員查詢卡密列表 (可用 ?app_id= 篩選特定應用程式)
  GET  /api/admin/online         -> 管理員查詢目前哪些卡密正在線上 (有 WebSocket 連線)
  GET  /api/admin/settings       -> 管理員查詢某應用程式的維護模式設定 (需帶 ?app_id=)
  PUT  /api/admin/settings       -> 管理員切換某應用程式的維護模式，開啟時只會踢掉該應用程式的線上使用者
"""

import os
import secrets
import string
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
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]  # 用 service_role key，後端專用
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]  # 你自己的後台呼叫這組 API 用的密鑰

# 注意：原本寫死在環境變數裡的單一 APP_SECRET 已經被移除。
# 現在每個「應用程式」都有自己獨立的 app_secret，存在 Supabase 的 applications 表裡，
# 由 /api/admin/apps 建立，C# 端改成呼叫 /api/verify 時帶自己那組 app_secret 即可。
# 部署時記得把舊的 APP_SECRET 環境變數移除 (程式不再讀取它)。

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
# key = license_key, value = {"ws": WebSocket, "username": str, "connected_at": iso字串}
# 注意：這是存在記憶體裡的，只適用「單一伺服器實例」(Render 免費方案本來就是單一實例，沒問題)
# ------------------------------------------------------------------
active_connections: Dict[str, dict] = {}


async def push_status_to_key(license_key: str, status: str, message: str):
    """如果這把卡密目前有連線在線上，推播一則狀態訊息給它，然後關閉連線。"""
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
    """推播給目前所有在線連線 (跨所有應用程式)。"""
    for license_key in list(active_connections.keys()):
        await push_status_to_key(license_key, status, message)


async def broadcast_to_app(app_id: str, status: str, message: str):
    """只推播給屬於某個應用程式、目前在線的連線 (用於該應用程式的維護模式開啟時)。"""
    for license_key, entry in list(active_connections.items()):
        if entry.get("app_id") == app_id:
            await push_status_to_key(license_key, status, message)


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------
class VerifyRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str
    version: str


class HeartbeatRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str


class VerifyResponse(BaseModel):
    status: str          # ok / invalid / expired / disabled / hwid_mismatch / maintenance / version_mismatch
    message: str
    username: Optional[str] = None
    expires_at: Optional[str] = None


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


DEFAULT_APP_SETTINGS = {
    "maintenance_mode": False,
    "maintenance_message": "卡密系統維護中",
    "latest_version": "v1.0.0",
}


def get_app_settings(app_id: str) -> dict:
    """取得某個應用程式自己的維護模式 / 版本設定，若尚未設定過就回傳預設值。"""
    res = supabase.table("app_settings").select("*").eq("app_id", app_id).execute()
    if res.data:
        row = res.data[0]
        return {
            "maintenance_mode": bool(row["maintenance_mode"]),
            "maintenance_message": row["maintenance_message"] or DEFAULT_APP_SETTINGS["maintenance_message"],
            "latest_version": row["latest_version"] or DEFAULT_APP_SETTINGS["latest_version"],
        }
    return dict(DEFAULT_APP_SETTINGS)


def set_app_settings(app_id: str, maintenance_mode: bool, maintenance_message: str, latest_version: str):
    """app_settings 用 upsert：這個應用程式存在就更新，不存在就新增一列。"""
    supabase.table("app_settings").upsert({
        "app_id": app_id,
        "maintenance_mode": maintenance_mode,
        "maintenance_message": maintenance_message,
        "latest_version": latest_version,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).execute()


def require_admin(x_admin_token: str = Header(...)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _random_token(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_owner_id() -> str:
    """類似 KeyAuth 的 Account Owner ID：10 碼英數混合，僅用於識別，不是密鑰。"""
    alphabet = string.ascii_letters + string.digits
    return _random_token(10, alphabet)


def generate_app_secret() -> str:
    """應用程式密鑰，寫死在客戶端程式裡用來擋非法呼叫，長度比照 KeyAuth 慣例。"""
    return secrets.token_hex(20)  # 40 字元 hex


def resolve_app(app_secret: str) -> dict:
    """依 app_secret 找出對應的應用程式，找不到就視為非法呼叫直接擋掉。"""
    res = supabase.table("license_applications").select("*").eq("app_secret", app_secret).execute()
    if not res.data:
        raise HTTPException(status_code=403, detail="Invalid app secret")
    return res.data[0]


def get_application_or_404(app_id: str) -> dict:
    res = supabase.table("license_applications").select("*").eq("id", app_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Application not found")
    return res.data[0]


def check_key_status(row: dict, hwid: str) -> tuple[str, str]:
    """回傳 (status, message)，共用在 verify / heartbeat / websocket"""
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
# app_secret 決定了這次驗證屬於「哪一個應用程式」，卡密查詢會限定在同一個應用程式底下，
# 不同應用程式即使卡密字串剛好一樣也不會互通。
# ------------------------------------------------------------------
@app.post("/api/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    application = resolve_app(req.app_secret)
    settings = get_app_settings(application["id"])

    if req.version != settings["latest_version"]:
        return VerifyResponse(status="version_mismatch", message=f"偵測到新版本，請前往更新至 {settings['latest_version']}。")

    if settings["maintenance_mode"]:
        return VerifyResponse(status="maintenance", message=settings["maintenance_message"])

    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", req.license_key)
        .eq("app_id", application["id"])
        .execute()
    )
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
# 過期/HWID被重設/維護模式開啟時才會主動推播一則訊息，平常完全不用你的軟體主動發請求
# ------------------------------------------------------------------
@app.websocket("/ws/license")
async def ws_license(
    websocket: WebSocket,
    license_key: str = Query(...),
    hwid: str = Query(...),
    app_secret: str = Query(...),
):
    res_app = supabase.table("license_applications").select("*").eq("app_secret", app_secret).execute()
    if not res_app.data:
        await websocket.close(code=4003)
        return
    application = res_app.data[0]

    await websocket.accept()

    settings = get_app_settings(application["id"])
    if settings["maintenance_mode"]:
        await websocket.send_json({"status": "maintenance", "message": settings["maintenance_message"]})
        await websocket.close()
        return

    # 先做一次驗證，不合格就直接告知並斷線
    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", license_key)
        .eq("app_id", application["id"])
        .execute()
    )
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

    # 驗證通過，註冊連線 (含所屬應用程式、上線時間、使用者名稱，後台可以查詢誰在線)
    active_connections[license_key] = {
        "ws": websocket,
        "app_id": application["id"],
        "username": row["username"],
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }
    await websocket.send_json({"status": "ok", "message": "已建立即時連線"})

    try:
        # 保持連線開著，等待管理員那邊主動推播，或偵測到斷線
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        # 只有目前註冊的連線就是自己時才移除，避免競態情況下誤刪新連線
        entry = active_connections.get(license_key)
        if entry is not None and entry["ws"] is websocket:
            active_connections.pop(license_key, None)


@app.post("/api/heartbeat", response_model=VerifyResponse)
def heartbeat(req: HeartbeatRequest):
    application = resolve_app(req.app_secret)
    settings = get_app_settings(application["id"])

    if settings["maintenance_mode"]:
        return VerifyResponse(status="maintenance", message=settings["maintenance_message"])

    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", req.license_key)
        .eq("app_id", application["id"])
        .execute()
    )
    if not res.data:
        return VerifyResponse(status="invalid", message="卡密不存在或已被刪除")

    row = res.data[0]
    status, message = check_key_status(row, req.hwid)

    if status == "ok":
        supabase.table("license_keys").update({
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", row["id"]).execute()

    return VerifyResponse(status=status, message=message, username=row["username"])


# ------------------------------------------------------------------
# 後台管理 API - 應用程式管理 (多應用程式支援)
# ------------------------------------------------------------------
@app.post("/api/admin/apps", dependencies=[Depends(require_admin)])
def create_application(req: CreateApplicationRequest):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="應用程式名稱不可為空")

    # owner_id / app_secret 都是隨機產生，重複機率極低，但保險起見重試幾次避免 unique 撞號
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

    # 找出這個應用程式底下所有卡密，先踢掉在線的使用者，再整批刪除
    keys_res = supabase.table("license_keys").select("license_key").eq("app_id", app_id).execute()
    for row in keys_res.data:
        await push_status_to_key(row["license_key"], "invalid", "此應用程式已被管理員刪除")

    supabase.table("license_keys").delete().eq("app_id", app_id).execute()
    supabase.table("license_applications").delete().eq("id", app_id).execute()
    return {"ok": True}


@app.patch("/api/admin/apps/{app_id}/rotate-secret", dependencies=[Depends(require_admin)])
async def rotate_app_secret(app_id: str):
    """重新產生 App Secret，舊的立刻失效 (例如懷疑外流時使用)。"""
    get_application_or_404(app_id)

    new_secret = generate_app_secret()
    res = supabase.table("license_applications").update({"app_secret": new_secret}).eq("id", app_id).execute()

    # 保險起見把這個應用程式底下所有在線連線踢掉，強制用新版重新驗證。
    keys_res = supabase.table("license_keys").select("license_key").eq("app_id", app_id).execute()
    for row in keys_res.data:
        await push_status_to_key(row["license_key"], "invalid", "應用程式金鑰已重設，請聯繫管理員取得最新版本")

    return res.data[0]


# ------------------------------------------------------------------
# 後台管理 API - 卡密管理 (每把卡密都歸屬於某個應用程式)
# ------------------------------------------------------------------
@app.post("/api/admin/keys", dependencies=[Depends(require_admin)])
def create_key(req: CreateKeyRequest):
    get_application_or_404(req.app_id)  # 確保 app_id 有效，錯誤訊息更明確

    key = req.license_key or "-".join(
        str(uuid.uuid4()).upper().split("-")[:3]
    )
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
    # 帶入應用程式名稱一起回傳，後台列表才能顯示「所屬應用程式」欄位
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
        await push_status_to_key(res.data[0]["license_key"], "disabled", "此卡密被停用")
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
        await push_status_to_key(res.data[0]["license_key"], "hwid_mismatch", "裝置綁定已被重設，請重新登入")
    return {"ok": True}


@app.delete("/api/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def delete_key(key_id: int):
    res = supabase.table("license_keys").select("license_key").eq("id", key_id).execute()
    if res.data:
        await push_status_to_key(res.data[0]["license_key"], "invalid", "此卡密已被刪除")
    supabase.table("license_keys").delete().eq("id", key_id).execute()
    return {"ok": True}


# ------------------------------------------------------------------
# 在線狀態查詢：回傳目前有 WebSocket 連線的卡密清單
# ------------------------------------------------------------------
@app.get("/api/admin/online", dependencies=[Depends(require_admin)])
def get_online():
    return [
        {
            "license_key": license_key,
            "app_id": entry.get("app_id"),
            "username": entry["username"],
            "connected_at": entry["connected_at"],
        }
        for license_key, entry in active_connections.items()
    ]


# ------------------------------------------------------------------
# 維護模式 / 版本號：每個應用程式各自獨立設定，互不影響
# 開啟時只會踢掉「這個應用程式底下」目前在線的使用者 (透過 WebSocket 主動推播)
# ------------------------------------------------------------------
@app.get("/api/admin/settings", dependencies=[Depends(require_admin)])
def get_settings(app_id: str = Query(...)):
    get_application_or_404(app_id)
    return get_app_settings(app_id)


@app.put("/api/admin/settings", dependencies=[Depends(require_admin)])
async def update_settings(req: MaintenanceSettingsRequest):
    get_application_or_404(req.app_id)
    was_on = get_app_settings(req.app_id)["maintenance_mode"]

    set_app_settings(req.app_id, req.maintenance_mode, req.maintenance_message, req.latest_version)

    # 從關閉切換成開啟時，立刻踢掉這個應用程式底下所有在線使用者，不用等他們下次連線才發現
    if req.maintenance_mode and not was_on:
        await broadcast_to_app(req.app_id, "maintenance", req.maintenance_message)

    return {"ok": True}