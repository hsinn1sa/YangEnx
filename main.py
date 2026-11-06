"""
授權系統後端 (FastAPI + Supabase + WebSockets)  ── v2 強化版
包含：
  - 核心驗證 (Verify / Heartbeat / WebSocket)
  - HWID / IP 黑名單系統 (Blacklist System)
  - 多裝置 HWID 動態綁定 (max_devices)
  - 伺服器時間校驗與 HMAC 簽名 + Nonce (防重放 / 反時鐘篡改)
  - 離線租約 Lease (Offline Grace) ── 解決 Render 免費版冷啟動/網路波動造成的誤登出
  - 動態記憶體 Key / 參數注入 (Dynamic Memory Injection)
  - 即時廣播公告彈窗推播 (Real-time Broadcast Popup)
  - API 速率限制 (Rate Limiting, thread-safe)
  - 後台管理安全強化 (常數時間比對 / 失敗鎖定 / 多組 Token 輪替)
  - 設定快取 (Settings/Blacklist Cache) 大幅降低 Supabase 往返延遲
  - 安全回應標頭 (Security Headers)

v2 相對 v1 的差異都標記為 [v2]，方便你用 diff 比對。
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from typing import Optional, Dict, List, Tuple

from fastapi import (
    FastAPI, HTTPException, Header, Depends, WebSocket,
    WebSocketDisconnect, Query, UploadFile, File, Form, Response, Request
)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, StreamingResponse
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

# [v2] 可同時放多組 Token（用逗號分隔）→ 換 Token 時可以零停機：先新增新 Token，之後再移除舊的。
ADMIN_TOKENS: List[str] = [t.strip() for t in ADMIN_TOKEN.split(",") if t.strip()]

# [v2] 離線租約秒數：客戶端在完全連不上伺服器時，仍可繼續使用到租約到期為止。
#      這才是「Render 免費版偶發斷線」的正解；預設 30 分鐘，可依商業模式調整（建議 15~60 分鐘）。
LEASE_TTL_SECONDS = int(os.environ.get("LEASE_TTL_SECONDS", "1800"))

# [v2] last_seen_at 最短寫入間隔（秒）。v1 每次心跳都 update，等於每 10 秒對 DB 寫一次。
LAST_SEEN_WRITE_INTERVAL = int(os.environ.get("LAST_SEEN_WRITE_INTERVAL", "60"))

# [v2] 快取秒數：把 app / app_settings / internal_settings / blacklist 放在記憶體內，
#      心跳只需要 1 次 license_keys 查詢（原本要 5~6 次），大幅降低延遲與 Supabase 用量。
APP_CACHE_TTL = float(os.environ.get("APP_CACHE_TTL", "60"))
SETTINGS_CACHE_TTL = float(os.environ.get("SETTINGS_CACHE_TTL", "20"))
BLACKLIST_CACHE_TTL = float(os.environ.get("BLACKLIST_CACHE_TTL", "20"))

# [v2] 正式環境預設關閉 /docs 與 /openapi.json（避免攻擊者直接看到完整 API 結構）。
ENABLE_DOCS = os.environ.get("ENABLE_DOCS", "0").strip().lower() in ("1", "true", "yes")

# [v2] 只有 1 個 worker 時，記憶體快取與 active_connections 才是一致的。
#      Render 免費方案就是 1 worker；若未來要開多 worker，請改用 Redis。
WORKER_HINT = os.environ.get("WEB_CONCURRENCY", "1")

# [v2] 是否信任 CF-Connecting-IP / X-Forwarded-For（Render 前面有 Cloudflare，正常要開）。
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "1").strip().lower() in ("1", "true", "yes")

# [v2] 下載 DLL 是否強制要求「有效卡密 + 已綁定 HWID」。
#      v1 只要知道 app_secret 就能下載（等於任何人都能拿走你的 DLL），強烈建議設 1。
REQUIRE_LICENSE_FOR_DOWNLOAD = os.environ.get("REQUIRE_LICENSE_FOR_DOWNLOAD", "0").strip().lower() in ("1", "true", "yes")

supabase: Optional[Client] = create_client(SUPABASE_URL, SUPABASE_KEY) if (SUPABASE_URL and SUPABASE_KEY) else None

app = FastAPI(
    title="YangEnx License System Pro",
    version="2.1.0",
    # [v2] 正式環境不公開 API 文件；本機開發可設 ENABLE_DOCS=1
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)


# ------------------------------------------------------------------
# [v2] 安全回應標頭 (Security Headers)
# ------------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"                 # 防 clickjacking（後台不能被 iframe）
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if request.url.path.startswith("/api/"):
        # API 回應一律不快取，避免中間層/瀏覽器拿到舊的授權結果
        response.headers["Cache-Control"] = "no-store"
    return response


@app.on_event("startup")
def _startup_warnings():
    # [v2] 設定缺漏時在日誌中直接警告，避免「以為有保護其實沒有」
    if not ADMIN_TOKENS:
        print("[SECURITY] ADMIN_TOKEN 未設定 → 後台 API 將全部回 401（這是安全的預設值）")
    if not supabase:
        print("[SECURITY] Supabase 未初始化 → 驗證功能無法使用")
    if WORKER_HINT not in ("", "1"):
        print(f"[WARN] WEB_CONCURRENCY={WORKER_HINT}：本版快取與 active_connections 為單程序記憶體，"
              f"多 worker 會導致踢人/公告只送到其中一個程序，請改用 Redis 或維持 1 worker。")

# ------------------------------------------------------------------
# API 速率限制 (Sliding Window Rate Limiter)  ── [v2] thread-safe 版本
# ------------------------------------------------------------------
# 為什麼要改：
#   1) 原本的 list 重建不是原子操作，FastAPI 同步端點跑在 threadpool，會有 race。
#   2) 只有 /api/verify 有限流，/api/heartbeat 完全沒有 → 被拿來打 DB 的破口。
#   3) 回應沒有 Retry-After，客戶端無法做正確退避。
class SlidingWindowLimiter:
    """固定窗口內的滑動視窗限流器（單程序記憶體版，足夠 1 worker 使用）。"""

    def __init__(self, max_events: int, window_seconds: float, name: str = ""):
        self.max_events = max_events
        self.window = window_seconds
        self.name = name
        self._hits: Dict[str, deque] = {}
        self._lock = threading.Lock()
        self._last_gc = time.time()

    def allow(self, key: str) -> Tuple[bool, int]:
        """回傳 (是否放行, 建議等待秒數)。"""
        now = time.time()
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                q = deque()
                self._hits[key] = q
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_events:
                return False, max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            self._gc_locked(now)
            return True, 0

    def _gc_locked(self, now: float):
        # 每 60 秒清一次，避免字典無限長大
        if now - self._last_gc < 60:
            return
        self._last_gc = now
        dead = [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]
        for k in dead:
            self._hits.pop(k, None)
        # 極端情況（有人用隨機卡密灌爆）硬性上限，避免記憶體被吃光
        if len(self._hits) > 50000:
            self._hits.clear()


# [v2] 可用環境變數調整，不用改程式
VERIFY_RATE_LIMIT = int(os.environ.get("VERIFY_RATE_LIMIT", "30"))        # 每 IP 每分鐘登入次數
HEARTBEAT_RATE_LIMIT = int(os.environ.get("HEARTBEAT_RATE_LIMIT", "120"))  # 每張卡密每分鐘心跳次數
ADMIN_RATE_LIMIT = int(os.environ.get("ADMIN_RATE_LIMIT", "240"))          # 每 IP 每分鐘後台請求

verify_limiter = SlidingWindowLimiter(VERIFY_RATE_LIMIT, 60, "verify")
heartbeat_limiter = SlidingWindowLimiter(HEARTBEAT_RATE_LIMIT, 60, "heartbeat")
# 每 IP 的心跳上限（比每卡密寬），防止有人用隨機卡密繞過「以卡密為鍵」的限流
heartbeat_ip_limiter = SlidingWindowLimiter(max(HEARTBEAT_RATE_LIMIT, 240), 60, "heartbeat_ip")
admin_limiter = SlidingWindowLimiter(ADMIN_RATE_LIMIT, 60, "admin")
# 後台密鑰錯誤嘗試：10 次 / 5 分鐘就鎖該 IP（防暴力破解）
admin_fail_limiter = SlidingWindowLimiter(10, 300, "admin_fail")


def _too_many(retry_after: int, message: str = "請求過於頻繁，請稍後再試 (Rate limit exceeded)"):
    raise HTTPException(
        status_code=429,
        detail=message,
        headers={"Retry-After": str(retry_after)},
    )


def check_rate_limit(request: Request):
    """適用於 /api/verify（登入）。"""
    ok, retry = verify_limiter.allow(get_client_ip(request))
    if not ok:
        _too_many(retry)


def check_heartbeat_rate_limit(request: Request, license_key: str = ""):
    """[v2] 心跳限流：
    - 以「卡密」為主鍵，避免同一網段/CGNAT 的多個使用者互相拖累
    - 另外加一層較寬的「每 IP」上限，防止有人用隨機卡密繞過
    """
    ip = get_client_ip(request)
    ok, retry = heartbeat_ip_limiter.allow(f"hb-ip:{ip}")
    if not ok:
        _too_many(retry, "心跳過於頻繁 (Heartbeat rate limit exceeded)")
    if license_key:
        ok, retry = heartbeat_limiter.allow(f"hb:{license_key}")
        if not ok:
            _too_many(retry, "心跳過於頻繁 (Heartbeat rate limit exceeded)")

# ------------------------------------------------------------------
# 連線註冊表（WebSocket + SSE 共用）
# key = license_key, value = {"ws": WebSocket, "app_id": str, "username": str, "hwid": str, "ip": str, "connected_at": iso}
# ------------------------------------------------------------------
active_connections: Dict[str, dict] = {}

# ------------------------------------------------------------------
# [v2] SSE 即時推播（Server-Sent Events）
#
#   為什麼要這個：
#     原本「停用 / 黑名單 / 廣播」只會對「有開 WebSocket」的連線推送，
#     但客戶端從來沒連過 /ws/license，所以實際上永遠推不到 0 個人，
#     按「停用」只是把線上名單刪掉，玩家要等下一次心跳才會被踢。
#
#   SSE 的好處：它就是一條「不會結束的 HTTP GET」，用你現有的 libcurl
#   就能接（不需要 WebSocket 支援，你的靜態庫實測沒有 WebSocket）。
# ------------------------------------------------------------------
SSE_KEEPALIVE_SECONDS = int(os.environ.get("SSE_KEEPALIVE_SECONDS", "25"))
SSE_TICKET_TTL = int(os.environ.get("SSE_TICKET_TTL", "60"))
SSE_MAX_PER_KEY = int(os.environ.get("SSE_MAX_PER_KEY", "2"))
SSE_MAX_TOTAL = int(os.environ.get("SSE_MAX_TOTAL", "2000"))


@dataclass(eq=False)
class _StreamConn:
    app_id: str
    license_key: str
    username: str
    hwid: str
    ip: str
    queue: Optional[asyncio.Queue] = None


# 注意：_streams 只在 event loop 內被讀寫，不需要鎖；
#       _tickets 會被 threadpool 的同步端點存取，所以要鎖。
_streams: Dict[str, List[_StreamConn]] = defaultdict(list)
_tickets: Dict[str, Tuple[float, dict]] = {}
_tickets_lock = threading.Lock()


def _gc_tickets_locked(now: float):
    if len(_tickets) < 2000:
        return
    for t in [t for t, (exp, _) in _tickets.items() if exp < now]:
        _tickets.pop(t, None)


def create_stream_ticket(app_id: str, license_key: str, username: str, hwid: str, ip: str) -> str:
    """建立一次性、短效（預設 60 秒）的串流門票，避免卡密直接出現在 URL / access log。"""
    ticket = secrets.token_urlsafe(24)
    now = time.time()
    with _tickets_lock:
        _gc_tickets_locked(now)
        _tickets[ticket] = (now + SSE_TICKET_TTL, {
            "app_id": app_id,
            "license_key": license_key,
            "username": username,
            "hwid": hwid,
            "ip": ip,
        })
    return ticket


def consume_stream_ticket(ticket: str) -> Optional[dict]:
    with _tickets_lock:
        item = _tickets.pop(ticket, None)
    if not item:
        return None
    expires_at, payload = item
    if expires_at < time.time():
        return None
    return payload


def publish_to_key(license_key: str, event: dict) -> int:
    """把事件放進這張卡密的所有 SSE 佇列，回傳推送條數。"""
    sent = 0
    for conn in list(_streams.get(license_key, ())):
        try:
            conn.queue.put_nowait(dict(event))
            sent += 1
        except Exception:
            pass
    return sent


def publish_to_app(app_id: Optional[str], event: dict) -> int:
    """推給某個 app 的所有 SSE 連線；app_id=None 表示全站。"""
    sent = 0
    for _key, conns in list(_streams.items()):
        for conn in list(conns):
            if app_id and conn.app_id != app_id:
                continue
            try:
                conn.queue.put_nowait(dict(event))
                sent += 1
            except Exception:
                pass
    return sent


async def _send_ws(entry: dict, payload: dict):
    ws = entry.get("ws")
    if not ws:
        return
    try:
        await ws.send_json(payload)
        await ws.close()
    except Exception as e:
        print(f"[WebSocket Push Error] {e}")


async def push_status_to_key(license_key: str, status: str, message: str, extra: Optional[dict] = None):
    """把狀態（停用/過期/黑名單/綁定重設…）推給這張卡密的所有連線。"""
    event = {
        "type": "status",
        "status": status,
        "message": message,
        "ts": int(time.time() * 1000),
    }
    if extra:
        event.update(extra)

    # 1) SSE（主要通道）
    publish_to_key(license_key, event)

    # 2) WebSocket（如果客戶端有開才會有）
    entry = active_connections.get(license_key)
    if entry is not None:
        await _send_ws(entry, {"status": status, "message": message, **(extra or {})})
        active_connections.pop(license_key, None)


async def broadcast_to_app(app_id: Optional[str], status: str, message: str, extra: Optional[dict] = None):
    """推播給指定 app_id 或所有在線連線（維護模式等）。"""
    event = {
        "type": "status",
        "status": status,
        "message": message,
        "ts": int(time.time() * 1000),
    }
    if extra:
        event.update(extra)

    publish_to_app(app_id, event)

    for license_key, entry in list(active_connections.items()):
        if not app_id or entry.get("app_id") == app_id:
            await _send_ws(entry, {"status": status, "message": message, **(extra or {})})

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
    # [v2] 客戶端每次登入產生的隨機值；伺服器會把它簽進簽章並原樣回傳，
    #      可以徹底防「重播舊的成功回應」。舊版客戶端不傳也能運作（向後相容）。
    nonce: Optional[str] = None

class HeartbeatRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str
    version: Optional[str] = None
    owner_id: Optional[str] = None
    nonce: Optional[str] = None          # [v2]

class VerifyResponse(BaseModel):
    status: str          # ok / invalid / expired / disabled / hwid_mismatch / maintenance / version_mismatch / blacklisted
    message: str
    username: Optional[str] = None
    expires_at: Optional[str] = None
    server_timestamp: Optional[str] = None
    server_time_ms: Optional[int] = None
    signature: Optional[str] = None
    dynamic_payload: Optional[str] = None
    # [v2] 以下三個欄位是「離線租約」核心，舊客戶端會忽略、不會壞
    nonce: Optional[str] = None
    lease_expires_ms: Optional[int] = None      # 租約到期時間（毫秒，UTC）
    heartbeat_interval: Optional[int] = None    # 建議心跳間隔（秒），之後想調整不用重編客戶端
    signature_v2: Optional[str] = None          # [v2] 新式簽章（含 nonce + 租約），舊欄位 signature 保留給舊客戶端

class CreateKeyRequest(BaseModel):
    app_id: str
    license_key: Optional[str] = None
    username: str
    max_devices: int = 1
    expires_at: str  # ISO datetime string

class ExtendKeyRequest(BaseModel):
    days: Optional[int] = None
    expires_at: Optional[str] = None

class CreateApplicationRequest(BaseModel):
    name: str
    app_type: str = "dll"  # 'exe' 或 'dll'

class MaintenanceSettingsRequest(BaseModel):
    app_id: str
    maintenance_mode: bool
    maintenance_message: str = "卡密系統維護中"
    latest_version: str = "v1.0.0"
    update_changelog: Optional[str] = ""

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
    app_id: Optional[str] = None
    latest_version: str = "v1.0.0"
    update_changelog: str = ""
    stopped: bool = False
    stop_message: str = "YangEnx Internal 停服維護中"

# ------------------------------------------------------------------
# 工具函式
# ------------------------------------------------------------------
# [v2] 輕量 TTL 快取：心跳路徑原本每個請求要打 5~6 次 Supabase，
#      每次 30~150ms，累積起來就是「明明伺服器活著卻心跳逾時」的元凶之一。
class TTLCache:
    def __init__(self, default_ttl: float = 20.0):
        self.default_ttl = default_ttl
        self._data: Dict[str, Tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return False, None
            expires_at, value = item
            if expires_at < time.time():
                self._data.pop(key, None)
                return False, None
            return True, value

    def set(self, key: str, value, ttl: Optional[float] = None):
        with self._lock:
            self._data[key] = (time.time() + (self.default_ttl if ttl is None else ttl), value)

    def invalidate(self, prefix: str = ""):
        with self._lock:
            for k in [k for k in self._data if k.startswith(prefix)]:
                self._data.pop(k, None)


app_cache = TTLCache(APP_CACHE_TTL)              # key: app_secret -> application row
settings_cache = TTLCache(SETTINGS_CACHE_TTL)    # key: app_settings:{app_id}
internal_cache = TTLCache(SETTINGS_CACHE_TTL)    # key: internal_settings:{app_id}
blacklist_cache = TTLCache(BLACKLIST_CACHE_TTL)  # key: index


def get_client_ip(request: Request) -> str:
    # [v2] 注意：X-Forwarded-For 是可以自行偽造的；若有人直連 Render 的 onrender.com 網域
    #      就可以自訂這個標頭來繞過「IP 黑名單」。真正重要的封鎖請用 HWID。
    #      若前面確定只有 Cloudflare，可再收緊成只信任 CF-Connecting-IP。
    if TRUST_PROXY_HEADERS:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()[:64]
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "127.0.0.1"

def verify_download_authorization(app_id: str, license_key: Optional[str], hwid: Optional[str], client_ip: str, x_admin_token: Optional[str] = None):
    # 若提供管理員 Token 且驗證通過，允許管理員免卡密測試下載
    if ADMIN_TOKENS and x_admin_token and any(hmac.compare_digest(x_admin_token, t) for t in ADMIN_TOKENS):
        return

    # [v2] 重要：v1 只要帶著 app_secret（而 app_secret 就寫在客戶端裡、任何人都能挖出來）
    #      就能下載 DLL。設 REQUIRE_LICENSE_FOR_DOWNLOAD=1 後，必須有「有效卡密 + 已綁定裝置」。
    if REQUIRE_LICENSE_FOR_DOWNLOAD and (not license_key or not hwid):
        raise HTTPException(status_code=403, detail="無下載權限：請先以卡密登入驗證")

    # 1. 黑名單檢查
    is_bl, bl_msg = check_blacklist(app_id, hwid or "", client_ip)
    if is_bl:
        raise HTTPException(status_code=403, detail=f"無下載權限：{bl_msg}")

    # 若有傳入卡密與硬體鎖，則進行卡密狀態、到期日與綁定檢查
    if license_key and hwid:
        res = supabase.table("license_keys").select("*").eq("license_key", license_key).eq("app_id", app_id).execute()
        if not res.data:
            raise HTTPException(status_code=403, detail="無下載權限：卡密不存在或無效")

        row = res.data[0]
        if row["status"] != "active":
            raise HTTPException(status_code=403, detail="無下載權限：此卡密已被停用")

        expires_at = parse_iso(row["expires_at"])
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="無下載權限：此卡密已過期")

        hwid_status, hwid_msg, _ = check_and_bind_hwid(row, hwid)
        if hwid_status != "ok":
            raise HTTPException(status_code=403, detail=f"無下載權限：{hwid_msg}")


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
    # [v2] 先看快取；TTL 只有 20 秒，後台按「儲存」時會主動清掉，所以體感仍是即時。
    hit, cached = settings_cache.get(f"app_settings:{app_id}")
    if hit and isinstance(cached, dict):
        return dict(cached)

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
                # [v2] 舊資料可能是 UTF-8 被當成 Latin-1 存進去的亂碼，讀取時順手修
                settings["update_changelog"] = _repair_mojibake(row["update_changelog"])
            if row.get("dynamic_payload"):
                settings["dynamic_payload"] = row["dynamic_payload"]
    except Exception as e:
        print(f"[Supabase Select Warning] {e}")
    settings_cache.set(f"app_settings:{app_id}", dict(settings))
    return settings

def set_app_settings(app_id: str, maintenance_mode: bool, maintenance_message: str, latest_version: str, update_changelog: str = "", dynamic_payload: str = "") -> Optional[str]:
    update_changelog = _repair_mojibake(update_changelog)   # [v2] 統一修正亂碼
    if not supabase:
        return "Supabase client not initialized"
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
        return None
    except Exception as e:
        print(f"[Supabase Upsert Error] {e}")
        return str(e)
    finally:
        # 一定要在「寫入之後」才清快取：先清的話，別的請求可能在 upsert 完成前
        # 又把資料庫裡的舊值讀回快取，後台就會顯示上一個版本（上傳後版本跳回舊的就是這個原因）。
        settings_cache.invalidate(f"app_settings:{app_id}")

def require_admin(request: Request, x_admin_token: Optional[str] = Header(None)):
    """[v2] 後台驗證強化：
    - 缺少 Token 時回 401（v1 用 Header(...) 會回 422，等於告訴攻擊者「這個端點存在」）
    - 用 hmac.compare_digest 做常數時間比對（避免理論上的 timing attack）
    - 支援多組 Token 輪替（ADMIN_TOKEN=a,b）
    - 每 IP 每分鐘限流 + 錯誤超過 10 次鎖 5 分鐘（防暴力破解）
    """
    ip = get_client_ip(request)
    ok, retry = admin_limiter.allow(f"admin:{ip}")
    if not ok:
        _too_many(retry, "後台請求過於頻繁")

    if not ADMIN_TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized: ADMIN_TOKEN not configured")
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Unauthorized: Missing X-Admin-Token")

    matched = any(hmac.compare_digest(x_admin_token, t) for t in ADMIN_TOKENS)
    if not matched:
        ok_fail, retry_fail = admin_fail_limiter.allow(f"fail:{ip}")
        # 注意：allow() 會在「還沒滿」時消耗一次；滿了才擋
        if not ok_fail:
            raise HTTPException(
                status_code=429,
                detail=f"密鑰錯誤次數過多，請 {retry_fail} 秒後再試",
                headers={"Retry-After": str(retry_fail)},
            )
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
    # [v2] app_secret 幾乎不會變，快取 60 秒可少一次 DB 往返（換密鑰時會主動清快取）
    hit, cached = app_cache.get(app_secret)
    if hit and isinstance(cached, dict):
        return cached
    res = supabase.table("license_applications").select("*").eq("app_secret", app_secret).execute()
    if not res.data:
        raise HTTPException(status_code=403, detail="Invalid app secret")
    app_row = res.data[0]
    app_cache.set(app_secret, app_row)
    return app_row

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
def _load_blacklist_index() -> List[Tuple[str, str, str, str]]:
    """[v2] 黑名單一次抓完整表並快取 20 秒（含預先轉小寫），
    取代 v1 每次心跳都 select * 全表掃描的做法。"""
    hit, cached = blacklist_cache.get("index")
    if hit and isinstance(cached, list):
        return cached
    if not supabase:
        return []
    try:
        res = supabase.table("blacklists").select("app_id,type,value,reason").execute()
        index: List[Tuple[str, str, str, str]] = []
        for row in res.data or []:
            row_app = row.get("app_id")
            row_app = str(row_app).strip() if row_app is not None else ""
            if row_app in ("", "null", "undefined", "None"):
                row_app = ""
            b_type = (row.get("type") or "").lower().strip()
            b_val = (row.get("value") or "").strip().lower()
            if not b_type or not b_val:
                continue
            index.append((row_app, b_type, b_val, row.get("reason") or "已被管理者列入黑名單"))
        blacklist_cache.set("index", index)
        return index
    except Exception as e:
        # 注意：資料庫出錯時 v1/v2 都是「放行」(fail-open)；若你的商業模式要求
        # 「DB 掛掉也不能用」，把下面改成 raise HTTPException(503) 即可。
        print(f"[Check Blacklist Warning] {e}")
        return []


def check_blacklist(app_id: str, hwid: str, client_ip: str) -> Tuple[bool, str]:
    """檢查 HWID 或 IP 是否在黑名單中 (支援全域與 App 專屬黑名單)。"""
    hwid_l = (hwid or "").strip().lower()
    ip_l = (client_ip or "").strip().lower()
    if not hwid_l and not ip_l:
        return False, ""
    for row_app, b_type, b_val, reason in _load_blacklist_index():
        if row_app and row_app != app_id:
            continue
        if b_type == "hwid" and hwid_l and b_val == hwid_l:
            return True, f"此裝置已封禁 ({reason})"
        if b_type == "ip" and ip_l and b_val == ip_l:
            return True, f"此 IP 位址已封禁 ({reason})"
    return False, ""

def touch_connection(license_key: str, app_id: str, username: str, hwid: str, ip: str):
    """更新（而不是覆蓋）線上連線資料。

    [修正] 原本 verify / heartbeat 都是直接換掉整個 dict，會把 SSE 連線建的
    "sse": True 和 WebSocket 的 "ws" 弄丟；一掉 flags 之後
    clean_active_connections() 就會把它當成「沒有長連線」的使用者，
    60 秒後從線上名單消失 → 後台線上狀態一下有、一下沒有。
    """
    entry = active_connections.get(license_key)
    if entry is None:
        entry = {
            "connected_at": datetime.now(timezone.utc).isoformat(),
        }
    entry.update({
        "app_id": app_id,
        "username": username,
        "hwid": hwid,
        "ip": ip,
        "last_seen": time.time(),
    })
    active_connections[license_key] = entry


def clean_active_connections():
    now_ts = time.time()
    for lk, entry in list(active_connections.items()):
        # 真的存在 WebSocket 連線 → 交給連線本身管理
        if entry.get("ws"):
            continue

        # SSE 連線：只要串流還在就一直算在線（心跳可能是 5 分鐘一次，不能靠 last_seen）
        if entry.get("sse"):
            if _streams.get(lk):
                continue
            # 串流已經不存在（例如被踢掉後沒清乾淨）→ 等 last_seen 過期再清
            if now_ts - entry.get("last_seen", 0) > 60:
                active_connections.pop(lk, None)
            continue

        # 只有心跳（沒有長連線）的使用者：60 秒沒心跳就當離線
        if now_ts - entry.get("last_seen", 0) > 60:
            active_connections.pop(lk, None)

def normalize_version(v: Optional[str]) -> str:
    """去除前後空白及開頭的 v/V，使 v1.0.0 與 1.0.0 能夠等價比對"""
    if not v:
        return ""
    clean = v.strip()
    if clean.lower().startswith("v"):
        clean = clean[1:].strip()
    return clean

def parse_hwids(hwid_str: Optional[str]) -> List[str]:
    if not hwid_str:
        return []
    try:
        if hwid_str.startswith("["):
            return [str(h).strip().lower() for h in json.loads(hwid_str)]
    except Exception:
        pass
    return [hwid_str.strip().lower()]

def check_and_bind_hwid(row: dict, input_hwid: str) -> Tuple[str, str, Optional[List[str]]]:
    clean_input = input_hwid.strip().lower()
    bound = parse_hwids(row.get("hwid"))
    max_dev = row.get("max_devices", 1)

    if clean_input in bound:
        return "ok", "驗證成功", None

    if len(bound) < max_dev:
        new_bound = bound + [clean_input]
        return "ok", "新裝置綁定成功", new_bound

    return "hwid_mismatch", f"此卡密已綁定滿 {max_dev} 台裝置 (現有: {len(bound)} 台)", None


def parse_iso(value) -> datetime:
    """[v2] 統一解析 Supabase 回傳的時間欄位（可能是 str、可能是 datetime、可能是 naive）。"""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def apply_hwid_binding(row: dict, input_hwid: str, new_bound: Optional[List[str]]) -> Tuple[str, str]:
    """[v2] 以樂觀鎖寫入 HWID，避免兩個請求同時綁定把 max_devices 撐爆。
    回傳 (status, message)；status == "ok" 代表成功或不需要寫入。
    """
    if new_bound is None:
        return "ok", ""
    clean_input = input_hwid.strip().lower()
    try:
        query = supabase.table("license_keys").update({"hwid": json.dumps(new_bound)}).eq("id", row["id"])
        old_value = row.get("hwid")
        if old_value is None:
            query = query.is_("hwid", "null")
        else:
            query = query.eq("hwid", old_value)
        res = query.execute()
        if res.data:
            return "ok", ""
    except Exception as e:
        print(f"[HWID Bind Warning] {e}")
        # 樂觀鎖語法不支援時退回舊寫法（至少不會讓使用者無法登入）
        try:
            supabase.table("license_keys").update({"hwid": json.dumps(new_bound)}).eq("id", row["id"]).execute()
            return "ok", ""
        except Exception as e2:
            print(f"[HWID Bind Error] {e2}")
            return "ok", ""

    # 寫入被別人搶先 → 重讀確認是否已經包含本機
    try:
        fresh = supabase.table("license_keys").select("hwid,max_devices").eq("id", row["id"]).execute()
        if fresh.data:
            frow = fresh.data[0]
            bound = parse_hwids(frow.get("hwid"))
            if clean_input in bound:
                return "ok", ""
            max_dev = frow.get("max_devices", 1)
            if len(bound) < max_dev:
                bound = bound + [clean_input]
                supabase.table("license_keys").update({"hwid": json.dumps(bound)}).eq("id", row["id"]).execute()
                return "ok", ""
            return "hwid_mismatch", f"此卡密已綁定滿 {max_dev} 台裝置 (現有: {len(bound)} 台)"
    except Exception as e:
        print(f"[HWID Recheck Warning] {e}")
    return "ok", ""

# [v2] 伺服器建議的心跳間隔（秒）。客戶端會照這個值調整，之後改這裡就能調負載，
#      不用重新編譯 DLL。10 秒太兇（免費方案容易被冷啟動拖垮），30~60 秒就夠。
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("HEARTBEAT_INTERVAL_SECONDS", "30"))


def generate_server_verification(app_secret: str, license_key: str, hwid: str,
                                 nonce: str = "", lease_seconds: int = LEASE_TTL_SECONDS):
    """回傳 (server_timestamp_iso, server_time_ms, signature_legacy, signature_v2, lease_expires_ms)

    - signature_legacy：與 v1 完全相同（`ts:key:hwid`），已部署的舊客戶端不會壞。
    - signature_v2    ：`v2:ts:key:hwid:nonce:lease_ms`，新客戶端「必須」驗證，
                        且 timestamp/租約都有，攻擊者無法重播舊回應。
    """
    now = datetime.now(timezone.utc)
    server_timestamp = now.isoformat()
    server_time_ms = int(now.timestamp() * 1000)
    lease_ms = server_time_ms + max(0, int(lease_seconds)) * 1000

    # 舊版簽章（向後相容，勿改格式）
    legacy_msg = f"{server_time_ms}:{license_key}:{hwid}"
    sig_legacy = hmac.new(app_secret.encode("utf-8"), legacy_msg.encode("utf-8"), hashlib.sha256).hexdigest()

    # 新版簽章（含 nonce 與租約）
    v2_msg = f"v2:{server_time_ms}:{license_key}:{hwid}:{nonce or ''}:{lease_ms}"
    sig_v2 = hmac.new(app_secret.encode("utf-8"), v2_msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return server_timestamp, server_time_ms, sig_legacy, sig_v2, lease_ms

# ------------------------------------------------------------------
# FastAPI 根路由與 Health
# ------------------------------------------------------------------
@app.get("/", include_in_schema=False)
@app.head("/", include_in_schema=False)
async def root():
    return {"status": "ok", "service": "YangEnx License System Pro"}

@app.get("/health")
async def health_check(deep: int = Query(0)):
    """[v2] deep=1 會順便打一次 Supabase（很輕的 select），
    用途：讓 UptimeRobot / cron-job.org 打這個端點，同時把 Render 和 Supabase 都保溫。"""
    if not deep:
        return {"status": "ok"}
    if not supabase:
        return JSONResponse(status_code=503, content={"status": "degraded", "db": "not_configured"})
    try:
        await run_in_threadpool(lambda: supabase.table("license_applications").select("id").limit(1).execute())
        return {"status": "ok", "db": "ok"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "degraded", "db": str(e)[:200]})

@app.get("/admin")
def admin_panel():
    # 後台 HTML 不給瀏覽器快取：不然改完樣式，手機還會拿著舊版頁面（上次就是這樣）
    return FileResponse(
        os.path.join(os.path.dirname(__file__), "admin.html"),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )

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

    # 2. 檢查維護模式與版本號 (區分 EXE 與 DLL 邏輯)
    app_type = (application.get("app_type") or "dll").lower()
    settings = get_app_settings(app_id)

    if settings.get("maintenance_mode"):
        return VerifyResponse(status="maintenance", message=settings.get("maintenance_message") or "卡密系統維護中")

    if app_type == "exe":
        # EXE 應用程式：只校驗主程式最新版本，完全獨立不受 DLL 停服影響
        if normalize_version(req.version) != normalize_version(settings["latest_version"]):
            return VerifyResponse(status="version_mismatch", message=f"偵測到新版本，請更新至 {settings['latest_version']}。")
    else:
        # DLL 應用程式：校驗 Client.dll 或 Internal.dll 版本與各自停服開關
        internal_s = get_internal_settings(app_id)
        if internal_s.get("stopped"):
            return VerifyResponse(status="maintenance", message=internal_s.get("stop_message") or "YangEnx Internal 停服維護中")

        client_ver = normalize_version(settings["latest_version"])
        internal_ver = normalize_version(internal_s.get("latest_version"))
        req_ver = normalize_version(req.version)

        if req_ver != client_ver and req_ver != internal_ver:
            return VerifyResponse(status="version_mismatch", message=f"偵測到新版本，請更新至 {settings['latest_version']}。")

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

    expires_at = parse_iso(row["expires_at"])
    if expires_at < datetime.now(timezone.utc):
        log_event(row["username"], "LOGIN_FAILED", "此卡密已過期", req.hwid, client_ip)
        return VerifyResponse(status="expired", message="此卡密已過期")

    # 5. 多裝置 HWID 比對與動態綁定（[v2] 樂觀鎖，避免同時綁定超過 max_devices）
    hwid_status, hwid_msg, new_bound = check_and_bind_hwid(row, req.hwid)
    if hwid_status != "ok":
        log_event(row["username"], "LOGIN_FAILED", hwid_msg, req.hwid, client_ip)
        return VerifyResponse(status="hwid_mismatch", message=hwid_msg)

    bind_status, bind_msg = apply_hwid_binding(row, req.hwid, new_bound)
    if bind_status != "ok":
        log_event(row["username"], "LOGIN_FAILED", bind_msg, req.hwid, client_ip)
        return VerifyResponse(status=bind_status, message=bind_msg)

    # [v2] last_seen_at 不再每次登入都寫（減少 DB 寫入）；60 秒內重複登入直接略過
    try:
        last_seen = row.get("last_seen_at")
        need_touch = True
        if last_seen:
            need_touch = (datetime.now(timezone.utc) - parse_iso(last_seen)).total_seconds() > LAST_SEEN_WRITE_INTERVAL
        if need_touch:
            supabase.table("license_keys").update({
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", row["id"]).execute()
    except Exception as e:
        print(f"[last_seen update warning] {e}")

    server_ts, server_ms, sig, sig_v2, lease_ms = generate_server_verification(
        req.app_secret, req.license_key, req.hwid, req.nonce or ""
    )
    dynamic_payload = settings.get("dynamic_payload", "")

    # 註冊即時在線連線監控（merge，不要把 SSE / WS 的旗標蓋掉）
    touch_connection(req.license_key, app_id, row["username"], req.hwid, client_ip)

    log_event(row["username"], "VERIFY_SUCCESS", "認證成功登入主程式", req.hwid, client_ip)
    return VerifyResponse(
        status="ok",
        message="驗證成功",
        username=row["username"],
        expires_at=row["expires_at"],
        server_timestamp=server_ts,
        server_time_ms=server_ms,
        signature=sig,
        signature_v2=sig_v2,
        nonce=req.nonce,
        lease_expires_ms=lease_ms,
        heartbeat_interval=HEARTBEAT_INTERVAL_SECONDS,
        dynamic_payload=dynamic_payload,
    )

# ------------------------------------------------------------------
# WebSocket 即時推播與心跳維持: WS /ws/license
# ------------------------------------------------------------------
class _WSReject(Exception):
    """WebSocket 授權失敗（內部用）。"""

    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _ws_validate(app_secret: str, license_key: str, hwid: str, version: Optional[str],
                 owner_id: Optional[str], client_ip: str):
    """[v2] 把 WebSocket 的授權檢查搬到 threadpool 執行。

    原本 v1 在 async 函式裡直接呼叫同步 Supabase（阻塞 event loop），
    只要有一條連線在等 DB，整個伺服器（含所有心跳）都會被卡住；
    Render 免費版只有 0.1 CPU，這種阻塞很容易被放大成「全部人一起斷線」。
    """
    try:
        application = resolve_app(app_secret)
    except HTTPException:
        raise _WSReject("invalid", "Invalid app secret")

    app_id = application["id"]
    if owner_id and application.get("owner_id") != owner_id:
        raise _WSReject("invalid", "Owner ID mismatch")

    is_bl, bl_msg = check_blacklist(app_id, hwid, client_ip)
    if is_bl:
        raise _WSReject("blacklisted", bl_msg)

    app_type = (application.get("app_type") or "dll").lower()
    settings = get_app_settings(app_id)

    if settings.get("maintenance_mode"):
        raise _WSReject("maintenance", settings.get("maintenance_message") or "卡密系統維護中")

    if app_type == "exe":
        if version and normalize_version(version) != normalize_version(settings["latest_version"]):
            raise _WSReject("version_mismatch", f"請更新至 {settings['latest_version']}")
    else:
        internal_s = get_internal_settings(app_id)
        if internal_s.get("stopped"):
            raise _WSReject("maintenance", internal_s.get("stop_message") or "YangEnx Internal 停服維護中")
        if version:
            client_ver = normalize_version(settings["latest_version"])
            internal_ver = normalize_version(internal_s.get("latest_version"))
            req_ver = normalize_version(version)
            if req_ver != client_ver and req_ver != internal_ver:
                raise _WSReject("version_mismatch", f"請更新至 {settings['latest_version']}")

    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", license_key)
        .eq("app_id", app_id)
        .execute()
    )
    if not res.data:
        raise _WSReject("invalid", "卡密不存在或已被刪除")

    row = res.data[0]
    if row["status"] != "active":
        raise _WSReject("disabled", "此卡密已被停用")
    if parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
        raise _WSReject("expired", "此卡密已過期")

    hwid_status, hwid_msg, _ = check_and_bind_hwid(row, hwid)
    if hwid_status != "ok":
        raise _WSReject("hwid_mismatch", hwid_msg)

    return application, row, settings


@app.websocket("/ws/license")
async def ws_license(
    websocket: WebSocket,
    license_key: str = Query(...),
    hwid: str = Query(...),
    app_secret: str = Query(...),
    version: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    app_name: Optional[str] = Query(None),
    nonce: Optional[str] = Query(None),
):
    if TRUST_PROXY_HEADERS:
        cf_ip = websocket.headers.get("CF-Connecting-IP")
        forwarded = websocket.headers.get("X-Forwarded-For")
        if cf_ip:
            client_ip = cf_ip.strip()
        elif forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = websocket.client.host if websocket.client else "127.0.0.1"
    else:
        client_ip = websocket.client.host if websocket.client else "127.0.0.1"

    await websocket.accept()

    # [v2] 所有阻塞式 DB 呼叫都丟到 threadpool，不再卡住 event loop
    try:
        application, row, settings = await run_in_threadpool(
            _ws_validate, app_secret, license_key, hwid, version, owner_id, client_ip
        )
    except _WSReject as rej:
        try:
            await websocket.send_json({"status": rej.status, "message": rej.message})
            await websocket.close()
        except Exception:
            pass
        return

    app_id = application["id"]

    server_ts, server_ms, sig, sig_v2, lease_ms = generate_server_verification(
        app_secret, license_key, hwid, nonce or ""
    )
    active_connections[license_key] = {
        "ws": websocket,
        "app_id": app_id,
        "username": row["username"],
        "hwid": hwid,
        "ip": client_ip,
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": time.time(),
    }

    await websocket.send_json({
        "status": "ok",
        "message": "已建立即時連線",
        "server_timestamp": server_ts,
        "server_time_ms": server_ms,
        "signature": sig,
        "signature_v2": sig_v2,
        "nonce": nonce,
        "lease_expires_ms": lease_ms,
        "heartbeat_interval": HEARTBEAT_INTERVAL_SECONDS,
        "dynamic_payload": settings.get("dynamic_payload", "")
    })

    try:
        while True:
            text = await websocket.receive_text()
            if "ping" in text.lower():
                _, ts_ms, _, _, lms = generate_server_verification(app_secret, license_key, hwid, nonce or "")
                await websocket.send_json({
                    "status": "pong",
                    "message": "pong",
                    "server_time_ms": ts_ms,
                    "lease_expires_ms": lms,
                })
    except WebSocketDisconnect:
        pass
    finally:
        entry = active_connections.get(license_key)
        if entry is not None and entry.get("ws") is websocket:
            active_connections.pop(license_key, None)


# ------------------------------------------------------------------
# [v2] SSE 即時推播：1) 換門票  2) 建立串流
# ------------------------------------------------------------------
class StreamTicketRequest(BaseModel):
    license_key: str
    hwid: str
    app_secret: str
    owner_id: Optional[str] = None


@app.post("/api/stream/ticket")
def create_stream_ticket_endpoint(req: StreamTicketRequest, request: Request):
    """用卡密換一張 60 秒有效、只能用一次的串流門票。

    回傳一律 200 + status 欄位（跟 /api/verify 一致），
    這樣客戶端可以分辨「授權被拒」與「網路錯誤」。
    """
    check_heartbeat_rate_limit(request, req.license_key)
    client_ip = get_client_ip(request)

    try:
        application = resolve_app(req.app_secret)
    except HTTPException:
        return {"status": "invalid", "message": "Invalid app secret"}

    app_id = application["id"]
    if req.owner_id and application.get("owner_id") != req.owner_id:
        return {"status": "invalid", "message": "Owner ID mismatch"}

    is_bl, bl_msg = check_blacklist(app_id, req.hwid, client_ip)
    if is_bl:
        return {"status": "blacklisted", "message": bl_msg}

    if not supabase:
        return {"status": "server_error", "message": "Database not configured"}

    res = (
        supabase.table("license_keys")
        .select("*")
        .eq("license_key", req.license_key)
        .eq("app_id", app_id)
        .execute()
    )
    if not res.data:
        return {"status": "invalid", "message": "卡密不存在或已被刪除"}

    row = res.data[0]
    if row["status"] != "active":
        return {"status": "disabled", "message": "此卡密已被停用"}
    if parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
        return {"status": "expired", "message": "此卡密已過期"}

    if (req.hwid or "").strip().lower() not in parse_hwids(row.get("hwid")):
        return {"status": "hwid_mismatch", "message": "此裝置尚未綁定，請先重新登入"}

    settings = get_app_settings(app_id)
    if settings.get("maintenance_mode"):
        return {"status": "maintenance", "message": settings.get("maintenance_message") or "卡密系統維護中"}

    ticket = create_stream_ticket(app_id, req.license_key, row.get("username", ""), req.hwid, client_ip)
    return {"status": "ok", "message": "ok", "ticket": ticket, "expires_in": SSE_TICKET_TTL}


@app.get("/api/stream")
async def license_stream(request: Request, ticket: str = Query(...)):
    payload = consume_stream_ticket(ticket)
    if not payload:
        # 401 讓客戶端知道要重新換票，而不是「卡密無效」
        raise HTTPException(status_code=401, detail="Invalid or expired stream ticket")

    total_conns = sum(len(v) for v in _streams.values())
    if total_conns >= SSE_MAX_TOTAL:
        raise HTTPException(status_code=503, detail="Too many streaming connections")

    license_key = payload["license_key"]
    conn = _StreamConn(
        app_id=payload["app_id"],
        license_key=license_key,
        username=payload.get("username", ""),
        hwid=payload.get("hwid", ""),
        ip=payload.get("ip", ""),
    )
    conn.queue = asyncio.Queue(maxsize=64)
    _streams[license_key].append(conn)

    # 同一張卡密最多 N 條（避免共用卡密掛一堆連線），超過就請舊的退出
    while len(_streams[license_key]) > SSE_MAX_PER_KEY:
        old = _streams[license_key].pop(0)
        try:
            old.queue.put_nowait({
                "type": "status",
                "status": "duplicate",
                "message": "此卡密已在其他位置建立新連線",
                "ts": int(time.time() * 1000),
            })
        except Exception:
            pass

    prev = active_connections.get(license_key) or {}
    active_connections[license_key] = {
        "app_id": payload["app_id"],
        "username": conn.username,
        "hwid": conn.hwid,
        "ip": conn.ip,
        "connected_at": prev.get("connected_at") or datetime.now(timezone.utc).isoformat(),
        "last_seen": time.time(),
        "sse": True,
        "ws": prev.get("ws"),
    }

    async def event_generator():
        yield "retry: 5000\n\n"
        yield "data: " + json.dumps({
            "type": "hello",
            "status": "ok",
            "message": "stream established",
            "ts": int(time.time() * 1000),
        }, ensure_ascii=False) + "\n\n"

        try:
            while True:
                try:
                    event = await asyncio.wait_for(conn.queue.get(), timeout=SSE_KEEPALIVE_SECONDS)
                    yield "data: " + json.dumps(event, ensure_ascii=False) + "\n\n"
                except asyncio.TimeoutError:
                    # 保活註解：Cloudflare 大約 100 秒沒資料就會切斷連線
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            try:
                _streams[license_key].remove(conn)
            except ValueError:
                pass
            if not _streams.get(license_key):
                _streams.pop(license_key, None)
                entry = active_connections.get(license_key)
                if entry is not None and entry.get("sse") and not entry.get("ws"):
                    active_connections.pop(license_key, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

# ------------------------------------------------------------------
# 相容性心跳 API: POST /api/heartbeat
# ------------------------------------------------------------------
@app.post("/api/heartbeat", response_model=VerifyResponse)
def heartbeat(req: HeartbeatRequest, request: Request):
    # [v2] 心跳限流（以卡密為鍵），防止有人拿 heartbeat 當免費 DB 查詢 API
    check_heartbeat_rate_limit(request, req.license_key)
    client_ip = get_client_ip(request)
    application = resolve_app(req.app_secret)
    app_id = application["id"]

    is_bl, bl_msg = check_blacklist(app_id, req.hwid, client_ip)
    if is_bl:
        return VerifyResponse(status="blacklisted", message=bl_msg)

    app_type = (application.get("app_type") or "dll").lower()
    settings = get_app_settings(app_id)

    if settings.get("maintenance_mode"):
        return VerifyResponse(status="maintenance", message=settings.get("maintenance_message") or "卡密系統維護中")

    if app_type == "exe":
        if req.version and normalize_version(req.version) != normalize_version(settings["latest_version"]):
            return VerifyResponse(status="version_mismatch", message=f"偵測到新版本，請更新至 {settings['latest_version']}。")
    else:
        internal_s = get_internal_settings(app_id)
        if internal_s.get("stopped"):
            return VerifyResponse(status="maintenance", message=internal_s.get("stop_message") or "YangEnx Internal 停服維護中")
        if req.version:
            client_ver = normalize_version(settings["latest_version"])
            internal_ver = normalize_version(internal_s.get("latest_version"))
            req_ver = normalize_version(req.version)
            if req_ver != client_ver and req_ver != internal_ver:
                return VerifyResponse(status="version_mismatch", message=f"偵測到新版本，請更新至 {settings['latest_version']}。")

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

    expires_at = parse_iso(row["expires_at"])
    if expires_at < datetime.now(timezone.utc):
        return VerifyResponse(status="expired", message="此卡密已過期")

    hwid_status, hwid_msg, _ = check_and_bind_hwid(row, req.hwid)
    if hwid_status != "ok":
        return VerifyResponse(status="hwid_mismatch", message=hwid_msg)

    # [v2] last_seen_at 只在超過 60 秒才寫，DB 寫入量可降 ~6 倍
    try:
        last_seen = row.get("last_seen_at")
        need_touch = True
        if last_seen:
            need_touch = (datetime.now(timezone.utc) - parse_iso(last_seen)).total_seconds() > LAST_SEEN_WRITE_INTERVAL
        if need_touch:
            supabase.table("license_keys").update({
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", row["id"]).execute()
    except Exception as e:
        print(f"[heartbeat last_seen warning] {e}")

    # 更新在線連線維護狀態（merge：保留 sse / ws 旗標）
    touch_connection(req.license_key, app_id, row["username"], req.hwid, client_ip)

    server_ts, server_ms, sig, sig_v2, lease_ms = generate_server_verification(
        req.app_secret, req.license_key, req.hwid, req.nonce or ""
    )
    return VerifyResponse(
        status="ok",
        message="心跳成功",
        username=row["username"],
        expires_at=row["expires_at"],
        server_timestamp=server_ts,
        server_time_ms=server_ms,
        signature=sig,
        signature_v2=sig_v2,
        nonce=req.nonce,
        lease_expires_ms=lease_ms,
        heartbeat_interval=HEARTBEAT_INTERVAL_SECONDS,
        dynamic_payload=settings.get("dynamic_payload", "")
    )

# ------------------------------------------------------------------
# 後台管理 API - 應用程式與 key 管理
# ------------------------------------------------------------------
@app.post("/api/admin/apps", dependencies=[Depends(require_admin)])
def create_application(req: CreateApplicationRequest):
    name = req.name.strip()
    app_type = req.app_type.strip().lower() if req.app_type else "dll"
    if app_type not in ("exe", "dll"):
        raise HTTPException(status_code=400, detail="app_type 必須為 'exe' 或 'dll'")
    if not name:
        raise HTTPException(status_code=400, detail="應用程式名稱不可為空")

    for _ in range(5):
        data = {
            "name": name,
            "owner_id": generate_owner_id(),
            "app_secret": generate_app_secret(),
            "app_type": app_type,
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

@app.patch("/api/admin/apps/{app_id}/toggle-type", dependencies=[Depends(require_admin)])
def toggle_app_type(app_id: str):
    app = get_application_or_404(app_id)
    current_type = (app.get("app_type") or "dll").lower()
    new_type = "exe" if current_type == "dll" else "dll"

    res = supabase.table("license_applications").update({"app_type": new_type}).eq("id", app_id).execute()
    app_cache.invalidate()   # [v2] app_type 有快取，改完要立刻失效
    return res.data[0] if res.data else {"id": app_id, "app_type": new_type}

@app.delete("/api/admin/apps/{app_id}", dependencies=[Depends(require_admin)])
async def delete_application(app_id: str):
    get_application_or_404(app_id)
    keys_res = supabase.table("license_keys").select("license_key").eq("app_id", app_id).execute()
    for row in keys_res.data or []:
        await push_status_to_key(row["license_key"], "invalid", "此應用程式已被管理員刪除")

    supabase.table("license_keys").delete().eq("app_id", app_id).execute()
    supabase.table("license_applications").delete().eq("id", app_id).execute()
    app_cache.invalidate()        # [v2]
    settings_cache.invalidate(f"app_settings:{app_id}")
    internal_cache.invalidate(f"internal:{app_id}")
    return {"ok": True}

@app.patch("/api/admin/apps/{app_id}/rotate-secret", dependencies=[Depends(require_admin)])
async def rotate_app_secret(app_id: str):
    get_application_or_404(app_id)
    new_secret = generate_app_secret()
    res = supabase.table("license_applications").update({"app_secret": new_secret}).eq("id", app_id).execute()
    app_cache.invalidate()   # [v2] 舊密鑰的快取必須立刻失效，否則舊客戶端還能繼續用 60 秒

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

@app.patch("/api/admin/keys/{key_id}/extend", dependencies=[Depends(require_admin)])
async def extend_key(key_id: int, req: ExtendKeyRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="資料庫未連接")

    res = supabase.table("license_keys").select("*").eq("id", key_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="找不到指定的卡密")

    row = res.data[0]
    now_utc = datetime.now(timezone.utc)

    if req.expires_at:
        try:
            clean_str = req.expires_at.strip().replace("Z", "+00:00")
            new_expiry = datetime.fromisoformat(clean_str)
            if new_expiry.tzinfo is None:
                new_expiry = new_expiry.replace(tzinfo=timezone.utc)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"到期時間格式無效：{e}")
    elif req.days is not None:
        try:
            curr_expires = parse_iso(row["expires_at"])
            base_time = max(curr_expires, now_utc)
            new_expiry = base_time + timedelta(days=req.days)
        except Exception:
            new_expiry = now_utc + timedelta(days=req.days)
    else:
        raise HTTPException(status_code=400, detail="請提供延長天數 (days) 或新的到期時間 (expires_at)")

    new_expiry_iso = new_expiry.isoformat()

    # 自動將狀態重新設為 active (激活)，延長期限
    supabase.table("license_keys").update({
        "expires_at": new_expiry_iso,
        "status": "active"
    }).eq("id", key_id).execute()

    log_event(
        actor="admin",
        event="KEY_EXTENDED",
        detail=f"卡密 {row['license_key']} 已延長期限至 {new_expiry_iso}",
        ip_address=""
    )

    return {
        "ok": True,
        "id": key_id,
        "license_key": row["license_key"],
        "expires_at": new_expiry_iso,
        "status": "active"
    }

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
    clean_active_connections()

    return [
        {
            "license_key": license_key,
            "app_id": entry.get("app_id"),
            "username": entry["username"],
            "hwid": entry.get("hwid"),
            "ip": entry.get("ip"),
            "connected_at": entry["connected_at"],
            # 方便除錯：看得出這個人是 SSE 長連線還是只有心跳
            "sse": bool(entry.get("sse")),
            "ws": bool(entry.get("ws")),
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

    new_changelog = req.update_changelog if req.update_changelog is not None else current.get("update_changelog", "")

    err = set_app_settings(req.app_id, req.maintenance_mode, req.maintenance_message, req.latest_version, new_changelog, current.get("dynamic_payload", ""))
    if err:
        raise HTTPException(status_code=500, detail=f"寫入 Supabase 資料表 app_settings 失敗，請確認資料表存在：{err}")

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

    clean_active_connections()

    # [v2] 先推 SSE（客戶端主要通道），再補 WebSocket（如果有開）
    count = publish_to_app(target_app_id, announcement_payload)

    for license_key, entry in list(active_connections.items()):
        if not target_app_id or entry.get("app_id") == target_app_id:
            ws = entry.get("ws")
            if ws:
                try:
                    await ws.send_json(announcement_payload)
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

    blacklist_cache.invalidate("index")   # [v2] 新封鎖立即生效（不用等 20 秒 TTL）

    # 即時踢掉所有符合此黑名單的線上用戶
    clean_active_connections()
    kicked_count = 0
    for license_key, entry in list(active_connections.items()):
        if target_app_id and entry.get("app_id") != target_app_id:
            continue
        user_hwid = (entry.get("hwid") or "").lower()
        user_ip = entry.get("ip") or ""
        if (b_type == "hwid" and user_hwid == val.lower()) or (b_type == "ip" and user_ip == val):
            try:
                await push_status_to_key(license_key, "blacklisted", f"已被系統封禁: {req.reason}")
            except Exception as e:
                print(f"[Kick Error] {e}")
                active_connections.pop(license_key, None)
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
    blacklist_cache.invalidate("index")   # [v2]
    return {"ok": True}

# ------------------------------------------------------------------
# Client / Internal DLL 檔案與下載 API
# ------------------------------------------------------------------
BUCKET_NAME = "client-files"

# [v2] 修正「UTF-8 被當成 Latin-1」造成的亂碼（multipart 表單常見）。
#      正常中文無法 encode 成 latin-1，所以這個函式對正確資料是無害的（原樣返回）。
def _repair_mojibake(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        fixed = value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value
    return fixed if fixed != value else value


def _storage_file_size(app_id: str, filename: str) -> int:
    """回傳 Supabase Storage 裡這個檔案的大小；找不到或失敗回 0。"""
    if not supabase:
        return 0
    try:
        for item in supabase.storage.from_(BUCKET_NAME).list(app_id) or []:
            if item.get("name") == filename:
                meta = item.get("metadata") or {}
                return int(meta.get("size") or 0)
    except Exception as e:
        print(f"[Storage List Warning] {e}")
    return 0


def ensure_bucket_exists():
    if not supabase:
        return
    try:
        buckets = supabase.storage.list_buckets()
        exists = any(b.name == BUCKET_NAME for b in buckets)
        if not exists:
            supabase.storage.create_bucket(BUCKET_NAME, options={"public": False})
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
    incoming_changelog = _repair_mojibake(changelog).strip() if changelog else ""
    update_changelog = incoming_changelog or settings.get("update_changelog", "")

    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")
    file_size = 0
    with open(local_path, "wb") as f:
        while chunk := await file.read(65536):
            f.write(chunk)
            file_size += len(chunk)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="檔案是空的，請重新選擇 Client.dll")

    ensure_bucket_exists()
    try:
        with open(local_path, "rb") as f:
            supabase.storage.from_(BUCKET_NAME).upload(
                path=f"{app_id}/Client.dll",
                file=f,
                file_options={"upsert": "true", "content-type": "application/octet-stream"}
            )
    except Exception as e:
        # [v2] 不再默默吞掉。Render 的 uploads/ 是暫存磁碟，重啟就會消失，
        #      所以 Storage 失敗一定要讓管理者看到，而不是顯示「上傳成功」。
        raise HTTPException(
            status_code=500,
            detail=f"檔案已寫入伺服器暫存，但上傳 Supabase Storage 失敗（重新部署後會消失）：{e}",
        )

    if _storage_file_size(app_id, "Client.dll") <= 0:
        raise HTTPException(
            status_code=500,
            detail="上傳後在 Supabase Storage 找不到 Client.dll。請確認 bucket 權限，或改用 Supabase 後台直接上傳。",
        )

    # [v2] 確認檔案真的進 Storage 之後，才更新版本號與說明
    settings_err = set_app_settings(app_id, settings["maintenance_mode"], settings["maintenance_message"], latest_version, update_changelog, settings.get("dynamic_payload", ""))
    if settings_err:
        raise HTTPException(status_code=500, detail=f"檔案已上傳，但版本號寫入資料庫失敗：{settings_err}")

    return {
        "ok": True,
        "filename": file.filename or "Client.dll",
        "size": file_size,
        "version": latest_version,
        "changelog": update_changelog,
        "storage": True,
        "source": "storage",
        "message": "已上傳並確認存到 Supabase Storage（重新部署不會消失）",
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
    local_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
    storage_size = _storage_file_size(app_id, "Client.dll")
    size = local_size or storage_size
    source = "local" if local_size > 0 else ("storage" if storage_size > 0 else "none")

    return {
        "has_file": size > 0,
        "filename": "Client.dll" if size > 0 else None,
        "size": size,
        "source": source,             # local = 只在暫存磁碟（重啟會消失）；storage = 已進 Supabase
        "local_size": local_size,
        "storage_size": storage_size,
        "in_storage": storage_size > 0,
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

    if size == 0 and supabase:
        try:
            res = supabase.storage.from_(BUCKET_NAME).list(app_id)
            for item in res or []:
                if item.get("name") == "Client.dll":
                    size = item.get("metadata", {}).get("size", 1024) or 1024
                    break
        except Exception:
            pass

    return {
        "status": "ok" if size > 0 else "no_file",
        "version": settings["latest_version"],
        "size": size,
        "changelog": settings.get("update_changelog", "")
    }

@app.get("/api/client/download")
def download_client_file(
    request: Request,
    app_secret: str = Query(...),
    license_key: Optional[str] = Query(None),
    hwid: Optional[str] = Query(None),
    x_admin_token: Optional[str] = Header(None)
):
    client_ip = get_client_ip(request)
    application = resolve_app(app_secret)
    app_id = application["id"]

    verify_download_authorization(app_id, license_key, hwid, client_ip, x_admin_token)

    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_Client.dll")

    # 優先從本機快取提供 (極致速度且節省雲端流量)
    if os.path.exists(local_path):
        return FileResponse(local_path, filename="Client.dll", media_type="application/octet-stream")

    if supabase:
        try:
            data = supabase.storage.from_(BUCKET_NAME).download(f"{app_id}/Client.dll")
            if data and isinstance(data, (bytes, bytearray)):
                # 下載成功後自動快取到本機硬碟，供後續下載直接使用
                try:
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    with open(local_path, "wb") as f:
                        f.write(data)
                except Exception:
                    pass
                return Response(
                    content=data,
                    media_type="application/octet-stream",
                    headers={
                        "Content-Disposition": 'attachment; filename="Client.dll"',
                        "Content-Length": str(len(data))
                    }
                )
        except Exception as e:
            print(f"[Supabase Client Download Error] {e}")

    raise HTTPException(status_code=404, detail="Client file not uploaded yet")

# ------------------------------------------------------------------
# Internal.dll 相關 APIs (Supabase + Local Sync)
# ------------------------------------------------------------------
DEFAULT_INTERNAL_SETTINGS = {
    "latest_version": "v1.0.0",
    "update_changelog": "",
    "stopped": False,
    "stop_message": "YangEnx Internal 停服維護中",
}

def get_internal_settings(app_id: str) -> dict:
    # [v2] 快取 20 秒（DLL 版本/停服狀態不需要每 10 秒問一次 DB）
    hit, cached = internal_cache.get(f"internal:{app_id}")
    if hit and isinstance(cached, dict):
        return dict(cached)

    settings = dict(DEFAULT_INTERNAL_SETTINGS)

    if supabase:
        try:
            res = supabase.table("internal_settings").select("*").eq("app_id", app_id).execute()
            if res.data:
                row = res.data[0]
                settings["latest_version"] = row.get("latest_version") or DEFAULT_INTERNAL_SETTINGS["latest_version"]
                settings["update_changelog"] = _repair_mojibake(row.get("update_changelog", ""))
                settings["stopped"] = bool(row.get("stopped", False))
                settings["stop_message"] = row.get("stop_message") or DEFAULT_INTERNAL_SETTINGS["stop_message"]
                internal_cache.set(f"internal:{app_id}", dict(settings))
                return settings
        except Exception as e:
            print(f"[Supabase internal_settings Select Warning] {e}")

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
    internal_cache.set(f"internal:{app_id}", dict(settings))
    return settings

def set_internal_settings(app_id: str, latest_version: str, update_changelog: str = "", stopped: Optional[bool] = None, stop_message: Optional[str] = None) -> Optional[str]:
    update_changelog = _repair_mojibake(update_changelog)
    # 先讀「目前值」再寫入。注意：這裡不能先 invalidate 再讀，
    # 否則 get_internal_settings() 會把資料庫裡還沒更新的舊值重新塞回快取，
    # 造成「上傳完版本又跳回上一個版本」。
    current = get_internal_settings(app_id)
    new_stopped = current["stopped"] if stopped is None else bool(stopped)
    new_stop_message = current["stop_message"] if stop_message is None else stop_message.strip()

    payload = {
        "app_id": app_id,
        "latest_version": latest_version,
        "update_changelog": update_changelog,
        "stopped": new_stopped,
        "stop_message": new_stop_message or DEFAULT_INTERNAL_SETTINGS["stop_message"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    supabase_err = None
    if supabase:
        try:
            supabase.table("internal_settings").upsert(payload).execute()
        except Exception as e:
            supabase_err = str(e)
            print(f"[Supabase internal_settings Upsert Warning] {e}")

    json_file = os.path.join(UPLOADS_DIR, f"{app_id}_internal_settings.json")
    try:
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # 寫入完成後才清快取，下一次讀取才會拿到新版本
    internal_cache.invalidate(f"internal:{app_id}")
    return supabase_err

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
    incoming_changelog = _repair_mojibake(changelog).strip() if changelog else ""
    update_changelog = incoming_changelog or settings.get("update_changelog", "")

    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    file_size = 0
    with open(local_path, "wb") as f:
        while chunk := await file.read(65536):
            f.write(chunk)
            file_size += len(chunk)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="檔案是空的，請重新選擇 YangEnx Internal.dll")

    ensure_bucket_exists()
    try:
        with open(local_path, "rb") as f:
            supabase.storage.from_(BUCKET_NAME).upload(
                path=f"{app_id}/YangEnx Internal.dll",
                file=f,
                file_options={"upsert": "true", "content-type": "application/octet-stream"}
            )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"檔案已寫入伺服器暫存，但上傳 Supabase Storage 失敗（重新部署後會消失）：{e}",
        )

    if _storage_file_size(app_id, "YangEnx Internal.dll") <= 0:
        raise HTTPException(
            status_code=500,
            detail="上傳後在 Supabase Storage 找不到 YangEnx Internal.dll。請確認 bucket 權限，或改用 Supabase 後台直接上傳。",
        )

    settings_err = set_internal_settings(app_id, latest_version, update_changelog)
    if settings_err:
        raise HTTPException(status_code=500, detail=f"檔案已上傳，但版本號寫入資料庫失敗：{settings_err}")

    return {
        "ok": True,
        "filename": file.filename or "YangEnx Internal.dll",
        "size": file_size,
        "version": latest_version,
        "changelog": update_changelog,
        "storage": True,
        "source": "storage",
        "message": "已上傳並確認存到 Supabase Storage（重新部署不會消失）",
    }

@app.put("/api/admin/apps/{app_id}/internal-settings", dependencies=[Depends(require_admin)])
def update_internal_settings_api(app_id: str, req: SaveInternalSettingsRequest):
    get_application_or_404(app_id)
    err = set_internal_settings(
        app_id,
        latest_version=req.latest_version,
        update_changelog=req.update_changelog,
        stopped=req.stopped,
        stop_message=req.stop_message
    )
    if err:
        raise HTTPException(status_code=500, detail=f"寫入 Supabase 資料表 internal_settings 失敗，請確認已在 SQL Editor 建立資料表！錯誤詳情：{err}")
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

    current = get_internal_settings(app_id)
    set_internal_settings(app_id, current["latest_version"], current.get("update_changelog", ""), current.get("stopped", False), current.get("stop_message", "YangEnx Internal 停服維護中"))
    return {"ok": True, "message": "已成功刪除 Internal.dll 檔案"}

@app.get("/api/admin/apps/{app_id}/internal-info", dependencies=[Depends(require_admin)])
def get_internal_file_info(app_id: str):
    get_application_or_404(app_id)
    settings = get_internal_settings(app_id)
    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")
    local_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
    storage_size = _storage_file_size(app_id, "YangEnx Internal.dll")
    size = local_size or storage_size
    source = "local" if local_size > 0 else ("storage" if storage_size > 0 else "none")

    return {
        "has_file": size > 0,
        "filename": "YangEnx Internal.dll" if size > 0 else None,
        "size": size,
        "source": source,
        "local_size": local_size,
        "storage_size": storage_size,
        "in_storage": storage_size > 0,
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

    if size == 0 and supabase:
        try:
            res = supabase.storage.from_(BUCKET_NAME).list(app_id)
            for item in res or []:
                if item.get("name") == "YangEnx Internal.dll":
                    size = item.get("metadata", {}).get("size", 1024) or 1024
                    break
        except Exception as e:
            print(f"[Supabase Storage List Warning] {e}")

    return {
        "status": "ok" if size > 0 else "no_file",
        "version": settings["latest_version"],
        "size": size,
        "changelog": settings.get("update_changelog", "")
    }

@app.get("/api/internal/download")
def download_internal_file(
    request: Request,
    app_secret: str = Query(...),
    license_key: Optional[str] = Query(None),
    hwid: Optional[str] = Query(None),
    x_admin_token: Optional[str] = Header(None)
):
    client_ip = get_client_ip(request)
    application = resolve_app(app_secret)
    app_id = application["id"]

    internal_s = get_internal_settings(app_id)
    is_admin = bool(ADMIN_TOKENS and x_admin_token and any(hmac.compare_digest(x_admin_token, t) for t in ADMIN_TOKENS))
    if internal_s.get("stopped", False) and not is_admin:
        raise HTTPException(status_code=503, detail=internal_s.get("stop_message") or "YangEnx Internal 停服維護中")

    verify_download_authorization(app_id, license_key, hwid, client_ip, x_admin_token)

    local_path = os.path.join(UPLOADS_DIR, f"{app_id}_YangEnx_Internal.dll")

    # 優先從本機快取提供 (極致速度且節省雲端流量)
    if os.path.exists(local_path):
        return FileResponse(local_path, filename="YangEnx Internal.dll", media_type="application/octet-stream")

    if supabase:
        try:
            data = supabase.storage.from_(BUCKET_NAME).download(f"{app_id}/YangEnx Internal.dll")
            if data and isinstance(data, (bytes, bytearray)):
                # 下載成功後自動快取到本機硬碟，供後續下載直接秒傳
                try:
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    with open(local_path, "wb") as f:
                        f.write(data)
                except Exception:
                    pass
                return Response(
                    content=data,
                    media_type="application/octet-stream",
                    headers={
                        "Content-Disposition": 'attachment; filename="YangEnx Internal.dll"',
                        "Content-Length": str(len(data))
                    }
                )
        except Exception as e:
            print(f"[Supabase Internal Download Error] {e}")

    raise HTTPException(status_code=404, detail="YangEnx Internal.dll file not uploaded yet")
