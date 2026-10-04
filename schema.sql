-- ============================================
-- 授權系統資料庫結構 (Supabase / PostgreSQL)
-- ============================================

-- 1. 應用程式主表 (Multi-App Support)
CREATE TABLE IF NOT EXISTS license_applications (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name          TEXT NOT NULL,
    owner_id      TEXT NOT NULL,
    app_secret    TEXT UNIQUE NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. 卡密主表
CREATE TABLE IF NOT EXISTS license_keys (
    id            BIGSERIAL PRIMARY KEY,
    app_id        TEXT REFERENCES license_applications(id) ON DELETE CASCADE,
    license_key   TEXT NOT NULL,               -- 相同 app 內不能重複
    username      TEXT NOT NULL,               -- 使用者名稱 (顯示用)
    hwid          TEXT,                        -- 綁定的 HWID JSON 陣列 (例如 ["HWID1", "HWID2"]) 或單一字串
    max_devices   INT NOT NULL DEFAULT 1,      -- 允許最大裝置綁定數
    status        TEXT NOT NULL DEFAULT 'active', -- active / disabled
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ,
    CONSTRAINT unique_app_key UNIQUE (app_id, license_key)
);

CREATE INDEX IF NOT EXISTS idx_license_keys_key ON license_keys (license_key);
CREATE INDEX IF NOT EXISTS idx_license_keys_app ON license_keys (app_id);

-- 3. 黑名單表 (HWID / IP 黑名單)
CREATE TABLE IF NOT EXISTS blacklists (
    id          BIGSERIAL PRIMARY KEY,
    app_id      TEXT,                          -- NULL = 全域黑名單; 有值 = 該 App 專屬黑名單
    type        TEXT NOT NULL,                 -- 'hwid' 或 'ip'
    value       TEXT NOT NULL,                 -- 黑名單 HWID 或 IP 位址
    reason      TEXT,                          -- 封禁原因
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_blacklists_value ON blacklists (value);
CREATE INDEX IF NOT EXISTS idx_blacklists_type ON blacklists (type);

-- 4. 系統與應用程式獨立設定表
CREATE TABLE IF NOT EXISTS app_settings (
    app_id               TEXT PRIMARY KEY REFERENCES license_applications(id) ON DELETE CASCADE,
    maintenance_mode     BOOLEAN NOT NULL DEFAULT false,
    maintenance_message  TEXT DEFAULT '系統維護中，請稍後再試。',
    latest_version       TEXT DEFAULT 'v1.0.0',
    update_changelog     TEXT DEFAULT '',
    dynamic_payload      TEXT DEFAULT '',      -- 動態記憶體 Key / 參數注入 JSON Payload
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. 即時公告廣播紀錄表
CREATE TABLE IF NOT EXISTS system_announcements (
    id          BIGSERIAL PRIMARY KEY,
    app_id      TEXT,                          -- NULL = 全域廣播; 有值 = 該 App 廣播
    title       TEXT NOT NULL,
    message     TEXT NOT NULL,
    level       TEXT NOT NULL DEFAULT 'info',  -- info / warning / important
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 6. 系統操作與認證日誌
CREATE TABLE IF NOT EXISTS system_logs (
    id          BIGSERIAL PRIMARY KEY,
    actor       TEXT NOT NULL,                 -- 卡密 / 使用者名稱 / UNKNOWN_KEY
    event       TEXT NOT NULL,                 -- LOGIN_SUCCESS / LOGIN_FAILED / HEARTBEAT_FAIL / VERIFY_SUCCESS / BLACKLISTED
    detail      TEXT,
    hwid        TEXT,
    ip_address  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 7. 系統全域設定
CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value) VALUES
    ('maintenance_mode', 'false'),
    ('maintenance_message', '卡密網站維護中，請稍後再試。'),
    ('current_version', '1.0.0')
ON CONFLICT (key) DO NOTHING;

-- 8. Client 檔案儲存表 (Client.dll 備份)
CREATE TABLE IF NOT EXISTS app_files (
    app_id        TEXT PRIMARY KEY REFERENCES license_applications(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    file_data     TEXT NOT NULL,
    file_size     BIGINT NOT NULL,
    version       TEXT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 9. YangEnx Internal Maxx 設定表 (Supabase 儲存)
CREATE TABLE IF NOT EXISTS internal_settings (
    app_id               TEXT PRIMARY KEY REFERENCES license_applications(id) ON DELETE CASCADE,
    latest_version       TEXT DEFAULT 'v1.0.0',
    update_changelog     TEXT DEFAULT '',
    stopped              BOOLEAN NOT NULL DEFAULT false,
    stop_message         TEXT DEFAULT 'YangEnx Internal 停服維護中',
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);