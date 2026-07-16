-- ============================================
-- 授權系統資料庫結構 (Supabase / PostgreSQL)
-- ============================================

-- 卡密主表
CREATE TABLE license_keys (
    id            BIGSERIAL PRIMARY KEY,
    license_key   TEXT UNIQUE NOT NULL,        -- 例如 XXXX-YYYY-ZZZZ
    username      TEXT NOT NULL,                -- 使用者名稱 (顯示用)
    hwid          TEXT,                         -- 綁定的硬體 ID，NULL = 尚未綁定
    max_devices   INT NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'active', -- active / disabled
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ
);

CREATE INDEX idx_license_keys_key ON license_keys (license_key);

-- 系統日誌
CREATE TABLE system_logs (
    id          BIGSERIAL PRIMARY KEY,
    actor       TEXT NOT NULL,          -- 卡密 / 使用者名稱 / UNKNOWN_KEY
    event       TEXT NOT NULL,          -- LOGIN_SUCCESS / LOGIN_FAILED / HEARTBEAT_FAIL / VERIFY_SUCCESS
    detail      TEXT,
    hwid        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 系統全域設定 (例如你截圖中的「暫停所有用戶連線」開關)
CREATE TABLE system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value) VALUES
    ('maintenance_mode', 'false'),
    ('maintenance_message', '卡密網站維護中，請稍後再試。'),
    ('current_version', '1.0.0');