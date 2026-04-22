-- Migration SQL for existing databases
-- Run in phpMyAdmin / MySQL client

-- 1) Email verification support (OTP gating)
SET @__col_exists := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'email_verified_at'
);

SET @__sql := IF(
  @__col_exists = 0,
  'ALTER TABLE users ADD COLUMN email_verified_at DATETIME(3) NULL AFTER password_hash',
  'SELECT "OK: users.email_verified_at already exists"'
);

PREPARE __stmt FROM @__sql;
EXECUTE __stmt;
DEALLOCATE PREPARE __stmt;

-- 2) OTP table for verify_email + reset_password
CREATE TABLE IF NOT EXISTS auth_otps (
  id VARCHAR(32) NOT NULL,
  user_id VARCHAR(32) NOT NULL,
  purpose ENUM('verify_email','reset_password') NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  used_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_auth_otps_user_purpose_created (user_id, purpose, created_at),
  KEY idx_auth_otps_expires (expires_at),
  CONSTRAINT fk_auth_otps_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 3) Per-password / per-login entity table (Option 2: title/host plaintext)
CREATE TABLE IF NOT EXISTS vault_items (
  id VARCHAR(32) NOT NULL,
  user_id VARCHAR(32) NOT NULL,

  -- plaintext metadata (for listing/search + future plan limits)
  title VARCHAR(255) NULL,
  host VARCHAR(255) NULL,

  -- encrypted full payload (username/password/url/etc)
  ciphertext LONGTEXT NOT NULL,

  version INT NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at DATETIME(3) NULL,

  PRIMARY KEY (id),
  KEY idx_vault_items_user_updated (user_id, updated_at),
  KEY idx_vault_items_user_deleted (user_id, deleted_at),
  CONSTRAINT fk_vault_items_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
