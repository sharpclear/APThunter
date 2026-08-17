-- Lazarus.day 事件采集接入：保存变更游标、来源候选和正式事件的可追溯字段。

ALTER TABLE apt_events
    MODIFY COLUMN title VARCHAR(500) NOT NULL COMMENT '事件标题';

SET @has_event_key := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'event_key'
);
SET @migration_sql := IF(
    @has_event_key = 0,
    'ALTER TABLE apt_events ADD COLUMN event_key CHAR(64) NULL COMMENT ''规范化事件稳定键'' AFTER id',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @has_date_precision := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'date_precision'
);
SET @migration_sql := IF(
    @has_date_precision = 0,
    'ALTER TABLE apt_events ADD COLUMN date_precision VARCHAR(32) NULL COMMENT ''事件日期精度'' AFTER event_date',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @has_event_confidence := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'confidence'
);
SET @migration_sql := IF(
    @has_event_confidence = 0,
    'ALTER TABLE apt_events ADD COLUMN confidence DECIMAL(5,4) NULL COMMENT ''采集置信度'' AFTER severity',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @has_review_status := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'review_status'
);
SET @migration_sql := IF(
    @has_review_status = 0,
    'ALTER TABLE apt_events ADD COLUMN review_status VARCHAR(32) NOT NULL DEFAULT ''accepted'' COMMENT ''审核状态'' AFTER confidence',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @has_event_evidence := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'evidence'
);
SET @migration_sql := IF(
    @has_event_evidence = 0,
    'ALTER TABLE apt_events ADD COLUMN evidence JSON NULL COMMENT ''来源证据列表'' AFTER review_status',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @has_collection_notes := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'collection_notes'
);
SET @migration_sql := IF(
    @has_collection_notes = 0,
    'ALTER TABLE apt_events ADD COLUMN collection_notes TEXT NULL COMMENT ''采集和审核说明'' AFTER evidence',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @has_event_key_index := (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_events'
      AND INDEX_NAME = 'uniq_apt_events_event_key'
);
SET @migration_sql := IF(
    @has_event_key_index = 0,
    'ALTER TABLE apt_events ADD UNIQUE KEY uniq_apt_events_event_key (event_key)',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

CREATE TABLE IF NOT EXISTS apt_event_sync_state (
    source VARCHAR(64) NOT NULL PRIMARY KEY,
    cursor_value TEXT NULL COMMENT '来源 API 返回的不透明游标',
    last_attempt_at DATETIME NULL,
    last_success_at DATETIME NULL,
    last_error TEXT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='APT 事件来源增量同步状态';

CREATE TABLE IF NOT EXISTS apt_event_import_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source VARCHAR(64) NOT NULL,
    trigger_type VARCHAR(32) NOT NULL DEFAULT 'scheduled',
    status VARCHAR(32) NOT NULL DEFAULT 'running',
    pages_processed INT NOT NULL DEFAULT 0,
    source_records INT NOT NULL DEFAULT 0,
    candidates_written INT NOT NULL DEFAULT 0,
    events_inserted INT NOT NULL DEFAULT 0,
    events_updated INT NOT NULL DEFAULT 0,
    events_unchanged INT NOT NULL DEFAULT 0,
    duplicates_linked INT NOT NULL DEFAULT 0,
    review_queued INT NOT NULL DEFAULT 0,
    error_message TEXT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,
    INDEX idx_apt_event_import_runs_source_started (source, started_at),
    INDEX idx_apt_event_import_runs_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='APT 事件同步批次记录';

SET @has_events_unchanged := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_event_import_runs'
      AND COLUMN_NAME = 'events_unchanged'
);
SET @migration_sql := IF(
    @has_events_unchanged = 0,
    'ALTER TABLE apt_event_import_runs ADD COLUMN events_unchanged INT NOT NULL DEFAULT 0 AFTER events_updated',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

CREATE TABLE IF NOT EXISTS apt_event_candidates (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source VARCHAR(64) NOT NULL,
    source_record_id VARCHAR(512) NOT NULL,
    variant_key VARCHAR(128) NOT NULL,
    source_identity_hash CHAR(64) NOT NULL,
    source_version INT NOT NULL DEFAULT 1,
    quality_status VARCHAR(64) NULL,
    review_required TINYINT(1) NOT NULL DEFAULT 1,
    decision VARCHAR(32) NOT NULL DEFAULT 'needs_review',
    decision_reason TEXT NULL,
    payload JSON NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    apt_event_id INT NULL,
    event_managed TINYINT(1) NOT NULL DEFAULT 0 COMMENT '正式事件是否由该来源创建和维护',
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_apt_event_candidate_identity (source_identity_hash),
    INDEX idx_apt_event_candidates_source_decision (source, decision),
    INDEX idx_apt_event_candidates_event (apt_event_id),
    CONSTRAINT fk_apt_event_candidates_event
        FOREIGN KEY (apt_event_id) REFERENCES apt_events(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='来源事件候选、审核状态和正式事件映射';

SET @has_event_managed := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apt_event_candidates'
      AND COLUMN_NAME = 'event_managed'
);
SET @migration_sql := IF(
    @has_event_managed = 0,
    'ALTER TABLE apt_event_candidates ADD COLUMN event_managed TINYINT(1) NOT NULL DEFAULT 0 COMMENT ''正式事件是否由该来源创建和维护'' AFTER apt_event_id',
    'SELECT 1'
);
PREPARE migration_stmt FROM @migration_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;
