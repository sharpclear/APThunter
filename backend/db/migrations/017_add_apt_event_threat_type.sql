-- 保留 APT 事件 CSV 中的业务类型（如 C2通信、钓鱼攻击、漏洞利用）。

SET @has_event_threat_type := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'threat_type'
);

SET @add_event_threat_type_sql := IF(
    @has_event_threat_type = 0,
    'ALTER TABLE apt_events ADD COLUMN threat_type VARCHAR(64) NOT NULL DEFAULT ''未分类'' COMMENT ''事件业务类型'' AFTER event_type',
    'SELECT 1'
);

PREPARE add_event_threat_type_stmt FROM @add_event_threat_type_sql;
EXECUTE add_event_threat_type_stmt;
DEALLOCATE PREPARE add_event_threat_type_stmt;
