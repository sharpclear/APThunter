-- 统一 APT 事件原报告链接字段为 link，并兼容曾使用 report_url 的已有环境。

SET @has_event_link := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'link'
);

SET @add_event_link_sql := IF(
    @has_event_link = 0,
    'ALTER TABLE apt_events ADD COLUMN link TEXT NULL COMMENT ''原报告链接'' AFTER description',
    'SELECT 1'
);

PREPARE add_event_link_stmt FROM @add_event_link_sql;
EXECUTE add_event_link_stmt;
DEALLOCATE PREPARE add_event_link_stmt;

SET @has_legacy_report_url := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'report_url'
);

SET @backfill_event_link_sql := IF(
    @has_legacy_report_url > 0,
    'UPDATE apt_events SET link = TRIM(report_url) WHERE (link IS NULL OR LENGTH(TRIM(link)) = 0) AND report_url IS NOT NULL AND LENGTH(TRIM(report_url)) > 0',
    'SELECT 1'
);

PREPARE backfill_event_link_stmt FROM @backfill_event_link_sql;
EXECUTE backfill_event_link_stmt;
DEALLOCATE PREPARE backfill_event_link_stmt;
