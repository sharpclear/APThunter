-- 保留事件 CSV 中的报告发布单位/产品字段。

SET @has_event_releasing_product := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'apt_events'
      AND COLUMN_NAME = 'releasing_product'
);

SET @add_event_releasing_product_sql := IF(
    @has_event_releasing_product = 0,
    'ALTER TABLE apt_events ADD COLUMN releasing_product VARCHAR(255) NULL COMMENT ''报告发布单位/产品'' AFTER threat_type',
    'SELECT 1'
);

PREPARE add_event_releasing_product_stmt FROM @add_event_releasing_product_sql;
EXECUTE add_event_releasing_product_stmt;
DEALLOCATE PREPARE add_event_releasing_product_stmt;
