-- 为已有环境增加版本化域名指纹快照；重复执行时不会重复添加列。
SET @fingerprint_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'domain_monitor_snapshots'
      AND column_name = 'fingerprint_snapshot'
);

SET @fingerprint_column_ddl = IF(
    @fingerprint_column_exists = 0,
    'ALTER TABLE domain_monitor_snapshots ADD COLUMN fingerprint_snapshot JSON NULL COMMENT ''用于后续归因的版本化指纹快照'' AFTER web_snapshot',
    'SELECT 1'
);

PREPARE fingerprint_column_stmt FROM @fingerprint_column_ddl;
EXECUTE fingerprint_column_stmt;
DEALLOCATE PREPARE fingerprint_column_stmt;
