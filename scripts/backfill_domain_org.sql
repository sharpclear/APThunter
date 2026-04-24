SET @col_exists := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'domains'
    AND COLUMN_NAME = 'organization_id'
);
SET @ddl := IF(@col_exists = 0,
  'ALTER TABLE domains ADD COLUMN organization_id INT NULL COMMENT ''关联组织ID''',
  'SELECT 1');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

DROP TEMPORARY TABLE IF EXISTS _stg_domains_org;
CREATE TEMPORARY TABLE _stg_domains_org (
  id VARCHAR(32),
  domain_name TEXT,
  is_malicious VARCHAR(32),
  first_seen TEXT,
  last_seen TEXT,
  organization_id VARCHAR(32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOAD DATA INFILE '/docker-entrypoint-initdb.d/domains.csv'
INTO TABLE _stg_domains_org
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"' ESCAPED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 LINES;

UPDATE domains d
JOIN _stg_domains_org s
  ON d.id = CAST(NULLIF(TRIM(s.id), '') AS UNSIGNED)
SET d.organization_id = CASE
  WHEN NULLIF(TRIM(s.organization_id), '') IS NULL THEN NULL
  ELSE CAST(TRIM(s.organization_id) AS UNSIGNED)
END;

UPDATE domains d
JOIN _stg_domains_org s
  ON LOWER(TRIM(s.domain_name)) = d.domain_name
SET d.organization_id = CASE
  WHEN NULLIF(TRIM(s.organization_id), '') IS NULL THEN d.organization_id
  ELSE CAST(TRIM(s.organization_id) AS UNSIGNED)
END
WHERE d.organization_id IS NULL;

SELECT COUNT(*) AS total_domains,
       SUM(CASE WHEN organization_id IS NOT NULL THEN 1 ELSE 0 END) AS domains_with_org,
       SUM(CASE WHEN organization_id IS NULL THEN 1 ELSE 0 END) AS domains_without_org
FROM domains;
