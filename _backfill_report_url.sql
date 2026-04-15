DROP TABLE IF EXISTS _stg_apt_events_link;
CREATE TABLE _stg_apt_events_link (
  id VARCHAR(32),
  event_date TEXT,
  title LONGTEXT,
  description LONGTEXT,
  threat_type TEXT,
  organization_id VARCHAR(32),
  releasing_product TEXT,
  link TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
LOAD DATA INFILE '/docker-entrypoint-initdb.d/apt_events.csv'
INTO TABLE _stg_apt_events_link
CHARACTER SET gbk
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"' ESCAPED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 LINES;
UPDATE apt_events e
JOIN _stg_apt_events_link s ON e.id = CAST(NULLIF(TRIM(s.id), '') AS UNSIGNED)
SET e.report_url = NULLIF(TRIM(s.link), '')
WHERE (e.report_url IS NULL OR e.report_url = '')
  AND NULLIF(TRIM(s.link), '') IS NOT NULL;
DROP TABLE IF EXISTS _stg_apt_events_link;
SELECT COUNT(*) AS linked_events FROM apt_events WHERE report_url IS NOT NULL AND report_url <> '';
