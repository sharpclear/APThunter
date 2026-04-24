-- ============================================
-- Dashboard 示例数据（APTHunter 数据集映射到 APTHunter3 架构）
-- 数据文件：apt_organizations.csv / apt_events.csv / domains.csv
-- ============================================

SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- ============================================
-- APT 组织数据（CSV 导入）
-- ============================================
DROP TABLE IF EXISTS _stg_apt_organizations;
CREATE TABLE _stg_apt_organizations (
	id VARCHAR(32),
	name TEXT,
	aliases LONGTEXT,
	origin TEXT,
	region TEXT,
	target_countries LONGTEXT,
	target_industries LONGTEXT,
	update_time TEXT,
	description_zh LONGTEXT,
	ioc_count VARCHAR(32),
	event_count VARCHAR(32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOAD DATA INFILE '/docker-entrypoint-initdb.d/apt_organizations.csv'
INTO TABLE _stg_apt_organizations
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"' ESCAPED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 LINES;

INSERT INTO apt_organizations (
	id,
	name,
	alias,
	description,
	ioc_count,
	event_count,
	update_time,
	region,
	origin,
	target_countries,
	target_industries,
	previous_domains,
	vps_providers
)
SELECT
	CAST(NULLIF(TRIM(id), '') AS UNSIGNED),
	TRIM(name),
	CASE
		WHEN NULLIF(TRIM(aliases), '') IS NULL THEN JSON_ARRAY()
		ELSE CAST(CONCAT('["', REPLACE(REPLACE(REPLACE(TRIM(aliases), '\\', '\\\\'), '"', '\\"'), ' | ', '","'), '"]') AS JSON)
	END,
	NULLIF(description_zh, ''),
	COALESCE(CAST(NULLIF(TRIM(ioc_count), '') AS UNSIGNED), 0),
	COALESCE(CAST(NULLIF(TRIM(event_count), '') AS UNSIGNED), 0),
	STR_TO_DATE(NULLIF(TRIM(update_time), ''), '%Y/%c/%e'),
	NULLIF(TRIM(region), ''),
	NULLIF(TRIM(origin), ''),
	CASE
		WHEN NULLIF(TRIM(target_countries), '') IS NULL THEN JSON_ARRAY()
		ELSE CAST(CONCAT('["', REPLACE(REPLACE(REPLACE(TRIM(target_countries), '\\', '\\\\'), '"', '\\"'), ' | ', '","'), '"]') AS JSON)
	END,
	CASE
		WHEN NULLIF(TRIM(target_industries), '') IS NULL THEN JSON_ARRAY()
		ELSE CAST(CONCAT('["', REPLACE(REPLACE(REPLACE(TRIM(target_industries), '\\', '\\\\'), '"', '\\"'), ' | ', '","'), '"]') AS JSON)
	END,
	JSON_ARRAY(),
	JSON_ARRAY()
FROM _stg_apt_organizations;

DROP TABLE IF EXISTS _stg_apt_organizations;

-- ============================================
-- APT 事件数据（CSV 导入并映射字段）
-- ============================================
DROP TABLE IF EXISTS _stg_apt_events;
CREATE TABLE _stg_apt_events (
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
INTO TABLE _stg_apt_events
CHARACTER SET gbk
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"' ESCAPED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 LINES;

INSERT INTO apt_events (
	id,
	event_date,
	title,
	description,
	report_url,
	event_type,
	region,
	latitude,
	longitude,
	organization_id,
	severity
)
SELECT
	CAST(NULLIF(TRIM(e.id), '') AS UNSIGNED),
	STR_TO_DATE(NULLIF(TRIM(e.event_date), ''), '%Y/%c/%e'),
	LEFT(TRIM(e.title), 255),
	NULLIF(e.description, ''),
	NULLIF(TRIM(e.link), ''),
	CASE
		WHEN COALESCE(TRIM(e.threat_type), '') IN ('供应链攻击', '漏洞利用', '勒索软件', 'APT攻击') THEN 'major'
		ELSE 'normal'
	END,
	COALESCE(NULLIF(TRIM(o.region), ''), '未知'),
	NULL,
	NULL,
	CASE
		WHEN NULLIF(TRIM(e.organization_id), '') IS NULL THEN NULL
		ELSE CAST(TRIM(e.organization_id) AS UNSIGNED)
	END,
	CASE
		WHEN COALESCE(TRIM(e.threat_type), '') IN ('供应链攻击', '漏洞利用', '勒索软件', 'APT攻击') THEN 5
		WHEN COALESCE(TRIM(e.threat_type), '') IN ('C2通信', '钓鱼攻击') THEN 4
		ELSE 3
	END
FROM _stg_apt_events e
LEFT JOIN apt_organizations o ON o.id = CAST(NULLIF(TRIM(e.organization_id), '') AS UNSIGNED);

DROP TABLE IF EXISTS _stg_apt_events;

-- ============================================
-- 地区事件统计（由事件+组织聚合）
-- ============================================
INSERT INTO region_event_stats (stat_date, region, event_count, major_count)
SELECT
	e.event_date AS stat_date,
	COALESCE(NULLIF(o.region, ''), '未知') AS region,
	COUNT(*) AS event_count,
	SUM(CASE WHEN e.event_type = 'major' THEN 1 ELSE 0 END) AS major_count
FROM apt_events e
LEFT JOIN apt_organizations o ON e.organization_id = o.id
GROUP BY e.event_date, COALESCE(NULLIF(o.region, ''), '未知');

-- ============================================
-- 域名数据（CSV 导入）
-- ============================================
DROP TABLE IF EXISTS _stg_domains;
CREATE TABLE _stg_domains (
	id VARCHAR(32),
	domain_name TEXT,
	is_malicious VARCHAR(32),
	first_seen TEXT,
	last_seen TEXT,
	organization_id VARCHAR(32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOAD DATA INFILE '/docker-entrypoint-initdb.d/domains.csv'
INTO TABLE _stg_domains
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"' ESCAPED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 LINES;

INSERT IGNORE INTO domains (
	id,
	domain_name,
	is_malicious,
	first_seen,
	last_seen,
	organization_id
)
SELECT
	CAST(NULLIF(TRIM(id), '') AS UNSIGNED),
	LOWER(TRIM(domain_name)),
	CASE
		WHEN NULLIF(TRIM(is_malicious), '') IS NULL THEN 0
		WHEN CAST(TRIM(is_malicious) AS SIGNED) > 0 THEN 1
		ELSE 0
	END,
	CASE
		WHEN NULLIF(TRIM(first_seen), '') IS NULL THEN NULL
		WHEN TRIM(first_seen) REGEXP '^[0-9]{4}[-/][0-9]{1,2}[-/][0-9]{1,2}$'
			THEN STR_TO_DATE(REPLACE(TRIM(first_seen), '/', '-'), '%Y-%m-%d')
		WHEN TRIM(first_seen) REGEXP '^[0-9]+(\\.[0-9]+)?$'
			THEN DATE_ADD('1899-12-30', INTERVAL CAST(TRIM(first_seen) AS UNSIGNED) DAY)
		ELSE NULL
	END,
	CASE
		WHEN NULLIF(TRIM(last_seen), '') IS NULL THEN NULL
		WHEN TRIM(last_seen) REGEXP '^[0-9]{4}[-/][0-9]{1,2}[-/][0-9]{1,2}$'
			THEN STR_TO_DATE(REPLACE(TRIM(last_seen), '/', '-'), '%Y-%m-%d')
		WHEN TRIM(last_seen) REGEXP '^[0-9]+(\\.[0-9]+)?$'
			THEN DATE_ADD('1899-12-30', INTERVAL CAST(TRIM(last_seen) AS UNSIGNED) DAY)
		ELSE NULL
	END,
	CASE
		WHEN NULLIF(TRIM(organization_id), '') IS NULL THEN NULL
		ELSE CAST(TRIM(organization_id) AS UNSIGNED)
	END
FROM _stg_domains
WHERE NULLIF(TRIM(domain_name), '') IS NOT NULL;

DROP TABLE IF EXISTS _stg_domains;

-- ============================================
-- Dashboard 统计聚合
-- ============================================
INSERT INTO threat_statistics (stat_date, total_organizations, total_events, total_domains, total_iocs, active_threats, new_threats_today)
SELECT
	CURDATE() AS stat_date,
	(SELECT COUNT(*) FROM apt_organizations) AS total_organizations,
	(SELECT COUNT(*) FROM apt_events) AS total_events,
	(SELECT COUNT(*) FROM domains) AS total_domains,
	(SELECT COALESCE(SUM(ioc_count), 0) FROM apt_organizations) AS total_iocs,
	(
		SELECT COUNT(DISTINCT organization_id)
		FROM apt_events
		WHERE event_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
		  AND organization_id IS NOT NULL
	) AS active_threats,
	(
		SELECT COUNT(*)
		FROM apt_events
		WHERE event_date = CURDATE()
	) AS new_threats_today;

INSERT INTO threat_trends (trend_date, dns_tunnel_count, dga_domain_count, phishing_count, c2_communication, malware_count)
SELECT
	e.event_date AS trend_date,
	0 AS dns_tunnel_count,
	0 AS dga_domain_count,
	SUM(CASE WHEN e.title LIKE '%钓鱼%' OR e.description LIKE '%钓鱼%' THEN 1 ELSE 0 END) AS phishing_count,
	SUM(CASE WHEN e.title LIKE '%C2%' OR e.description LIKE '%C2%' THEN 1 ELSE 0 END) AS c2_communication,
	COUNT(*) AS malware_count
FROM apt_events e
GROUP BY e.event_date
ORDER BY e.event_date;

INSERT INTO attack_sources (country, attack_count, last_attack_date)
SELECT
	COALESCE(NULLIF(origin, ''), '未知') AS country,
	COUNT(*) AS attack_count,
	CURDATE() AS last_attack_date
FROM apt_organizations
GROUP BY COALESCE(NULLIF(origin, ''), '未知');
