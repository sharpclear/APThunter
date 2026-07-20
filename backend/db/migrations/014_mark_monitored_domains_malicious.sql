-- 将所有持续监控目标同步到 domains，并确保它们标记为恶意域名。
-- 可重复执行：已存在域名只更新 is_malicious，不修改组织归属或属性数据。
INSERT INTO domains (domain_name, is_malicious)
SELECT DISTINCT
    normalized_domain,
    1
FROM domain_monitor_targets
WHERE normalized_domain IS NOT NULL
  AND LENGTH(TRIM(normalized_domain)) > 0
ON DUPLICATE KEY UPDATE
    is_malicious = 1;
