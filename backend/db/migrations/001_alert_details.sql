-- ============================================
-- 迁移：将 high_risk_domains 从 alerts 拆到 alert_details
-- 执行顺序：1. 建表 2. 迁移数据 3. 删列
-- ============================================

-- 1. 创建 alert_details 表
CREATE TABLE IF NOT EXISTS alert_details (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(64) NOT NULL COMMENT '预警ID，关联 alerts.alert_id',
    high_risk_domains JSON NULL COMMENT '高风险域名列表（JSON数组）',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_alert_id (alert_id),
    CONSTRAINT fk_alert_details_alert_id FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='预警详情表（高风险域名等大字段）';

-- 2. 迁移现有数据：将 alerts 中的 high_risk_domains 复制到 alert_details
INSERT INTO alert_details (alert_id, high_risk_domains)
SELECT alert_id, high_risk_domains
FROM alerts
WHERE high_risk_domains IS NOT NULL;

-- 3. 从 alerts 表删除 high_risk_domains 列
ALTER TABLE alerts DROP COLUMN high_risk_domains;
