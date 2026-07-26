-- ============================================
-- 数据库初始化脚本
-- 包含所有表结构定义（使用统一的 BIGINT UNSIGNED ID）
-- ============================================

-- 创建 users 表
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(128) NULL,
    bio VARCHAR(500) NULL,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户表';

-- 创建 models 表
CREATE TABLE IF NOT EXISTS models (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(64) NULL,
    description TEXT NULL,
    model_path VARCHAR(500) NULL,
    file_size BIGINT NULL,
    accuracy_metrics JSON NULL,
    model_type ENUM('official','custom','market') NULL DEFAULT 'custom',
    model_category ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd') NULL,
    is_public TINYINT(1) NULL DEFAULT 0,
    is_official TINYINT(1) NULL DEFAULT 0,
    created_by VARCHAR(64) NULL,
    status ENUM('active','inactive') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_model_type (model_type),
    INDEX idx_is_public (is_public),
    INDEX idx_is_official (is_official),
    INDEX idx_created_by (created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='模型表';

-- 创建 files 表
CREATE TABLE IF NOT EXISTS files (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    bucket VARCHAR(128) NOT NULL,
    object_key VARCHAR(512) NOT NULL,
    filename VARCHAR(255) NULL,
    content_type VARCHAR(128) NULL,
    size BIGINT UNSIGNED NULL,
    uploaded_by VARCHAR(64) NULL,
    uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata JSON NULL,
    INDEX idx_bucket (bucket),
    INDEX idx_uploaded_at (uploaded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='文件表';

-- 创建 tasks 表
CREATE TABLE IF NOT EXISTS tasks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(64) UNIQUE NOT NULL,
    task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity','apt_template_nrd') NOT NULL,
    model_id BIGINT UNSIGNED NOT NULL,
    file_id BIGINT UNSIGNED NULL,
    extra JSON NULL,
    status ENUM('pending','processing','completed','failed') NOT NULL DEFAULT 'pending',
    created_by BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_task_id (task_id),
    INDEX idx_model_id (model_id),
    INDEX idx_file_id (file_id),
    INDEX idx_created_by (created_by),
    INDEX idx_tasks_created_by_created_at (created_by, created_at),
    CONSTRAINT fk_tasks_files FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
    CONSTRAINT fk_tasks_models FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE RESTRICT,
    CONSTRAINT fk_tasks_users FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='任务表';

-- 创建 training_tasks 表
CREATE TABLE IF NOT EXISTS training_tasks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(64) UNIQUE NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    model_name VARCHAR(255) NOT NULL,
    model_desc VARCHAR(500) NULL,
    model_category ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd') NOT NULL DEFAULT 'malicious',
    training_data_file_id BIGINT UNSIGNED NULL,
    training_parameters JSON NULL,
    training_status ENUM('pending','training','paused','stopped','completed','failed') NOT NULL DEFAULT 'pending',
    progress DECIMAL(5,2) NOT NULL DEFAULT 0,
    estimated_remaining_seconds INT NULL,
    model_id BIGINT UNSIGNED NULL,
    accuracy_metrics JSON NULL,
    error_message TEXT NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_task_id (task_id),
    INDEX idx_user_id (user_id),
    INDEX idx_training_status (training_status),
    INDEX idx_training_data_file_id (training_data_file_id),
    INDEX idx_model_id (model_id),
    INDEX idx_created_at (created_at),
    CONSTRAINT fk_training_data_file FOREIGN KEY (training_data_file_id) REFERENCES files(id) ON DELETE SET NULL,
    CONSTRAINT fk_training_model FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE SET NULL,
    CONSTRAINT fk_training_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='训练任务表';

-- 创建 user_models 表
CREATE TABLE IF NOT EXISTS user_models (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    model_id BIGINT UNSIGNED NOT NULL,
    acquired_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active TINYINT(1) NULL DEFAULT 1,
    source ENUM('official','custom','market') NOT NULL DEFAULT 'custom',
    UNIQUE KEY unique_user_model (user_id, model_id),
    INDEX idx_user_id (user_id),
    INDEX idx_model_id (model_id),
    CONSTRAINT fk_user_models_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_models_model FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户模型关联表';

-- 创建 subscriptions 表
CREATE TABLE IF NOT EXISTS subscriptions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    subscription_id VARCHAR(64) UNIQUE NOT NULL COMMENT '订阅ID，格式：S+时间戳',
    user_id BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
    model_id BIGINT UNSIGNED NOT NULL COMMENT '模型ID',
    frequency ENUM('daily', 'weekly', 'monthly') NOT NULL DEFAULT 'weekly' COMMENT '检测频率：每天/每周/每月',
    threshold INT NULL DEFAULT NULL COMMENT '预警阈值（0-100）；NULL 表示使用默认阈值策略',
    official_file_id BIGINT UNSIGNED NULL COMMENT '官方域名文件ID（仅仿冒检测需要）',
    is_active TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否激活：1-激活，0-已取消',
    next_run_at DATETIME NOT NULL COMMENT '下次执行时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX idx_user_id (user_id),
    INDEX idx_model_id (model_id),
    INDEX idx_is_active (is_active),
    INDEX idx_next_run_at (next_run_at),
    INDEX idx_subscription_id (subscription_id),
    CONSTRAINT fk_subscriptions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_subscriptions_model_id FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE,
    CONSTRAINT fk_subscriptions_official_file_id FOREIGN KEY (official_file_id) REFERENCES files(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='订阅表';

-- 创建 alerts 表
CREATE TABLE IF NOT EXISTS alerts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(64) UNIQUE NOT NULL COMMENT '预警ID，格式：A+时间戳',
    subscription_id VARCHAR(64) NOT NULL COMMENT '订阅ID',
    task_id VARCHAR(64) NOT NULL COMMENT '关联的检测任务ID',
    user_id BIGINT UNSIGNED NOT NULL COMMENT '用户ID（冗余字段，便于查询）',
    model_id BIGINT UNSIGNED NOT NULL COMMENT '模型ID（冗余字段）',
    model_name VARCHAR(255) NOT NULL COMMENT '模型名称（冗余字段，避免关联查询）',
    task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity', 'apt_template_nrd') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史APT域名相似性检测/模板化APT域名检测',
    detected_count INT NOT NULL DEFAULT 0 COMMENT '检测到的域名总数',
    high_risk_count INT NOT NULL DEFAULT 0 COMMENT '高风险域名数量',
    high_risk_domains JSON NULL COMMENT '高风险域名列表（JSON数组）',
    threshold INT NULL COMMENT '触发预警的阈值；NULL 表示使用默认阈值策略',
    status ENUM('pending', 'processed') NOT NULL DEFAULT 'pending' COMMENT '处理状态：pending-未处理，processed-已处理',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX idx_subscription_id (subscription_id),
    INDEX idx_task_id (task_id),
    INDEX idx_user_id (user_id),
    INDEX idx_model_id (model_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_alert_id (alert_id),
    CONSTRAINT fk_alerts_subscription_id FOREIGN KEY (subscription_id) REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
    CONSTRAINT fk_alerts_task_id FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    CONSTRAINT fk_alerts_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_alerts_model_id FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='预警表';

-- 创建 alert_files 表
CREATE TABLE IF NOT EXISTS alert_files (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(64) NOT NULL COMMENT '预警业务ID',
    subscription_id VARCHAR(64) NOT NULL COMMENT '订阅业务ID',
    task_id VARCHAR(64) NOT NULL COMMENT '任务业务ID',
    user_id BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
    model_id BIGINT UNSIGNED NOT NULL COMMENT '模型ID',
    task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity', 'apt_template_nrd') NOT NULL COMMENT '任务类型',
    frequency ENUM('daily', 'weekly', 'monthly') NOT NULL COMMENT '订阅周期',
    file_id BIGINT UNSIGNED NOT NULL COMMENT '文件ID',
    file_role ENUM('full_result', 'report') NOT NULL DEFAULT 'full_result' COMMENT '文件角色',
    file_format ENUM('json') NOT NULL DEFAULT 'json' COMMENT '文件格式',
    domain_count INT NOT NULL DEFAULT 0 COMMENT '高风险域名数量',
    alert_date DATE NOT NULL COMMENT '预警日期',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    INDEX idx_alert_id (alert_id),
    INDEX idx_subscription_id (subscription_id),
    INDEX idx_task_id (task_id),
    INDEX idx_user_id (user_id),
    INDEX idx_model_id (model_id),
    INDEX idx_file_id (file_id),
    INDEX idx_alert_date (alert_date),
    CONSTRAINT fk_alert_files_alert_id FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
    CONSTRAINT fk_alert_files_file_id FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='预警文件索引表';

-- 创建域名持续监控目标表
CREATE TABLE IF NOT EXISTS domain_monitor_targets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
    domain VARCHAR(255) NOT NULL COMMENT '展示域名',
    normalized_domain VARCHAR(255) NOT NULL COMMENT '规范化域名',
    is_active TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用监控',
    monitor_interval_hours INT NOT NULL DEFAULT 24 COMMENT '监控间隔小时',
    next_check_at DATETIME NOT NULL COMMENT '下次检查时间',
    last_checked_at DATETIME NULL COMMENT '最近检查时间',
    status VARCHAR(32) NOT NULL DEFAULT 'pending' COMMENT '监控状态',
    consecutive_failures INT NOT NULL DEFAULT 0 COMMENT '连续失败次数',
    last_error TEXT NULL COMMENT '最近错误',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    UNIQUE KEY uniq_domain_monitor_user_domain (user_id, normalized_domain),
    INDEX idx_domain_monitor_user_id (user_id),
    INDEX idx_domain_monitor_domain (normalized_domain),
    INDEX idx_domain_monitor_due (is_active, next_check_at),
    INDEX idx_domain_monitor_status (status),
    CONSTRAINT fk_domain_monitor_targets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域名持续监控目标';

-- 创建域名持续监控来源表
CREATE TABLE IF NOT EXISTS domain_monitor_sources (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    target_id BIGINT UNSIGNED NOT NULL COMMENT '监控目标ID',
    source_type VARCHAR(32) NOT NULL COMMENT '来源类型：subscription_alert/detection_task/manual',
    task_id VARCHAR(64) NULL COMMENT '检测任务ID',
    task_type VARCHAR(64) NULL COMMENT '检测任务类型',
    model_id BIGINT UNSIGNED NULL COMMENT '模型ID',
    subscription_id VARCHAR(64) NULL COMMENT '订阅ID',
    alert_id VARCHAR(64) NULL COMMENT '预警ID',
    risk_score DECIMAL(10,6) NULL COMMENT '检测风险分',
    risk_level VARCHAR(32) NULL COMMENT '检测风险等级',
    risk_record JSON NULL COMMENT '检测来源记录',
    detected_at DATETIME NULL COMMENT '来源检测时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    INDEX idx_domain_monitor_source_target (target_id),
    INDEX idx_domain_monitor_source_type (source_type),
    INDEX idx_domain_monitor_source_task (task_id),
    INDEX idx_domain_monitor_source_alert (alert_id),
    INDEX idx_domain_monitor_source_subscription (subscription_id),
    INDEX idx_domain_monitor_source_model (model_id),
    CONSTRAINT fk_domain_monitor_sources_target FOREIGN KEY (target_id) REFERENCES domain_monitor_targets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域名监控来源';

-- 创建域名持续监控快照表
CREATE TABLE IF NOT EXISTS domain_monitor_snapshots (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    target_id BIGINT UNSIGNED NOT NULL COMMENT '监控目标ID',
    status VARCHAR(32) NOT NULL DEFAULT 'success' COMMENT '采集状态：success/partial/failed',
    collected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '采集时间',
    whois_snapshot JSON NULL COMMENT 'WHOIS快照',
    dns_snapshot JSON NULL COMMENT 'DNS快照',
    certificate_snapshot JSON NULL COMMENT '证书快照',
    web_snapshot JSON NULL COMMENT '网页快照',
    fingerprint_snapshot JSON NULL COMMENT '用于后续归因的版本化指纹快照',
    changed_fields JSON NULL COMMENT '与上次快照相比的变化字段',
    raw_lookup_errors JSON NULL COMMENT '原始查询错误',
    error_message TEXT NULL COMMENT '错误信息',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    INDEX idx_domain_monitor_snapshot_target (target_id),
    INDEX idx_domain_monitor_snapshot_collected (target_id, collected_at),
    INDEX idx_domain_monitor_snapshot_status (status),
    CONSTRAINT fk_domain_monitor_snapshots_target FOREIGN KEY (target_id) REFERENCES domain_monitor_targets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域名持续监控快照';
