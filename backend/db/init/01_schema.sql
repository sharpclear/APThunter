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
    model_category ENUM('malicious','impersonation') NULL,
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
    task_type ENUM('malicious','impersonation') NOT NULL,
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
    model_category ENUM('malicious','impersonation') NOT NULL DEFAULT 'malicious',
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
    threshold INT NOT NULL DEFAULT 60 COMMENT '预警阈值（0-100）',
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
    task_type ENUM('malicious', 'impersonation') NOT NULL COMMENT '任务类型：恶意性检测/仿冒域名检测',
    detected_count INT NOT NULL DEFAULT 0 COMMENT '检测到的域名总数',
    high_risk_count INT NOT NULL DEFAULT 0 COMMENT '高风险域名数量',
    high_risk_domains JSON NULL COMMENT '高风险域名列表（JSON数组）',
    threshold INT NOT NULL COMMENT '触发预警的阈值',
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
