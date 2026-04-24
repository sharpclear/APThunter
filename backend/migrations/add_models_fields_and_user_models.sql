-- 迁移脚本：为models表添加字段并创建user_models表
-- 执行时间：请在执行前备份数据库

-- 1. 为models表添加created_at字段
ALTER TABLE models 
ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP 
AFTER status;

-- 2. 为models表添加model_category字段（模型类型：恶意性检测/仿冒域名检测）
ALTER TABLE models 
ADD COLUMN model_category ENUM('malicious', 'impersonation') NULL 
AFTER model_type;

-- 3. 为models表添加updated_at字段（可选，用于记录更新时间）
ALTER TABLE models 
ADD COLUMN updated_at DATETIME NULL DEFAULT NULL 
ON UPDATE CURRENT_TIMESTAMP 
AFTER created_at;

-- 4. 创建user_models表（用户模型关联表）
CREATE TABLE IF NOT EXISTS user_models (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL,
    model_id INT NOT NULL,
    acquired_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active TINYINT(1) DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY unique_user_model (user_id, model_id),
    KEY idx_user_id (user_id),
    KEY idx_model_id (model_id),
    CONSTRAINT fk_user_models_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_models_model FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
