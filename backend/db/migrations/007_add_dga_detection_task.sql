ALTER TABLE models
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga') DEFAULT NULL;

ALTER TABLE tasks
  MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga') NOT NULL COMMENT '任务类型';

ALTER TABLE training_tasks
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga') NOT NULL DEFAULT 'malicious';

ALTER TABLE subscription_tasks
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测';

ALTER TABLE alert_records
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga') NOT NULL COMMENT '任务类型';

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '官方DGA域名检测模型',
  'v1.0',
  '用于DGA-like域名检测的官方Char-CNN模型',
  'saved_model/dga_cnn_detector.keras',
  NULL,
  JSON_OBJECT('note', '官方DGA Char-CNN模型'),
  'official',
  'dga',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1 FROM models
  WHERE model_category = 'dga'
    AND model_type = 'official'
    AND status = 'active'
);

INSERT IGNORE INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT u.id, m.id, NOW(), 1, 'official'
FROM users u
JOIN models m
  ON m.model_category = 'dga'
 AND m.model_type = 'official'
 AND m.status = 'active';
