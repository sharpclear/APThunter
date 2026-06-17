ALTER TABLE models
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity') DEFAULT NULL;

ALTER TABLE tasks
  MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity') NOT NULL COMMENT '任务类型';

ALTER TABLE training_tasks
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity') NOT NULL DEFAULT 'malicious';

ALTER TABLE alerts
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史高度相似检测';

ALTER TABLE alert_files
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity') NOT NULL COMMENT '任务类型';

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '历史高度相似检测模型',
  'v1.0',
  '基于历史恶意域名样本的字符相似度与重排序特征筛选模型',
  'dataset/history_data/训练黑数据.xlsx',
  NULL,
  JSON_OBJECT('note', '官方历史恶意域名相似性模型', 'default_min_score', 0.55),
  'official',
  'history_similarity',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1 FROM models
  WHERE model_category = 'history_similarity'
    AND model_type = 'official'
    AND status = 'active'
);

UPDATE models
SET
  name = '历史高度相似检测模型',
  model_path = 'dataset/history_data/训练黑数据.xlsx',
  description = '基于历史恶意域名样本的字符相似度与重排序特征筛选模型'
WHERE model_category = 'history_similarity'
  AND model_type = 'official';

INSERT IGNORE INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT u.id, m.id, NOW(), 1, 'official'
FROM users u
JOIN models m
  ON m.model_category = 'history_similarity'
 AND m.model_type = 'official'
 AND m.status = 'active';
