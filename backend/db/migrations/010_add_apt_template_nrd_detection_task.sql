ALTER TABLE models
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd') DEFAULT NULL;

ALTER TABLE tasks
  MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity','apt_template_nrd') NOT NULL COMMENT '任务类型';

ALTER TABLE training_tasks
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd') NOT NULL DEFAULT 'malicious';

ALTER TABLE alerts
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity', 'apt_template_nrd') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史高度相似检测/APT模板新注册域名检测';

ALTER TABLE alert_files
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity', 'apt_template_nrd') NOT NULL COMMENT '任务类型';

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  'APT模板新注册域名检测模型',
  'v1.0',
  '基于APT注册模板库匹配新注册域名的官方规则模型',
  'dataset/APTdomains/疑似模板化注册域名_筛选结果.xlsx',
  NULL,
  JSON_OBJECT('note', '官方APT模板新注册域名匹配模型', 'default_score_threshold', 0.90),
  'official',
  'apt_template_nrd',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1 FROM models
  WHERE model_category = 'apt_template_nrd'
    AND model_type = 'official'
    AND status = 'active'
);

UPDATE models
SET
  name = 'APT模板新注册域名检测模型',
  model_path = 'dataset/APTdomains/疑似模板化注册域名_筛选结果.xlsx',
  description = '基于APT注册模板库匹配新注册域名的官方规则模型',
  accuracy_metrics = JSON_OBJECT('note', '官方APT模板新注册域名匹配模型', 'default_score_threshold', 0.90)
WHERE model_category = 'apt_template_nrd'
  AND model_type = 'official';

INSERT IGNORE INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT u.id, m.id, NOW(), 1, 'official'
FROM users u
JOIN models m
  ON m.model_category = 'apt_template_nrd'
 AND m.model_type = 'official'
 AND m.status = 'active';
