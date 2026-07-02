ALTER TABLE alerts
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity', 'apt_template_nrd') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史高度相似检测/模板化APT域名检测';

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '模板化APT域名检测模型',
  'v1.0',
  '基于模板化APT域名模板库匹配待检测域名的官方规则模型',
  'dataset/history_data/APTdomain_templates.xlsx',
  NULL,
  JSON_OBJECT('note', '官方模板化APT域名匹配模型', 'template_source', 'dataset/history_data/APTdomain_templates.xlsx', 'default_score_threshold', 0.90),
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
  name = '模板化APT域名检测模型',
  model_path = 'dataset/history_data/APTdomain_templates.xlsx',
  description = '基于模板化APT域名模板库匹配待检测域名的官方规则模型',
  accuracy_metrics = JSON_OBJECT('note', '官方模板化APT域名匹配模型', 'template_source', 'dataset/history_data/APTdomain_templates.xlsx', 'default_score_threshold', 0.90),
  is_public = 1,
  is_official = 1,
  status = 'active'
WHERE model_category = 'apt_template_nrd'
  AND model_type = 'official';

INSERT IGNORE INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT u.id, m.id, NOW(), 1, 'official'
FROM users u
JOIN models m
  ON m.model_category = 'apt_template_nrd'
 AND m.model_type = 'official'
 AND m.status = 'active';
