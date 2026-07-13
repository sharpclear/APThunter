-- ============================================
-- 核心业务种子数据（最小可运行）
-- 说明：
-- 1) 本脚本设计为幂等执行（重复执行不会产生重复数据）
-- 2) 默认管理员账号：admin / admin（上线前请立即修改）
-- ============================================

SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- 1) 创建默认管理员用户
INSERT INTO users (username, password_hash, email, bio)
SELECT
  'admin',
  '$pbkdf2-sha256$29000$W4tx7p2TMuYcw5hTam0tpQ$kKFKnqLRKgkOtw/s107YASzK8k1YsPmh8jX0fmVYFlA',
  'admin@apthunter.local',
  'System seeded administrator'
WHERE NOT EXISTS (
  SELECT 1 FROM users WHERE username = 'admin'
);

-- 2) 创建官方模型（仿冒检测 + DGA检测 + 历史APT域名相似性检测 + 模板化APT域名检测）

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '官方仿冒检测模型',
  'v1.0',
  '用于仿冒域名检测的官方基线模型',
  NULL,
  NULL,
  JSON_OBJECT('note', '官方基线种子模型'),
  'official',
  'impersonation',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1
  FROM models
  WHERE name = '官方仿冒检测模型'
    AND version = 'v1.0'
    AND model_type = 'official'
);

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '官方DGA域名检测模型',
  'v2.0',
  '用于高置信DGA域名检测与DGA家族识别的官方本地模型',
  'saved_model/dga_detection_local_model',
  NULL,
  JSON_OBJECT(
    'note', '官方DGA本地交付模型：主检测模型 + Sequence GRU家族识别',
    'direct_high_confidence_threshold', 0.98,
    'family_input_threshold', 0.90,
    'family_confidence_threshold', 0.95,
    'precision_at_training_threshold', 0.9000,
    'recall_at_training_threshold', 0.6206,
    'f1_at_training_threshold', 0.7347
  ),
  'official',
  'dga',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1
  FROM models
  WHERE name = '官方DGA域名检测模型'
    AND version = 'v2.0'
    AND model_type = 'official'
);

INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '历史APT域名相似性检测模型',
  'v1.0',
  '基于历史恶意域名样本的字符相似度与重排序特征筛选模型',
  'dataset/history_data/训练黑数据.xlsx',
  NULL,
  JSON_OBJECT('note', '官方历史APT域名相似性种子模型', 'default_min_score', 0.65),
  'official',
  'history_similarity',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1
  FROM models
  WHERE model_category = 'history_similarity'
    AND model_type = 'official'
    AND status = 'active'
);

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
  SELECT 1
  FROM models
  WHERE name = '模板化APT域名检测模型'
    AND version = 'v1.0'
    AND model_type = 'official'
);

-- 3) 绑定管理员与官方模型（仅激活可用模型）
INSERT INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT
  u.id,
  m.id,
  NOW(),
  1,
  'official'
FROM users u
JOIN models m
  ON m.model_type = 'official'
 AND m.status = 'active'
WHERE u.username = 'admin'
  AND NOT EXISTS (
    SELECT 1
    FROM user_models um
    WHERE um.user_id = u.id
      AND um.model_id = m.id
  );
