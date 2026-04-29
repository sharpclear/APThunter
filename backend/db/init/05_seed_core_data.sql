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

-- 2) 创建官方模型（恶意检测 + 仿冒检测）
-- 注意：malicious 模型需要确保 model_path 指向的文件在容器内可读取，否则执行恶意检测时会报模型文件不存在。
INSERT INTO models (
  name, version, description, model_path, file_size, accuracy_metrics,
  model_type, model_category, is_public, is_official, created_by, status
)
SELECT
  '官方恶意检测模型',
  'v1.0',
  '用于恶意域名检测的官方基线模型',
  'saved_model/svm_model2.pkl',
  NULL,
  JSON_OBJECT('note', '官方基线种子模型'),
  'official',
  'malicious',
  1,
  1,
  'system',
  'active'
WHERE NOT EXISTS (
  SELECT 1
  FROM models
  WHERE name = '官方恶意检测模型'
    AND version = 'v1.0'
    AND model_type = 'official'
);

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
