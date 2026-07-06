-- 迁移：将官方 DGA 模型切换为本地交付版（主模型 + Sequence GRU 家族识别）
-- 说明：复用已有 dga model_category/task_type，不新增数据库枚举。

UPDATE models
SET
  version = 'v2.0',
  description = '用于高置信DGA域名检测与DGA家族识别的官方本地模型',
  model_path = 'saved_model/dga_detection_local_model',
  accuracy_metrics = JSON_OBJECT(
    'note', '官方DGA本地交付模型：主检测模型 + Sequence GRU家族识别',
    'direct_high_confidence_threshold', 0.98,
    'family_input_threshold', 0.90,
    'family_confidence_threshold', 0.95,
    'precision_at_training_threshold', 0.9000,
    'recall_at_training_threshold', 0.6206,
    'f1_at_training_threshold', 0.7347
  )
WHERE model_category = 'dga'
  AND model_type = 'official'
  AND status = 'active';

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
  WHERE model_category = 'dga'
    AND model_type = 'official'
    AND status = 'active'
);

INSERT INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT
  u.id,
  m.id,
  NOW(),
  1,
  'official'
FROM users u
JOIN models m
  ON m.model_category = 'dga'
 AND m.model_type = 'official'
 AND m.status = 'active'
WHERE NOT EXISTS (
  SELECT 1
  FROM user_models um
  WHERE um.user_id = u.id
    AND um.model_id = m.id
);
