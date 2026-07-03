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
