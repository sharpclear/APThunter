UPDATE models
SET
  description = '用于DGA-like域名检测的官方二分类模型',
  model_path = 'saved_model/dga_binary_detector.joblib',
  accuracy_metrics = JSON_OBJECT(
    'note', '官方DGA二分类模型',
    'threshold', 0.90,
    'precision', 0.9000,
    'recall', 0.6206,
    'f1', 0.7347
  )
WHERE model_category = 'dga'
  AND model_type = 'official'
  AND status = 'active';
