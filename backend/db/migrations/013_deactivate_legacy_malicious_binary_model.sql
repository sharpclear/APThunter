-- 停用旧“恶意性检测”二分类官方模型。
-- 统一恶意域名检测由仿冒、DGA、历史APT相似、模板化APT四个模块共同完成。

UPDATE models
SET status = 'inactive'
WHERE model_category = 'malicious'
  AND name = '官方恶意检测模型'
  AND model_type = 'official';

UPDATE user_models um
JOIN models m ON um.model_id = m.id
SET um.is_active = 0
WHERE m.model_category = 'malicious'
  AND m.name = '官方恶意检测模型'
  AND m.model_type = 'official';
