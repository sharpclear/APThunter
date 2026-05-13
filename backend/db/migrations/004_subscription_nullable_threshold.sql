-- threshold=NULL 表示使用订阅检测默认阈值策略：
-- - malicious：模型判为恶意的结果全部作为预警对象
-- - impersonation：使用普通仿冒检测的自适应相似度阈值
ALTER TABLE subscriptions
  MODIFY COLUMN threshold INT NULL DEFAULT NULL;

ALTER TABLE alerts
  MODIFY COLUMN threshold INT NULL DEFAULT NULL;
