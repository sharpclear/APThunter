-- 将组织关联匹配方法默认值切换为 rule_v2_infra。
-- 业务代码会显式写入 match_method；此迁移用于对齐直接插表或旧环境的数据库默认值。
ALTER TABLE alert_domain_matches
  ALTER COLUMN match_method SET DEFAULT 'rule_v2_infra';
