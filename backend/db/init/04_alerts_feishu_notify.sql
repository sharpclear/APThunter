-- 预警表增加飞书推送幂等字段（新环境随 init 执行；已有库若未执行请用 migrations/002_alerts_feishu_notify.sql）
ALTER TABLE alerts
  ADD COLUMN feishu_notified TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否已成功推送飞书' AFTER status,
  ADD COLUMN feishu_notified_at DATETIME NULL COMMENT '飞书推送成功时间' AFTER feishu_notified;
