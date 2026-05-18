-- Add malicious_ip as a reserved task type for future malicious IP detection tasks.
ALTER TABLE tasks
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip') NOT NULL;

ALTER TABLE alerts
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测';

ALTER TABLE alert_files
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip') NOT NULL COMMENT '任务类型';
