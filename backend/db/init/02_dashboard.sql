-- ============================================
-- Dashboard 数据表初始化脚本
-- 包含：组织画像/时空分布/域名属性/数据展示
-- ============================================

-- ============================================
-- 组织画像 (Organization Profile)
-- ============================================
CREATE TABLE IF NOT EXISTS apt_organizations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE COMMENT '组织名称',
  alias JSON NULL COMMENT '别名列表',
  description TEXT NULL COMMENT '描述',
  ioc_count INT NOT NULL DEFAULT 0 COMMENT 'IOC数量',
  event_count INT NOT NULL DEFAULT 0 COMMENT '事件数量',
  update_time DATE NULL COMMENT '最后更新时间',
  region VARCHAR(64) NULL COMMENT '所属地区',
  origin VARCHAR(128) NULL COMMENT '来源国家',
  target_countries JSON NULL COMMENT '目标国家',
  target_industries JSON NULL COMMENT '目标行业',
  previous_domains JSON NULL COMMENT '曾用域名',
  vps_providers JSON NULL COMMENT 'VPS服务商分布',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_region (region),
  INDEX idx_update_time (update_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='APT组织信息';

-- ============================================
-- 时空分布 (Spatio-Temporal Distribution)
-- ============================================
CREATE TABLE IF NOT EXISTS apt_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_date DATE NOT NULL COMMENT '事件日期',
  title VARCHAR(255) NOT NULL COMMENT '事件标题',
  description TEXT NULL COMMENT '事件描述',
  report_url VARCHAR(1024) NULL COMMENT '事件报告链接',
  event_type ENUM('major','normal') NOT NULL DEFAULT 'normal' COMMENT '事件类型',
  region VARCHAR(64) NULL COMMENT '发生地区',
  latitude DECIMAL(10,7) NULL COMMENT '纬度',
  longitude DECIMAL(10,7) NULL COMMENT '经度',
  organization_id INT NULL COMMENT '关联组织ID',
  severity INT NULL DEFAULT 1 COMMENT '严重程度(1-5)',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organization_id) REFERENCES apt_organizations(id) ON DELETE SET NULL,
  INDEX idx_event_date (event_date),
  INDEX idx_region (region),
  INDEX idx_organization (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='APT事件时空分布';

-- 地区事件统计（预聚合表，提升查询性能）
CREATE TABLE IF NOT EXISTS region_event_stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  stat_date DATE NOT NULL COMMENT '统计日期',
  region VARCHAR(64) NOT NULL COMMENT '地区',
  event_count INT NOT NULL DEFAULT 0 COMMENT '事件数量',
  major_count INT NOT NULL DEFAULT 0 COMMENT '重大事件数',
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_date_region (stat_date, region)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='地区事件统计';

-- ============================================
-- 域名属性 (Domain Attributes)
-- ============================================
CREATE TABLE IF NOT EXISTS domains (
  id INT AUTO_INCREMENT PRIMARY KEY,
  domain_name VARCHAR(255) NOT NULL UNIQUE COMMENT '域名',
  is_malicious TINYINT(1) DEFAULT 0 COMMENT '是否恶意',
  first_seen DATE NULL COMMENT '首次发现',
  last_seen DATE NULL COMMENT '最后发现',
  organization_id INT NULL COMMENT '关联组织ID',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organization_id) REFERENCES apt_organizations(id) ON DELETE SET NULL,
  INDEX idx_domain (domain_name),
  INDEX idx_malicious (is_malicious),
  INDEX idx_organization (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域名基础信息';

CREATE TABLE IF NOT EXISTS whois_info (
  id INT AUTO_INCREMENT PRIMARY KEY,
  domain_id INT NOT NULL COMMENT '域名ID',
  registrar VARCHAR(255) NULL COMMENT '注册商',
  registration_date DATE NULL COMMENT '注册日期',
  expiration_date DATE NULL COMMENT '过期日期',
  updated_date DATE NULL COMMENT '更新日期',
  name_servers JSON NULL COMMENT '名称服务器',
  registrant JSON NULL COMMENT '注册人信息',
  admin JSON NULL COMMENT '管理员信息',
  tech JSON NULL COMMENT '技术联系人',
  status JSON NULL COMMENT '域名状态',
  raw_text TEXT NULL COMMENT '原始WHOIS文本',
  query_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '查询时间',
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  INDEX idx_domain (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='WHOIS信息';

CREATE TABLE IF NOT EXISTS dns_records (
  id INT AUTO_INCREMENT PRIMARY KEY,
  domain_id INT NOT NULL COMMENT '域名ID',
  record_type VARCHAR(16) NOT NULL COMMENT '记录类型(A/AAAA/CNAME/MX/TXT等)',
  record_name VARCHAR(255) NOT NULL COMMENT '记录名',
  record_value TEXT NOT NULL COMMENT '记录值',
  ttl INT NULL COMMENT 'TTL',
  priority INT NULL COMMENT '优先级(MX记录)',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  INDEX idx_domain (domain_id),
  INDEX idx_type (record_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='DNS记录';

CREATE TABLE IF NOT EXISTS ssl_certificates (
  id INT AUTO_INCREMENT PRIMARY KEY,
  domain_id INT NOT NULL COMMENT '域名ID',
  issuer JSON NULL COMMENT '颁发者信息',
  subject JSON NULL COMMENT '主题信息',
  serial_number VARCHAR(128) NULL COMMENT '序列号',
  fingerprint VARCHAR(256) NULL COMMENT '指纹',
  not_before DATETIME NULL COMMENT '有效期开始',
  not_after DATETIME NULL COMMENT '有效期结束',
  algorithm VARCHAR(64) NULL COMMENT '算法',
  key_size INT NULL COMMENT '密钥长度',
  san_names JSON NULL COMMENT 'SAN域名列表',
  is_expired TINYINT(1) DEFAULT 0 COMMENT '是否过期',
  is_self_signed TINYINT(1) DEFAULT 0 COMMENT '是否自签名',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  INDEX idx_domain (domain_id),
  INDEX idx_expired (is_expired)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='SSL证书信息';

-- ============================================
-- 数据展示 (Data Display Dashboard)
-- ============================================
CREATE TABLE IF NOT EXISTS threat_statistics (
  id INT AUTO_INCREMENT PRIMARY KEY,
  stat_date DATE NOT NULL COMMENT '统计日期',
  total_organizations INT DEFAULT 0 COMMENT '组织总数',
  total_events INT DEFAULT 0 COMMENT '事件总数',
  total_domains INT DEFAULT 0 COMMENT '域名总数',
  total_iocs INT DEFAULT 0 COMMENT 'IOC总数',
  active_threats INT DEFAULT 0 COMMENT '活跃威胁数',
  new_threats_today INT DEFAULT 0 COMMENT '今日新增威胁',
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_stat_date (stat_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='威胁统计数据';

CREATE TABLE IF NOT EXISTS threat_trends (
  id INT AUTO_INCREMENT PRIMARY KEY,
  trend_date DATE NOT NULL COMMENT '日期',
  dns_tunnel_count INT DEFAULT 0 COMMENT 'DNS隧道检测数',
  dga_domain_count INT DEFAULT 0 COMMENT 'DGA域名数',
  phishing_count INT DEFAULT 0 COMMENT '钓鱼攻击数',
  c2_communication INT DEFAULT 0 COMMENT 'C2通信数',
  malware_count INT DEFAULT 0 COMMENT '恶意软件数',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_trend_date (trend_date),
  INDEX idx_date (trend_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='威胁趋势数据';

CREATE TABLE IF NOT EXISTS attack_sources (
  id INT AUTO_INCREMENT PRIMARY KEY,
  country VARCHAR(64) NOT NULL COMMENT '攻击来源国家',
  attack_count INT DEFAULT 0 COMMENT '攻击次数',
  last_attack_date DATE NULL COMMENT '最后攻击日期',
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_country (country),
  INDEX idx_count (attack_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='攻击来源统计';
