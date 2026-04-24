-- ============================================
-- Dashboard 示例数据
-- 用于测试和演示系统功能
-- ============================================

SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- ============================================
-- APT 组织数据（扩充至覆盖更多地区）
-- ============================================
INSERT INTO apt_organizations (id, name, alias, description, ioc_count, event_count, update_time, region, origin, target_countries, target_industries, previous_domains, vps_providers) VALUES
(1, 'APT28', '["Fancy Bear", "Sofacy", "Sednit"]', '俄罗斯高级持续性威胁组织，主要针对政府和军事目标', 156, 43, '2025-12-20', '东欧', '俄罗斯', '["美国", "英国", "德国", "乌克兰"]', '["政府", "军事", "国防", "外交"]', '["sofacy-news.com", "kremlin-news.info"]', '[{"provider": "DigitalOcean", "count": 68, "percentage": 43.6}, {"provider": "Vultr", "count": 45, "percentage": 28.8}, {"provider": "Linode", "count": 28, "percentage": 17.9}, {"provider": "其他", "count": 15, "percentage": 9.6}]'),
(2, 'APT29', '["Cozy Bear", "The Dukes"]', '疑似与俄罗斯情报机构相关的APT组织', 124, 31, '2025-11-18', '东欧', '俄罗斯', '["美国", "英国", "挪威"]', '["政府", "智库", "医疗"]', '["cozy-portal.com"]', '[{"provider": "AWS", "count": 62, "percentage": 50.0}, {"provider": "Azure", "count": 50, "percentage": 40.3}, {"provider": "其他", "count": 12, "percentage": 9.7}]'),
(3, 'APT41', '["Double Dragon", "Winnti"]', '中国背景的双重任务APT组织，同时进行间谍活动和经济犯罪', 203, 57, '2025-10-22', '东亚', '中国', '["美国", "日本", "韩国", "印度"]', '["科技", "游戏", "医疗", "电信"]', '["game-update.net", "software-cdn.com"]', '[{"provider": "Alibaba Cloud", "count": 90, "percentage": 44.3}, {"provider": "Tencent Cloud", "count": 70, "percentage": 34.5}, {"provider": "其他", "count": 43, "percentage": 21.2}]'),
(4, 'Lazarus Group', '["Hidden Cobra", "ZINC"]', '朝鲜国家支持的APT组织，以金融攻击和破坏性活动著称', 178, 48, '2025-09-19', '东亚', '朝鲜', '["韩国", "美国", "日本", "新加坡"]', '["金融", "加密货币", "媒体"]', '["swift-update.org", "bank-security.net"]', '[{"provider": "Choopa", "count": 71, "percentage": 39.9}, {"provider": "LeaseWeb", "count": 45, "percentage": 25.3}, {"provider": "OVH", "count": 38, "percentage": 21.3}, {"provider": "其他", "count": 24, "percentage": 13.5}]'),
(5, 'APT34', '["OilRig", "Helix Kitten"]', '伊朗APT组织，专注于中东地区的能源和金融行业', 98, 26, '2025-08-15', '中东', '伊朗', '["沙特阿拉伯", "阿联酋", "科威特"]', '["能源", "金融", "政府"]', '["energy-portal.com"]', '[{"provider": "Private VPS", "count": 78, "percentage": 79.6}, {"provider": "其他", "count": 20, "percentage": 20.4}]'),
(6, 'APT33', '["Elfin", "Magnallium"]', '伊朗背景的APT组织，针对航空航天和能源行业', 87, 22, '2025-07-12', '中东', '伊朗', '["美国", "韩国", "沙特阿拉伯"]', '["航空航天", "能源", "化工"]', '["aerospace-news.com"]', '[{"provider": "Private VPS", "count": 70, "percentage": 80.5}, {"provider": "其他", "count": 17, "percentage": 19.5}]'),
(7, 'APT10', '["Stone Panda", "MenuPass"]', '中国APT组织，专注于大规模数据窃取', 145, 38, '2025-06-21', '东亚', '中国', '["美国", "欧洲", "日本"]', '["科技", "通信", "制造业"]', '["cloud-service.net"]', '[{"provider": "Alibaba Cloud", "count": 58, "percentage": 40.0}, {"provider": "DigitalOcean", "count": 45, "percentage": 31.0}, {"provider": "Vultr", "count": 28, "percentage": 19.3}, {"provider": "其他", "count": 14, "percentage": 9.7}]'),
(8, 'FIN7', '["Carbanak"]', '以金融犯罪为目标的威胁组织', 112, 29, '2025-05-17', '东欧', '俄罗斯/乌克兰', '["美国", "欧盟", "澳大利亚"]', '["零售", "餐饮", "酒店"]', '["payment-secure.com"]', '[{"provider": "Bulletproof hosting", "count": 89, "percentage": 79.5}, {"provider": "其他", "count": 23, "percentage": 20.5}]'),
(9, 'Turla', '["Snake", "Uroburos"]', '俄罗斯高级威胁组织，针对政府和外交机构', 134, 35, '2025-04-10', '欧洲', '俄罗斯', '["德国", "法国", "英国"]', '["政府", "外交", "军事"]', '["turla-backdoor.net"]', '[{"provider": "Hetzner", "count": 70, "percentage": 52.2}, {"provider": "OVH", "count": 45, "percentage": 33.6}, {"provider": "其他", "count": 19, "percentage": 14.2}]'),
(10, 'Kimsuky', '["Velvet Chollima"]', '朝鲜APT组织，专注于情报收集', 95, 28, '2025-03-25', '东亚', '朝鲜', '["韩国", "美国"]', '["政府", "智库", "教育"]', '["kimsuky-phish.com"]', '[{"provider": "Choopa", "count": 55, "percentage": 57.9}, {"provider": "其他", "count": 40, "percentage": 42.1}]'),
(11, 'Sandworm', '["VooDoo Bear"]', '俄罗斯APT组织，针对关键基础设施', 167, 42, '2025-02-14', '东欧', '俄罗斯', '["乌克兰", "波兰", "格鲁吉亚"]', '["能源", "通信", "工控"]', '["sandworm-ics.com"]', '[{"provider": "Private VPS", "count": 120, "percentage": 71.9}, {"provider": "其他", "count": 47, "percentage": 28.1}]'),
(12, 'MuddyWater', '["SeedWorm"]', '伊朗威胁组织，针对中东和亚洲', 118, 32, '2025-01-20', '中东', '伊朗', '["伊拉克", "沙特", "土耳其"]', '["电信", "政府"]', '["muddywater-c2.net"]', '[{"provider": "Private VPS", "count": 95, "percentage": 80.5}, {"provider": "其他", "count": 23, "percentage": 19.5}]'),
(13, 'Ocean Lotus', '["APT32"]', '越南APT组织，针对东南亚地区', 142, 37, '2024-12-18', '东南亚', '越南', '["菲律宾", "老挝", "柬埔寨"]', '["政府", "媒体", "制造业"]', '["oceanlotus.net"]', '[{"provider": "DigitalOcean", "count": 75, "percentage": 52.8}, {"provider": "Vultr", "count": 50, "percentage": 35.2}, {"provider": "其他", "count": 17, "percentage": 12.0}]'),
(14, 'Machete', '["El Machete"]', '拉美APT组织，针对南美政府机构', 89, 24, '2024-11-22', '南美洲', '未知', '["委内瑞拉", "厄瓜多尔", "哥伦比亚"]', '["政府", "军事"]', '["machete-apt.com"]', '[{"provider": "AWS", "count": 50, "percentage": 56.2}, {"provider": "其他", "count": 39, "percentage": 43.8}]'),
(15, 'Patchwork', '["Dropping Elephant"]', '南亚APT组织，针对政府和智库', 76, 21, '2024-10-15', '南亚', '印度', '["巴基斯坦", "中国", "孟加拉"]', '["政府", "军事", "智库"]', '["patchwork-apt.net"]', '[{"provider": "DigitalOcean", "count": 40, "percentage": 52.6}, {"provider": "Linode", "count": 28, "percentage": 36.8}, {"provider": "其他", "count": 8, "percentage": 10.6}]'),
(16, 'Molerats', '["Gaza Cybergang"]', '中东APT组织，针对以色列及周边', 68, 19, '2024-09-10', '中东', '巴勒斯坦', '["以色列", "埃及", "约旦"]', '["政府", "金融", "媒体"]', '["molerats.net"]', '[{"provider": "Private VPS", "count": 52, "percentage": 76.5}, {"provider": "其他", "count": 16, "percentage": 23.5}]'),
(17, 'Sidewinder', '["Rattlesnake"]', '南亚APT组织，针对邻国', 105, 29, '2024-08-05', '南亚', '印度', '["巴基斯坦", "中国", "阿富汗"]', '["军事", "政府"]', '["sidewinder-apt.com"]', '[{"provider": "AWS", "count": 60, "percentage": 57.1}, {"provider": "Azure", "count": 35, "percentage": 33.3}, {"provider": "其他", "count": 10, "percentage": 9.6}]'),
(18, 'Donot Team', '["APT-C-35"]', '南亚威胁组织，针对巴基斯坦和克什米尔', 92, 25, '2024-07-18', '南亚', '印度', '["巴基斯坦", "克什米尔"]', '["政府", "军事", "外交"]', '["donot-apt.net"]', '[{"provider": "DigitalOcean", "count": 50, "percentage": 54.3}, {"provider": "Vultr", "count": 32, "percentage": 34.8}, {"provider": "其他", "count": 10, "percentage": 10.9}]'),
(19, 'DarkHotel', '["Tapaoux"]', '韩国APT组织，针对商务人士', 128, 34, '2024-06-12', '东亚', '韩国', '["日本", "中国", "美国"]', '["商务", "高管", "政府"]', '["darkhotel.net"]', '[{"provider": "AWS", "count": 75, "percentage": 58.6}, {"provider": "Azure", "count": 40, "percentage": 31.3}, {"provider": "其他", "count": 13, "percentage": 10.1}]'),
(20, 'Charming Kitten', '["APT35", "Phosphorus"]', '伊朗APT组织，针对学术和政府机构', 113, 31, '2024-05-08', '中东', '伊朗', '["美国", "以色列", "英国"]', '["学术", "政府", "智库"]', '["charmingkitten.net"]', '[{"provider": "Private VPS", "count": 85, "percentage": 75.2}, {"provider": "其他", "count": 28, "percentage": 24.8}]'),
(21, 'Silver Sparrow', '["SS-APT"]', '北美洲活动的APT组织，重点针对云服务与金融行业', 102, 27, '2025-11-03', '北美洲', '美国', '["美国", "加拿大"]', '["云服务", "金融"]', '["silver-sparrow.net"]', '[{"provider": "AWS", "count": 48, "percentage": 47.1}, {"provider": "Azure", "count": 32, "percentage": 31.4}, {"provider": "其他", "count": 22, "percentage": 21.5}]'),
(22, 'Desert Lynx', '["DL-APT"]', '非洲地区活跃的APT组织，主要针对电信与政府部门', 76, 19, '2025-11-12', '非洲', '未知', '["埃及", "肯尼亚", "南非"]', '["电信", "政府"]', '["desert-lynx.org"]', '[{"provider": "AWS", "count": 30, "percentage": 39.5}, {"provider": "OVH", "count": 24, "percentage": 31.6}, {"provider": "其他", "count": 22, "percentage": 28.9}]'),
(23, 'Coral Reef', '["CR-APT"]', '大洋洲地区活跃的APT组织，主要针对能源与海事行业', 64, 15, '2025-11-20', '大洋洲', '澳大利亚', '["澳大利亚", "新西兰"]', '["能源", "海事"]', '["coral-reef.net"]', '[{"provider": "Azure", "count": 26, "percentage": 40.6}, {"provider": "AWS", "count": 20, "percentage": 31.2}, {"provider": "其他", "count": 18, "percentage": 28.2}]'),
(24, 'Ghost Orchid', '["GO-APT"]', '来源不明的APT组织，活动区域尚未确认', 58, 12, '2025-11-26', '未知', '未知', '[]', '[]', '["ghost-orchid.cc"]', '[{"provider": "其他", "count": 58, "percentage": 100.0}]');

-- ============================================
-- APT 事件数据（覆盖全年）
-- ============================================
INSERT INTO apt_events (id, event_date, title, description, event_type, region, latitude, longitude, organization_id, severity) VALUES
-- 2025年1-3月事件
(1, '2025-01-08', 'MuddyWater 针对沙特电信攻击', 'MuddyWater组织对沙特电信基础设施发起攻击', 'major', '中东', 24.7136, 46.6753, 12, 5),
(2, '2025-01-20', 'APT28 针对德国政府渗透', 'APT28对德国联邦政府网络进行长期渗透', 'major', '欧洲', 52.5200, 13.4050, 1, 5),
(3, '2025-02-05', 'Sandworm 乌克兰电网攻击', 'Sandworm针对乌克兰电力系统的破坏性攻击', 'major', '东欧', 50.4501, 30.5234, 11, 5),
(4, '2025-02-14', 'Ocean Lotus 菲律宾政府入侵', 'Ocean Lotus对菲律宾政府机构发起网络攻击', 'normal', '东南亚', 14.5995, 120.9842, 13, 4),
(5, '2025-03-10', 'Kimsuky 韩国智库钓鱼攻击', 'Kimsuky针对韩国智库的钓鱼邮件攻击活动', 'normal', '东亚', 37.5665, 126.9780, 10, 3),
(6, '2025-03-22', 'Turla 法国外交部渗透', 'Turla组织对法国外交部网络的长期潜伏', 'major', '欧洲', 48.8566, 2.3522, 9, 5),
-- 2025年4-6月事件
(7, '2025-04-05', 'Charming Kitten 美国学术机构攻击', 'Charming Kitten针对美国大学研究机构的钓鱼活动', 'normal', '北美', 40.7128, -74.0060, 20, 3),
(8, '2025-04-18', 'Machete 委内瑞拉军方入侵', 'Machete针对委内瑞拉军方系统的间谍活动', 'major', '南美洲', 10.4806, -66.9036, 14, 4),
(9, '2025-05-07', 'FIN7 欧洲酒店业攻击', 'FIN7针对欧洲多家连锁酒店的POS系统攻击', 'normal', '欧洲', 51.5074, -0.1278, 8, 3),
(10, '2025-05-20', 'DarkHotel 日本商务酒店攻击', 'DarkHotel在日本高端商务酒店部署间谍软件', 'normal', '东亚', 35.6762, 139.6503, 19, 4),
(11, '2025-06-12', 'Sidewinder 巴基斯坦军方攻击', 'Sidewinder针对巴基斯坦军方的网络间谍活动', 'major', '南亚', 33.6844, 73.0479, 17, 5),
(12, '2025-06-25', 'APT10 美国云服务商供应链攻击', 'APT10通过云服务商对多家企业发起供应链攻击', 'major', '北美', 37.7749, -122.4194, 7, 5),
-- 2025年7-9月事件
(13, '2025-07-08', 'Donot Team 克什米尔政府攻击', 'Donot Team针对克什米尔地方政府的网络攻击', 'normal', '南亚', 34.0837, 74.7973, 18, 3),
(14, '2025-07-18', 'APT33 韩国航空航天攻击', 'APT33针对韩国航空航天企业的工业间谍活动', 'major', '东亚', 37.5665, 126.9780, 6, 4),
(15, '2025-08-05', 'Molerats 以色列金融机构攻击', 'Molerats对以色列多家银行发起网络攻击', 'normal', '中东', 31.7683, 35.2137, 16, 3),
(16, '2025-08-22', 'APT34 阿联酋能源公司入侵', 'APT34针对阿联酋石油公司的长期渗透', 'major', '中东', 24.4539, 54.3773, 5, 5),
(17, '2025-09-10', 'Patchwork 孟加拉政府机构攻击', 'Patchwork针对孟加拉国政府机构的间谍活动', 'normal', '南亚', 23.8103, 90.4125, 15, 3),
(18, '2025-09-28', 'Lazarus 日本加密货币交易所攻击', 'Lazarus Group对日本大型加密货币交易所的攻击', 'major', '东亚', 35.6762, 139.6503, 4, 5),
-- 2025年10-12月事件
(19, '2025-10-10', 'APT41 印度电信运营商入侵', 'APT41对印度电信运营商的大规模数据窃取', 'major', '南亚', 28.7041, 77.1025, 3, 4),
(20, '2025-10-25', 'Ocean Lotus 柬埔寨政府渗透', 'Ocean Lotus针对柬埔寨政府网络的长期潜伏', 'normal', '东南亚', 11.5564, 104.9282, 13, 4),
(21, '2025-11-08', 'APT29 挪威外交部攻击', 'APT29针对挪威外交部的网络间谍活动', 'major', '欧洲', 59.9139, 10.7522, 2, 5),
(22, '2025-11-20', 'Turla 英国政府机构渗透', 'Turla对英国政府机构的长期潜伏活动', 'major', '欧洲', 51.5074, -0.1278, 9, 5),
(23, '2025-12-05', 'Sandworm 波兰能源设施攻击', 'Sandworm针对波兰能源基础设施的破坏性攻击', 'major', '东欧', 52.2297, 21.0122, 11, 5),
(24, '2025-12-18', 'MuddyWater 土耳其政府攻击', 'MuddyWater针对土耳其政府机构的网络攻击', 'normal', '中东', 39.9334, 32.8597, 12, 3),
-- 2026年1月事件
(25, '2026-01-08', 'APT28 乌克兰军事网络攻击', 'APT28针对乌克兰军事指挥系统的攻击', 'major', '东欧', 50.4501, 30.5234, 1, 5),
(26, '2026-01-13', 'APT41 游戏公司供应链攻击', 'APT41通过游戏更新系统分发恶意软件', 'normal', '东亚', 31.2304, 121.4737, 3, 4),
(27, '2026-01-14', 'APT33 沙特石化企业攻击', 'APT33针对沙特石化企业的工控系统攻击', 'normal', '中东', 26.4207, 50.0888, 6, 4),
(28, '2026-01-15', 'APT34 科威特金融机构入侵', 'APT34针对科威特银行业的网络间谍活动', 'major', '中东', 29.3759, 47.9774, 5, 5),
(29, '2026-01-16', 'FIN7 美国零售连锁店攻击', 'FIN7针对美国零售连锁店的POS系统攻击', 'normal', '北美', 34.0522, -118.2437, 8, 3),
(30, '2026-01-17', 'Charming Kitten 以色列智库攻击', 'Charming Kitten针对以色列研究机构的钓鱼活动', 'normal', '中东', 32.0853, 34.7818, 20, 3),
(31, '2026-01-18', 'APT29 美国智库数据窃取', 'APT29组织针对美国智库的数据窃取活动', 'major', '北美', 38.9072, -77.0369, 2, 4),
(32, '2026-01-19', 'Lazarus 韩国加密货币交易所攻击', 'Lazarus Group对韩国大型加密货币交易所发起攻击', 'major', '东亚', 37.5665, 126.9780, 4, 5),
(33, '2026-01-20', 'Turla 德国政府网络渗透', 'Turla组织对德国政府网络的长期潜伏', 'major', '欧洲', 52.5200, 13.4050, 9, 5),
(34, '2026-01-21', 'APT10 日本制造业供应链攻击', 'APT10通过供应链攻击日本多家制造企业', 'normal', '东亚', 35.6762, 139.6503, 7, 3),
(35, '2026-01-22', 'APT41 新加坡电信运营商入侵', 'APT41对新加坡电信运营商发起大规模攻击', 'normal', '东南亚', 1.3521, 103.8198, 3, 4),
(36, '2026-01-23', 'Silver Sparrow 北美金融机构攻击', 'Silver Sparrow针对北美金融机构的钓鱼攻击活动', 'normal', '北美洲', 40.7128, -74.0060, 21, 3),
(37, '2026-01-24', 'Desert Lynx 非洲电信供应链攻击', 'Desert Lynx针对非洲电信供应链发起钓鱼与植入活动', 'normal', '非洲', 30.0444, 31.2357, 22, 3),
(38, '2026-01-25', 'Coral Reef 大洋洲能源企业入侵', 'Coral Reef对大洋洲能源企业进行长期潜伏', 'major', '大洋洲', -33.8688, 151.2093, 23, 4),
(39, '2026-01-26', 'Ghost Orchid 未知来源异常活动', 'Ghost Orchid在多地区出现异常C2通信活动', 'normal', '未知', NULL, NULL, 24, 2);

-- ============================================
-- 地区事件统计
-- ============================================
INSERT INTO region_event_stats (stat_date, region, event_count, major_count) VALUES
('2026-01-22', '东亚', 3, 1),
('2026-01-22', '欧洲', 1, 1),
('2026-01-21', '北美', 2, 0),
('2026-01-20', '欧洲', 1, 1),
('2026-01-19', '东亚', 1, 1),
('2026-01-18', '北美', 1, 1),
('2026-01-17', '北美', 1, 0),
('2026-01-16', '东欧', 1, 1),
('2026-01-15', '中东', 1, 1),
('2026-01-14', '东亚', 1, 0);

-- ============================================
-- 域名数据
-- ============================================
INSERT INTO domains (id, domain_name, is_malicious, first_seen, last_seen) VALUES
(1, 'sofacy-news.com', 1, '2025-12-15', '2026-01-20'),
(2, 'kremlin-news.info', 1, '2025-11-20', '2026-01-18'),
(3, 'cozy-portal.com', 1, '2025-10-10', '2026-01-15'),
(4, 'game-update.net', 1, '2025-12-01', '2026-01-22'),
(5, 'software-cdn.com', 1, '2025-11-05', '2026-01-21'),
(6, 'swift-update.org', 1, '2025-09-15', '2026-01-19'),
(7, 'bank-security.net', 1, '2025-10-20', '2026-01-17'),
(8, 'energy-portal.com', 1, '2025-08-10', '2026-01-15'),
(9, 'aerospace-news.com', 1, '2025-11-12', '2026-01-14'),
(10, 'cloud-service.net', 1, '2025-12-08', '2026-01-21');

-- ============================================
-- WHOIS 信息
-- ============================================
INSERT INTO whois_info (domain_id, registrar, registration_date, expiration_date, name_servers, registrant, status) VALUES
(1, 'NameCheap Inc.', '2025-12-15', '2026-12-15', '["ns1.privatens.com", "ns2.privatens.com"]', '{"name": "Privacy Protected", "org": "WhoisGuard Inc.", "country": "PA"}', '["clientTransferProhibited"]'),
(2, 'GoDaddy', '2025-11-20', '2026-11-20', '["ns1.godaddy.com", "ns2.godaddy.com"]', '{"name": "Redacted", "org": "Domains by Proxy", "country": "US"}', '["clientDeleteProhibited", "clientTransferProhibited"]'),
(3, 'Alibaba Cloud', '2025-10-10', '2026-10-10', '["dns1.alibabadns.com", "dns2.alibabadns.com"]', '{"name": "Privacy Protected", "country": "CN"}', '["ok"]'),
(4, 'Namecheap', '2025-12-01', '2026-12-01', '["ns1.privatens.com", "ns2.privatens.com"]', '{"name": "Privacy Protected", "country": "PA"}', '["clientTransferProhibited"]');

-- ============================================
-- DNS 记录
-- ============================================
INSERT INTO dns_records (domain_id, record_type, record_name, record_value, ttl) VALUES
(1, 'A', 'sofacy-news.com', '185.220.101.45', 3600),
(1, 'A', 'www.sofacy-news.com', '185.220.101.45', 3600),
(1, 'MX', 'sofacy-news.com', 'mail.sofacy-news.com', 3600),
(2, 'A', 'kremlin-news.info', '45.142.212.61', 3600),
(2, 'CNAME', 'www.kremlin-news.info', 'kremlin-news.info', 3600),
(3, 'A', 'cozy-portal.com', '103.224.182.251', 3600),
(4, 'A', 'game-update.net', '103.85.24.155', 3600),
(4, 'A', 'cdn.game-update.net', '103.85.24.156', 3600);

-- ============================================
-- SSL 证书信息
-- ============================================
INSERT INTO ssl_certificates (domain_id, issuer, subject, serial_number, not_before, not_after, is_expired, is_self_signed) VALUES
(1, '{"CN": "Let\'s Encrypt Authority X3", "O": "Let\'s Encrypt", "C": "US"}', '{"CN": "sofacy-news.com"}', '03ABC123456789DEF', '2025-12-15 00:00:00', '2026-03-15 23:59:59', 0, 0),
(2, '{"CN": "Self-Signed"}', '{"CN": "kremlin-news.info"}', '01', '2025-11-20 00:00:00', '2026-11-20 00:00:00', 0, 1),
(3, '{"CN": "DigiCert SHA2 Secure Server CA", "O": "DigiCert Inc"}', '{"CN": "cozy-portal.com"}', '0F123456789ABCDEF', '2025-10-10 00:00:00', '2026-10-10 00:00:00', 0, 0);

-- ============================================
-- 威胁统计数据
-- ============================================
INSERT INTO threat_statistics (stat_date, total_organizations, total_events, total_domains, total_iocs, active_threats, new_threats_today) VALUES
('2026-01-22', 8, 10, 10, 1203, 5, 3),
('2026-01-21', 8, 8, 10, 1198, 4, 2),
('2026-01-20', 8, 7, 9, 1195, 3, 1),
('2026-01-19', 8, 6, 9, 1189, 4, 2),
('2026-01-18', 8, 5, 8, 1185, 3, 1);

-- ============================================
-- 威胁趋势数据
-- ============================================
INSERT INTO threat_trends (trend_date, dns_tunnel_count, dga_domain_count, phishing_count, c2_communication, malware_count) VALUES
('2026-01-22', 15, 23, 8, 12, 5),
('2026-01-21', 12, 19, 6, 10, 4),
('2026-01-20', 18, 25, 10, 15, 7),
('2026-01-19', 10, 17, 5, 9, 3),
('2026-01-18', 14, 21, 7, 11, 6),
('2026-01-17', 11, 18, 4, 8, 4),
('2026-01-16', 16, 22, 9, 13, 5),
('2026-01-15', 13, 20, 6, 10, 5),
('2026-01-14', 9, 16, 5, 7, 3),
('2026-01-13', 12, 19, 7, 9, 4);

-- ============================================
-- 攻击来源统计
-- ============================================
INSERT INTO attack_sources (country, attack_count, last_attack_date) VALUES
('俄罗斯', 127, '2026-01-22'),
('中国', 95, '2026-01-22'),
('朝鲜', 68, '2026-01-19'),
('伊朗', 52, '2026-01-15'),
('美国', 31, '2026-01-20'),
('乌克兰', 23, '2026-01-17'),
('荷兰', 18, '2026-01-18'),
('德国', 15, '2026-01-16'),
('法国', 12, '2026-01-14'),
('巴西', 9, '2026-01-13');
