import sys
from pathlib import Path
import unittest


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.services.notification import feishu_service as MODULE


class FeishuServiceFormatTest(unittest.TestCase):
    def test_v1_impersonation_match_line_uses_chinese_fields(self) -> None:
        item = {
            "impersonation_domain": "micr0s0ft.online",
            "official_domain": "microsoft.com",
            "official_unit_name": "Microsoft",
            "match_type": "confusable",
            "risk_level": "high",
            "final_risk_score": "1.0000",
            "hit_reason": (
                "matched strong token 'microsoft'; "
                "recall rule: confusable_match; "
                "features: recall:confusable_match|token:microsoft|hard_filter_pass|"
                "suspicious_tld|suffix_changed|visual_confusable; "
                "scores: rule=0.900, lgbm=1.000, fusion=1.000"
            ),
            "llm_key_features": (
                "recall:confusable_match|token:microsoft|suspicious_tld|"
                "suffix_changed|visual_confusable"
            ),
        }

        text = MODULE._build_impersonation_match_line(1, item)[0]["text"]

        self.assertIn("1. 仿冒域名：micr0s0ft.online", text)
        self.assertIn("官方域名：microsoft.com", text)
        self.assertIn("官方单位名称：Microsoft", text)
        self.assertIn("匹配类型：视觉混淆", text)
        self.assertIn("风险等级：高", text)
        self.assertNotIn("最终风险分", text)
        self.assertNotIn("命中原因", text)
        self.assertNotIn("LLM", text)

    def test_v1_grouped_alert_lines_order_by_unit_type_and_brand_subtype_count(self) -> None:
        matches = [
            {
                "impersonation_domain": "login-bank.top",
                "official_domain": "bank.example",
                "official_unit_name": "Bank",
                "official_unit_type": "金融",
                "match_type": "service_entry|prefix_suffix",
                "risk_level": "中",
                "final_risk_score": "0.7100",
                "llm_disposition": "保留人工复核",
            },
            {
                "impersonation_domain": "gov-login.top",
                "official_domain": "gov.example",
                "official_unit_name": "Gov",
                "official_unit_type": "政府",
                "match_type": "brand_combo",
                "risk_level": "高",
                "final_risk_score": "0.9300",
                "llm_disposition": "保留高危告警",
            },
            {
                "impersonation_domain": "edu-login.top",
                "official_domain": "edu.example",
                "official_unit_name": "Edu",
                "official_unit_type": "教育",
                "match_type": "confusable",
                "risk_level": "中",
                "final_risk_score": "0.7000",
                "llm_disposition": "保留人工复核",
            },
            {
                "impersonation_domain": "cloud-login.top",
                "official_domain": "cloud.example",
                "official_unit_name": "Cloud",
                "official_unit_type": "品牌",
                "official_unit_subtype": "云服务",
                "match_type": "service_entry|template_reuse|pinyin_abbr",
                "risk_level": "高",
                "final_risk_score": "0.9100",
                "llm_disposition": "保留高危告警",
            },
            {
                "impersonation_domain": "coin-login.top",
                "official_domain": "coin.example",
                "official_unit_name": "Coin",
                "official_unit_type": "品牌",
                "official_unit_subtype": "crypto",
                "match_type": "brand_combo",
                "risk_level": "高",
                "final_risk_score": "0.9000",
                "llm_disposition": "保留高危告警",
            },
            {
                "impersonation_domain": "coin-pay.top",
                "official_domain": "coin.example",
                "official_unit_name": "Coin",
                "official_unit_type": "品牌",
                "official_unit_subtype": "crypto",
                "match_type": "hyphenation",
                "risk_level": "中",
                "final_risk_score": "0.7200",
                "llm_disposition": "保留人工复核",
            },
        ]

        lines = MODULE._build_impersonation_alert_lines(matches)
        text = "".join(part["text"] for line in lines for part in line)

        self.assertIn("仿冒域名数量：6", text)
        group_titles = [
            line[0]["text"].strip()
            for line in lines
            if line and line[0]["text"].strip().startswith(("一、", "二、", "三、", "四、", "五、"))
        ]
        self.assertEqual(
            [
                "一、单位类型：政府",
                "二、单位类型：金融",
                "三、单位类型：教育",
                "四、单位类型：品牌-加密货币",
                "五、单位类型：品牌-云服务",
            ],
            group_titles,
        )
        self.assertIn("匹配类型：业务入口仿冒\\前后缀仿冒", text)
        self.assertIn("匹配类型：业务入口仿冒\\历史模板复用\\拼音缩写", text)
        self.assertNotIn("最终风险分", text)
        self.assertNotIn("命中原因", text)

    def test_feature_only_reason_is_translated(self) -> None:
        item = {
            "impersonation_domain": "login-microsoft.top",
            "llm_key_features": "risk_words:login,verify|suspicious_tld|tld_replace|strong_rule_fallback:0.85",
        }

        reason = MODULE._translate_v1_hit_reason(item)

        self.assertIn("组合风险词 login、verify", reason)
        self.assertIn("使用可疑顶级域 top", reason)
        self.assertIn("命中后缀替换特征", reason)
        self.assertIn("触发强规则兜底，最终风险分下限提升至 0.85", reason)
        self.assertNotIn("命中可疑特征 strong_rule_fallback:0.85", reason)

    def test_filter_keeps_one_best_official_domain_per_impersonation_domain(self) -> None:
        matches = [
            {
                "impersonation_domain": "portal-example.top",
                "official_domain": "example.cn",
                "risk_level": "中",
                "final_risk_score": "0.7200",
                "llm_disposition": "保留人工复核",
            },
            {
                "impersonation_domain": "portal-example.top",
                "official_domain": "example.com",
                "risk_level": "高",
                "final_risk_score": "0.9500",
                "llm_disposition": "保留高危告警",
            },
            {
                "impersonation_domain": "low-example.top",
                "official_domain": "example.org",
                "risk_level": "低",
                "final_risk_score": "0.5000",
                "llm_disposition": "保留人工复核",
            },
            {
                "impersonation_domain": "medium-example.top",
                "official_domain": "example.net",
                "risk_level": "medium",
                "final_risk_score": "0.6600",
                "llm_disposition": "保留人工复核",
            },
        ]

        filtered = MODULE._filter_impersonation_matches(matches)

        self.assertEqual(["portal-example.top", "medium-example.top"], [
            item["impersonation_domain"] for item in filtered
        ])
        self.assertEqual("example.com", filtered[0]["official_domain"])
        self.assertNotIn("low-example.top", {item["impersonation_domain"] for item in filtered})

    def test_filter_prefers_canonical_official_domain_for_same_brand(self) -> None:
        matches = [
            {
                "impersonation_domain": "1pathgoogle.com",
                "official_domain": "google.com.om",
                "official_unit_name": "Google",
                "risk_level": "高",
                "final_risk_score": "0.8524",
                "llm_disposition": "保留高危告警",
            },
            {
                "impersonation_domain": "1pathgoogle.com",
                "official_domain": "google.com",
                "official_unit_name": "Google",
                "risk_level": "中",
                "final_risk_score": "0.7000",
                "llm_disposition": "保留人工复核",
            },
        ]

        filtered = MODULE._filter_impersonation_matches(matches)

        self.assertEqual(1, len(filtered))
        self.assertEqual("google.com", filtered[0]["official_domain"])


if __name__ == "__main__":
    unittest.main()
