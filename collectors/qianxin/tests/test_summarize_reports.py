from __future__ import annotations

from scripts.qianxin.summarize_reports import (
    build_argument_parser,
    build_validated_executive_summary,
    chunk_pages,
    extract_indicators,
    filter_non_prescriptive_recommendations,
    filter_non_tool_names,
    filter_unsupported_named_items,
    filter_vulnerability_placeholders,
    ground_quotes,
    lock_reduced_facts_to_notes,
    load_active_failures,
    parse_json_response,
    pack_pages_for_context,
    persist_active_failures,
    remove_duplicate_tool_names,
    validate_evidence_pages,
)


def test_request_timeout_argument_defaults_and_overrides():
    parser = build_argument_parser()
    assert parser.parse_args([]).request_timeout == 600
    assert parser.parse_args(["--request-timeout", "1800"]).request_timeout == 1800


def test_failure_state_preserves_unselected_failures_and_clears_resolved_items(tmp_path):
    path = tmp_path / "failures.json"
    state = {
        "a/document.json": {"document": "a/document.json", "error": "A", "attempts": 1},
        "b/document.json": {"document": "b/document.json", "error": "B", "attempts": 2},
    }
    persist_active_failures(path, state)
    loaded = load_active_failures(path)
    loaded.pop("a/document.json")
    persist_active_failures(path, loaded)
    assert list(load_active_failures(path)) == ["b/document.json"]
    loaded.clear()
    persist_active_failures(path, loaded)
    assert not path.exists()


def test_extract_indicators_preserves_evidence_pages_and_defangs():
    pages = [
        {
            "page_number": 3,
            "markdown": "CVE-2026-12345 T1059.001 hxxps://evil[.]example/path "
            "8.8.8.8 admin@example.org d41d8cd98f00b204e9800998ecf8427e",
        },
        {"page_number": 4, "markdown": "evil.example and CVE-2026-12345"},
    ]
    result = extract_indicators(pages)
    assert result["cves"] == [
        {"value": "CVE-2026-12345", "evidence_pages": [3, 4], "classification": "observable"}
    ]
    assert result["mitre_techniques"][0]["value"] == "T1059.001"
    assert result["ipv4"][0]["value"] == "8.8.8.8"
    assert result["md5"][0]["value"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert any(item["value"] == "evil.example" for item in result["domains"])


def test_markdown_urls_are_cleaned_and_duplicate_link_rendering_prefers_target():
    pages = [
        {
            "page_number": 1,
            "markdown": (
                "https://short.example/a](https://full.example/complete/) "
                "**https://evil.example/path** `https://other.example/x`"
            ),
        }
    ]
    values = [item["value"] for item in extract_indicators(pages)["urls"]]
    assert "https://full.example/complete/" in values
    assert "https://evil.example/path" in values
    assert "https://other.example/x" in values
    assert all("](" not in value and "*" not in value and "`" not in value for value in values)


def test_markdown_table_suffixes_are_removed_and_truncated_recipe_urls_are_dropped():
    pages = [
        {
            "page_number": 1,
            "markdown": (
                "https://evil.example/download.php?id=7||payload.exe| "
                "https://gchq.github.io/CyberChef/#recipe=From_Base64("
            ),
        }
    ]
    values = [item["value"] for item in extract_indicators(pages)["urls"]]
    assert values == ["https://evil.example/download.php?id=7"]


def test_truncated_or_non_public_url_hosts_are_dropped():
    pages = [
        {
            "page_number": 1,
            "markdown": (
                "https://book https://bed-office-original- http://check.nid- "
                "https://apiscriptv3.vercel https://valid.example/path "
                "https://valid-service.run/path"
            ),
        }
    ]
    values = [item["value"] for item in extract_indicators(pages)["urls"]]
    assert values == ["https://valid-service.run/path", "https://valid.example/path"]


def test_private_and_loopback_addresses_are_not_observable():
    pages = [
        {
            "page_number": 1,
            "markdown": "http://127.0.0.1/admin 10.0.0.1 8.8.8.8",
        }
    ]
    result = extract_indicators(pages)
    ipv4 = {item["value"]: item["classification"] for item in result["ipv4"]}
    urls = {item["value"]: item["classification"] for item in result["urls"]}
    assert ipv4["10.0.0.1"] == "local"
    assert ipv4["8.8.8.8"] == "observable"
    assert urls["http://127.0.0.1/admin"] == "local"


def test_attributed_actor_aliases_are_not_retained_as_tools():
    summary = {
        "attribution": {"actor": "APT28 (Fancy Bear)"},
        "malware_tools": [
            {"name": "APT28/Fancy Bear"},
            {"name": "PowerShell"},
        ],
    }
    removed = filter_non_tool_names(summary)
    assert [item["name"] for item in removed] == ["APT28/Fancy Bear"]
    assert [item["name"] for item in summary["malware_tools"]] == ["PowerShell"]


def test_actor_roles_and_non_tool_artifacts_are_removed_from_tool_list():
    summary = {
        "attribution": {"actor": "GRU"},
        "malware_tools": [
            {"name": "APT28/Fancy Bear", "role": "攻击者"},
            {"name": "Cisco设备漏洞", "role": "用于入侵"},
            {"name": "GitHub 仓库", "role": "隐藏依赖"},
            {
                "name": "Seedworm",
                "role": "被用于攻击",
                "evidence_quote": "Seedworm: Iranian Hackers Target Telecoms",
            },
            {"name": "ALGORIT_MD5", "role": "用于计算MD5哈希值的算法"},
            {"name": "ClickFix", "role": "剪切板注入攻击"},
            {"name": "ChainVeil", "role": "恶意软件活动"},
            {"name": "ALGORIT_MD5", "role": "用于计算MD5哈希值"},
            {"name": "DECODE SHELLCODE", "role": "解密代码内容"},
            {"name": "Kazuar", "role": "后门"},
        ],
    }
    removed = filter_non_tool_names(summary)
    assert [item["name"] for item in removed] == [
        "APT28/Fancy Bear",
        "Cisco设备漏洞",
        "GitHub 仓库",
        "Seedworm",
        "ALGORIT_MD5",
        "ClickFix",
        "ChainVeil",
        "ALGORIT_MD5",
        "DECODE SHELLCODE",
    ]
    assert [item["name"] for item in summary["malware_tools"]] == ["Kazuar"]


def test_duplicate_tool_names_are_collapsed_without_merging_unverified_roles():
    summary = {
        "malware_tools": [
            {"name": "Zoho WorkDrive", "role": "C2 channel", "evidence_pages": [2]},
            {"name": "zoho-workdrive", "role": "data exfiltration", "evidence_pages": [2]},
        ]
    }
    removed = remove_duplicate_tool_names(summary)
    assert len(removed) == 1
    assert summary["malware_tools"] == [
        {"name": "Zoho WorkDrive", "role": "C2 channel", "evidence_pages": [2]}
    ]


def test_plain_web_links_are_candidates_but_defanged_and_ioc_section_values_are_observable():
    pages = [
        {
            "page_number": 1,
            "markdown": "See https://learn.microsoft.com/security and vendor.example for details.",
        },
        {
            "page_number": 2,
            "markdown": "Defanged sample: hxxps://evil[.]example/dropper",
        },
        {
            "page_number": 3,
            "markdown": "## Indicators of Compromise\nhttps://c2.example/beacon analyst@c2.example",
        },
    ]
    result = extract_indicators(pages)
    urls = {item["value"]: item["classification"] for item in result["urls"]}
    domains = {item["value"]: item["classification"] for item in result["domains"]}
    emails = {item["value"]: item["classification"] for item in result["emails"]}
    assert urls["https://learn.microsoft.com/security"] == "candidate"
    assert domains["vendor.example"] == "candidate"
    assert urls["https://evil.example/dropper"] == "observable"
    assert urls["https://c2.example/beacon"] == "observable"
    assert domains["c2.example"] == "observable"
    assert emails["analyst@c2.example"] == "observable"


def test_file_names_are_not_treated_as_domains():
    result = extract_indicators([{"page_number": 1, "markdown": "payload.dll image.png real.example"}])
    values = [item["value"] for item in result["domains"]]
    assert "payload.dll" not in values
    assert "image.png" not in values
    assert "real.example" in values


def test_chunk_pages_never_splits_page_boundaries():
    pages = [
        {"page_number": 1, "markdown": "a" * 60},
        {"page_number": 2, "markdown": "b" * 60},
    ]
    chunks = chunk_pages(pages, max_chars=100)
    assert [chunk["pages"] for chunk in chunks] == [[1], [2]]
    assert "[PDF_PAGE 1]" in chunks[0]["text"]


def test_parse_json_response_accepts_fenced_json():
    assert parse_json_response('```json\n{"ok": true}\n```') == {"ok": True}


def test_validate_evidence_removes_invalid_pages():
    value = {"items": [{"evidence_pages": [1, 2, 99, "3"]}]}
    invalid = validate_evidence_pages(value, page_count=3)
    assert value["items"][0]["evidence_pages"] == [1, 2]
    assert len(invalid) == 2


def test_ground_quotes_assigns_real_page_and_drops_unsupported_fact():
    value = {
        "key_findings": [
            {"finding": "Kazuar was used", "evidence_quote": "campaigns relied on the Kazuar malware"},
            {"finding": "Invented", "evidence_quote": "this text is absent"},
        ]
    }
    pages = [
        {"page_number": 1, "markdown": "Overview"},
        {"page_number": 3, "markdown": "Since 2016, campaigns relied on the Kazuar malware."},
    ]
    dropped = ground_quotes(value, pages)
    assert value["key_findings"] == [
        {
            "finding": "Kazuar was used",
            "evidence_quote": "campaigns relied on the Kazuar malware",
            "evidence_pages": [3],
            "evidence_match": "exact",
        }
    ]
    assert len(dropped) == 1


def test_ground_quotes_allows_high_unique_fuzzy_match():
    value = {
        "key_findings": [
            {
                "finding": "Attribution",
                "evidence_quote": "Members of the C4 have observed targeting by the Turla intrusion set operated by the FSB since at least 2004 for intelligence collection worldwide",
            }
        ]
    }
    pages = [
        {
            "page_number": 1,
                "markdown": "Members of the Cyber Crisis Coordination Center (C4) have observed targeting by the Turla intrusion set operated by the FSB since at least 2004 for intelligence collection worldwide.",
        },
        {"page_number": 2, "markdown": "Unrelated technical details."},
    ]
    assert ground_quotes(value, pages) == []
    assert value["key_findings"][0]["evidence_pages"] == [1]
    assert value["key_findings"][0]["evidence_match"] == "fuzzy_unique_characters"


def test_attack_description_is_not_accepted_as_defensive_recommendation():
    summary = {
        "defensive_recommendations": [
            {
                "recommendation": "加固设备",
                "evidence_quote": "Attackers compromised network equipment and business applications.",
            },
            {
                "recommendation": "安装补丁",
                "evidence_quote": "Organizations should apply the security patch immediately.",
            },
        ]
    }
    removed = filter_non_prescriptive_recommendations(summary)
    assert len(removed) == 1
    assert len(summary["defensive_recommendations"]) == 1


def test_multilingual_and_imperative_recommendations_are_preserved():
    quotes = [
        "Для зниження ризику доцільно обмежити можливість запуску wscript.exe",
        "及时更新病毒库并关闭不必要的服务。",
        "请及时安装安全补丁。",
        "Следует обновить систему.",
        "Strengthen Microsoft Defender for Endpoint configuration",
        "Enforce domain-name-based network access controls using Zero Trust DNS.",
        "Organizations defending against espionage should focus on operational behavior.",
        "If business cases allow, this setting should be disabled.",
        "Behavior-based EDR is required to detect the indicators of compromise.",
        "Continuous and close monitoring of the group's operations, infrastructure, and toolset changes is essential to detect future operations.",
        "The safest remediation path for an affected host is a complete wipe.",
        "To counter that threat, do your cloning and testing in a sandboxed environment.",
        "Hunt and block by campaign patterns, not single package names.",
        "특히 위험한 신호이므로, 절대 압축을 풀거나 실행해서는 안 됩니다.",
        "그러니 반드시 해당 부분은 윈도우 설정에서 변경해야 합니다.",
        "不審なファイルを実行しないでください",
    ]
    summary = {
        "defensive_recommendations": [
            {"recommendation": str(index), "evidence_quote": quote}
            for index, quote in enumerate(quotes)
        ]
    }
    assert filter_non_prescriptive_recommendations(summary) == []
    assert len(summary["defensive_recommendations"]) == len(quotes)


def test_attacker_behavior_with_must_or_detection_is_not_a_recommendation():
    summary = {
        "defensive_recommendations": [
            {"recommendation": "bad", "evidence_quote": "Attackers must execute the loader first."},
            {"recommendation": "bad", "evidence_quote": "恶意软件通过混淆绕过静态特征检测。"},
            {"recommendation": "bad", "evidence_quote": "攻击者及时更新了恶意配置。"},
        ]
    }
    assert len(filter_non_prescriptive_recommendations(summary)) == 3
    assert summary["defensive_recommendations"] == []


def test_vulnerability_placeholders_and_invalid_cves_are_removed():
    summary = {
        "vulnerabilities": [
            {"cve": "", "description": "未明确提及具体漏洞", "evidence_quote": "none"},
            {"cve": "CVE-2021-34473/34523", "description": "invalid shorthand", "evidence_quote": "CVE shorthand"},
            {"cve": "CVE-2026-12345", "description": "real", "evidence_quote": "real"},
            {"cve": "", "description": "未编号的反序列化漏洞", "evidence_quote": "an unpatched deserialization vulnerability"},
            {"cve": "", "description": "无需身份验证的漏洞", "evidence_quote": "an authentication-free vulnerability"},
            {"cve": "", "description": "RC4配置", "evidence_quote": "configuration data is encrypted with RC4"},
            {
                "cve": "",
                "description": "漏洞情况",
                "evidence_quote": "No known vulnerabilities were identified in this campaign.",
            },
            {"cve": "", "description": "漏洞情况", "evidence_quote": "未发现漏洞利用行为。"},
        ]
    }
    removed = filter_vulnerability_placeholders(summary)
    assert len(removed) == 5
    assert [item["cve"] for item in summary["vulnerabilities"]] == ["CVE-2026-12345", "", ""]
    assert sum(item["reason"] == "negated_vulnerability" for item in removed) == 3


def test_executive_summary_is_rebuilt_only_from_validated_facts():
    summary = {
        "executive_summary_zh": "未验证的归因和建议。",
        "key_findings": [
            {
                "finding": "虚构的 APT28 归因",
                "evidence_quote": "The attachment launches a PowerShell downloader.",
                "evidence_pages": [2],
            },
            {
                "finding": "没有证据页的内容",
                "evidence_quote": "This quote has no located page.",
                "evidence_pages": [],
            },
        ],
        "attack_chain": [],
    }
    rebuilt = build_validated_executive_summary(summary)
    assert "The attachment launches a PowerShell downloader." in rebuilt
    assert "[PDF p.2]" in rebuilt
    assert "未验证的归因" not in rebuilt
    assert "APT28" not in rebuilt


def test_executive_summary_deduplicates_quotes_and_respects_length_limit():
    repeated_quote = "A" * 80
    summary = {
        "key_findings": [
            {"finding": "invented one", "evidence_quote": repeated_quote, "evidence_pages": [1]},
            {"finding": "invented two", "evidence_quote": repeated_quote, "evidence_pages": [1]},
            {"finding": "invented duplicate", "evidence_quote": repeated_quote, "evidence_pages": [1]},
        ],
        "attack_chain": [
            {"activity": "invented three", "evidence_quote": "B" * 80, "evidence_pages": [2]},
            {"activity": "invented four", "evidence_quote": "C" * 180, "evidence_pages": [3]},
        ],
    }
    rebuilt = build_validated_executive_summary(summary)
    assert rebuilt.count(repeated_quote) == 1
    assert "B" * 80 in rebuilt
    assert "invented" not in rebuilt
    assert len(rebuilt) <= 240


def test_reduce_can_only_select_original_grounded_chunk_facts():
    notes = [
        {
            "key_findings": [
                {
                    "finding": "Original supported finding",
                    "evidence_quote": "The malware used HTTPS for command and control.",
                    "evidence_pages": [4],
                    "evidence_match": "exact",
                }
            ],
            "attribution_evidence": [
                {
                    "actor": "APT29",
                    "basis": "The report attributes the activity to APT29.",
                    "confidence": "high",
                    "evidence_quote": "The activity was attributed to APT29.",
                    "evidence_pages": [1],
                }
            ],
        }
    ]
    reduced = {
        "key_findings": [
            {
                "finding": "APT28 attacked Ukraine",
                "evidence_quote": "The malware used HTTPS for command and control.",
                "evidence_pages": [4],
            },
            {
                "finding": "Invented reducer fact",
                "evidence_quote": "A quote never emitted by a chunk",
                "evidence_pages": [9],
            },
        ],
        "attribution": {
            "actor": "Invented actor",
            "basis": "Invented basis",
            "confidence": "high",
            "evidence_quote": "The activity was attributed to APT29.",
            "evidence_pages": [1],
        },
    }
    removed = lock_reduced_facts_to_notes(reduced, notes)
    assert reduced["key_findings"] == notes[0]["key_findings"]
    assert reduced["attribution"]["actor"] == "APT29"
    assert len(removed) == 1


def test_reduce_preserves_distinct_entities_that_share_an_evidence_quote():
    quote = "The campaign deployed GoldDragon and BravePrince malware."
    notes = [
        {
            "malware_tools": [
                {"name": "GoldDragon", "role": "malware", "evidence_quote": quote, "evidence_pages": [2]},
                {"name": "BravePrince", "role": "malware", "evidence_quote": quote, "evidence_pages": [2]},
            ]
        }
    ]
    reduced = {
        "malware_tools": [
            {"name": "GoldDragon", "evidence_quote": quote, "evidence_pages": [2]},
            {"name": "BravePrince", "evidence_quote": quote, "evidence_pages": [2]},
        ]
    }
    assert lock_reduced_facts_to_notes(reduced, notes) == []
    assert [item["name"] for item in reduced["malware_tools"]] == ["GoldDragon", "BravePrince"]


def test_tool_name_support_rejects_generic_token_only_and_accepts_informative_token():
    summary = {
        "malware_tools": [
            {"name": "Windows TotallyFakeRAT", "evidence_pages": [1]},
            {"name": "Kazuar backdoor", "evidence_pages": [2]},
        ],
        "vulnerabilities": [],
    }
    pages = [
        {"page_number": 1, "markdown": "The campaign targets Windows hosts."},
        {"page_number": 2, "markdown": "The operators deployed Kazuar malware."},
    ]
    removed = filter_unsupported_named_items(summary, pages)
    assert [item["name"] for item in summary["malware_tools"]] == ["Kazuar backdoor"]
    assert [item["value"] for item in removed] == ["Windows TotallyFakeRAT"]


def test_ground_quotes_handles_cjk_spacing_and_sentence_joining():
    value = {
        "key_findings": [
            {
                "finding": "钓鱼活动",
                "evidence_quote": "钓鱼网站使用LiteSpeed Web搭建。该服务包含伪装下载页面，点击后下载恶意脚本",
            }
        ]
    }
    pages = [
        {
            "page_number": 2,
            "markdown": "钓鱼网站使用 LiteSpeed Web 搭建。该服务包含伪装下载页面。点击后下载恶意脚本。",
        },
        {"page_number": 3, "markdown": "其他无关的技术分析内容。"},
    ]
    assert ground_quotes(value, pages) == []
    assert value["key_findings"][0]["evidence_pages"] == [2]
    assert value["key_findings"][0]["evidence_match"] == "fuzzy_unique_cjk_bigrams"


def test_token_aware_page_packing_preserves_whole_pages():
    class FakeClient:
        @staticmethod
        def token_count(text: str) -> int:
            return text.count("x")

    pages = [
        {"page_number": 1, "markdown": "xx"},
        {"page_number": 2, "markdown": "xx"},
        {"page_number": 3, "markdown": "x"},
    ]
    chunks = pack_pages_for_context(pages, FakeClient(), context_size=2403, max_chars=0)
    assert [chunk["pages"] for chunk in chunks] == [[1], [2, 3]]


def test_token_aware_page_packing_splits_one_oversized_page():
    class FakeClient:
        @staticmethod
        def token_count(text: str) -> int:
            return text.count("x")

    pages = [{"page_number": 55, "markdown": "x" * 10}]
    chunks = pack_pages_for_context(pages, FakeClient(), context_size=2404, max_chars=0)
    assert len(chunks) > 1
    assert all(chunk["pages"] == [55] for chunk in chunks)
    assert "".join(chunk["text"].split("\n", 1)[1] for chunk in chunks) == "x" * 10
    assert all(FakeClient.token_count(chunk["text"]) <= 4 for chunk in chunks)


def test_single_page_character_cap_is_enforced_even_when_tokens_fit():
    class FakeClient:
        @staticmethod
        def token_count(text: str) -> int:
            return 1

    pages = [{"page_number": 7, "markdown": "word " * 20}]
    chunks = pack_pages_for_context(pages, FakeClient(), context_size=4096, max_chars=40)
    assert len(chunks) > 1
    assert all(len(chunk["text"]) <= 40 for chunk in chunks)
