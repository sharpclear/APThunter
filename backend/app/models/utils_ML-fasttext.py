import numpy as np
import pandas as pd
import re
import math
import os
from collections import Counter
from wordsegment import load, segment
import fasttext


# =========================
# fastText 相关函数
# =========================

_FASTTEXT_MODEL_CACHE = None


def load_fasttext_model(model_path=None):
    """
    加载 fastText 预训练模型。
    """
    global _FASTTEXT_MODEL_CACHE

    if _FASTTEXT_MODEL_CACHE is not None:
        return _FASTTEXT_MODEL_CACHE

    if model_path is None:
        model_path = os.path.join(
            os.path.dirname(__file__),
            "fasttext",
            "cc.en.100.bin"
        )

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"fastText 模型文件不存在: {model_path}")

    print(f"Loading fastText model from {model_path}...")
    model = fasttext.load_model(model_path)
    print(f"fastText model loaded. dimension={model.get_dimension()}")

    _FASTTEXT_MODEL_CACHE = model
    return _FASTTEXT_MODEL_CACHE


def normalize_domain(domain):
    domain = str(domain).strip().lower()

    # 去掉协议
    domain = re.sub(r"^https?://", "", domain)

    # 去掉路径、参数、片段
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]

    # 去掉端口
    domain = domain.split(":")[0]

    # 去掉开头的 www.
    if domain.startswith("www."):
        domain = domain[4:]

    # 去掉首尾多余的点
    domain = domain.strip(".")

    return domain


def tokenize_domain_for_fasttext(domain):
    """将域名切分成适合输入 fastText 的 token。"""
    domain = str(domain).lower().strip()

    # 按常见域名分隔符切分
    parts = re.split(r'[-—._]', domain)

    # 去掉空字符串
    parts = [p for p in parts if p]

    tokens = []

    for part in parts:
        # 去掉纯数字片段
        if part.isdigit():
            continue

        # 如果是较长字符串，尝试进一步分词
        if len(part) > 7:
            without_digit = re.sub(r'\d+', '', part)

            if without_digit:
                seg_words = segment(without_digit)

                # 如果分词结果有效，则加入分词结果
                if len(seg_words) > 1:
                    tokens.extend(seg_words)
                else:
                    tokens.append(without_digit)
        else:
            tokens.append(part)

    return tokens


def domain_to_fasttext_vector(domain, ft_model, vector_size=None):
    """
    将单个域名转换为 fastText 向量。
    """
    if vector_size is None:
        vector_size = ft_model.get_dimension()

    tokens = tokenize_domain_for_fasttext(domain)

    vectors = []

    for token in tokens:
        try:
            vec = ft_model.get_word_vector(token)
            vectors.append(vec)
        except Exception:
            continue

    if len(vectors) == 0:
        return np.zeros(vector_size, dtype=np.float32)

    return np.mean(vectors, axis=0).astype(np.float32)


# =========================
# 原人工特征函数
# =========================

def length(domain):
    feature = []
    parts = domain.split('.')

    if len(parts) < 2:
        feature.extend([0, 0, 0])
    else:
        main_domain = parts[-2]
        top_level_domain = parts[-1]
        subdomains = parts[:-2]

        feature.append(len(main_domain))
        feature.append(len(top_level_domain))
        feature.append(sum(len(sub) for sub in subdomains))

    return feature


def count_subdomain(domain):
    parts = domain.split('.')

    if len(parts) < 3:
        return [0]
    else:
        return [len(parts) - 2]


def consecutive(domain):
    consecutive_char_list = []

    for i in range(0, len(domain) - 1):
        if domain[i] == domain[i + 1]:
            if domain[i] not in consecutive_char_list:
                consecutive_char_list.append(domain[i])

    return [len(consecutive_char_list)]


def count_special_char(domain):
    count = 0
    special = ["-", "—"]

    for char in domain:
        if char in special:
            count += 1

    return [count]


def count_digit(domain):
    parts = domain.split('.')

    def count_digits(word):
        return sum(c.isdigit() for c in word)

    if len(parts) < 2:
        main_domain_digit_count = count_digits(domain)
        subdomain_digit_count = 0
    else:
        main_domain = parts[-2]
        subdomains = parts[:-2]

        main_domain_digit_count = count_digits(main_domain)
        subdomain_digit_count = sum(count_digits(sub) for sub in subdomains)

    return [
        main_domain_digit_count + subdomain_digit_count,
        subdomain_digit_count
    ]


def known_top(domain):
    parts = domain.lower().strip().split('.')

    if len(parts) < 2:
        return [0]

    top_domain = parts[-1]

    known_tlds = {
        "com", "net", "org", "info", "biz", "name", "pro",
        "top", "xyz", "site", "online", "club", "vip", "shop",
        "store", "app", "dev", "cloud", "tech", "space", "website",
        "link", "click", "live", "work", "today", "world", "email",
        "services", "support", "systems", "network", "digital",
        "cn", "ru", "us", "uk", "de", "fr", "jp", "kr", "in",
        "br", "au", "ca", "nl", "it", "es", "pl", "tr", "ir",
        "ua", "hk", "tw", "sg", "vn", "th", "id", "my", "ph",
        "cc", "co", "io", "me", "tv", "pw", "su", "to", "gg",
        "ml", "ga", "cf", "tk", "gq", "icu", "cyou", "monster",
        "quest", "rest", "bar", "fun", "bond", "cam"
    }

    return [1 if top_domain in known_tlds else 0]


def raw_word(parts):
    if len(parts) == 0:
        return [0, 0, 0, 0, 0]

    raw_word_count = len(parts)
    word_len = [len(part) for part in parts]

    return [
        raw_word_count,
        sum(word_len) / raw_word_count,
        max(word_len),
        min(word_len),
        np.std(word_len)
    ]


def combined_word(words):
    num = len(words)

    if num == 0:
        return [0, 0]

    total_word_len = sum(len(word) for word in words)

    return [
        num,
        total_word_len / num
    ]


def calculate_entropy(domain):
    if len(domain) == 0:
        return 0

    char_counts = Counter(domain)
    total_chars = len(domain)

    entropy = 0.0
    for char, count in char_counts.items():
        prob = count / total_chars
        entropy -= prob * math.log2(prob)

    return entropy


# =========================
# 融合人工特征 + fastText 特征
# =========================

def feature_extract(domains, ft_model=None, vector_size=None):
    """
    提取域名特征。

    固定启用 fastText（默认 cc.en.100.bin）：
        输出 18 + 100 = 118 维特征。
    """
    result = []

    load()
    if ft_model is None:
        ft_model = load_fasttext_model()
    if vector_size is None:
        vector_size = ft_model.get_dimension()

    for domain in domains:
        domain = normalize_domain(domain)

        feature = []
        combined_word_list = []
        domain_word_list = []

        # 1. 人工特征
        feature.extend(length(domain))
        feature.extend(count_subdomain(domain))
        feature.extend(consecutive(domain))
        feature.extend(count_special_char(domain))
        feature.extend(count_digit(domain))
        feature.extend(known_top(domain))

        parts = re.split(r'[-—._]', domain)
        parts = [part for part in parts if part]

        feature.extend(raw_word(parts))

        for part in parts:
            if len(part) > 7:
                without_digit = re.sub(r'\d+', '', part)

                if without_digit:
                    words = segment(without_digit)

                    if len(words) > 1:
                        combined_word_list.append(part)

                    for word in words:
                        domain_word_list.append(word)
            else:
                domain_word_list.append(part)

        feature.append(len(domain_word_list))
        feature.extend(combined_word(combined_word_list))
        feature.append(calculate_entropy(domain))

        manual_feature = np.array(feature, dtype=np.float32)

        # 2. fastText 语义特征
        ft_vector = domain_to_fasttext_vector(
            domain,
            ft_model,
            vector_size=vector_size
        )
        final_feature = np.concatenate([manual_feature, ft_vector])

        result.append(final_feature)

    return np.array(result, dtype=np.float32)