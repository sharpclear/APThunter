import numpy as np
import pandas as pd
import re
import math
import os
from collections import Counter

import torch
from transformers import CanineTokenizer, CanineModel

from wordsegment import load, segment


# =========================
# 本地 CANINE 模型路径配置
# =========================

# 默认使用项目内置的本地 CANINE 模型目录（相对于当前文件）
DEFAULT_CANINE_MODEL_PATH = os.path.normpath(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "pretrained_model", "canine-s")
    )
)


# =========================
# CANINE 相关缓存
# =========================

_CANINE_TOKENIZER_CACHE = None
_CANINE_MODEL_CACHE = None


def get_device(device=None):
    """
    获取运行设备。
    如果不指定 device，则优先使用 cuda，否则使用 cpu。
    """
    if device is not None:
        return torch.device(device)

    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_canine_model(model_path=None, device=None):
    """
    加载本地离线 CANINE 模型和 tokenizer。
    """
    global _CANINE_TOKENIZER_CACHE
    global _CANINE_MODEL_CACHE

    if _CANINE_TOKENIZER_CACHE is not None and _CANINE_MODEL_CACHE is not None:
        return _CANINE_TOKENIZER_CACHE, _CANINE_MODEL_CACHE

    if model_path is None:
        model_path = os.getenv("ATDV_CANINE_MODEL_PATH", DEFAULT_CANINE_MODEL_PATH)

    if not os.path.isdir(model_path):
        raise FileNotFoundError(f"CANINE 本地模型目录不存在: {model_path}")

    config_path = os.path.join(model_path, "config.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"CANINE 模型目录中缺少 config.json: {config_path}"
        )

    has_safetensors = os.path.exists(os.path.join(model_path, "model.safetensors"))
    has_pytorch_bin = os.path.exists(os.path.join(model_path, "pytorch_model.bin"))

    if not has_safetensors and not has_pytorch_bin:
        raise FileNotFoundError(
            f"CANINE 模型目录中未找到 model.safetensors 或 pytorch_model.bin: {model_path}"
        )

    device = get_device(device)

    print(f"Loading local CANINE tokenizer from {model_path}...")
    tokenizer = CanineTokenizer.from_pretrained(
        model_path,
        local_files_only=True
    )

    print(f"Loading local CANINE model from {model_path}...")
    model = CanineModel.from_pretrained(
        model_path,
        local_files_only=True
    )

    model.to(device)
    model.eval()

    print(
        f"CANINE model loaded. "
        f"hidden_size={model.config.hidden_size}, "
        f"device={device}"
    )

    _CANINE_TOKENIZER_CACHE = tokenizer
    _CANINE_MODEL_CACHE = model

    return _CANINE_TOKENIZER_CACHE, _CANINE_MODEL_CACHE


def reduce_768_to_128_by_group_mean(vectors):
    """
    将 CANINE 的 768 维向量通过分组平均池化降到 128 维。

    原理：
        768 / 128 = 6

    即每 6 维取平均，得到 1 维。

    输入：
        vectors shape = (768,)
        或
        vectors shape = (N, 768)

    输出：
        shape = (128,)
        或
        shape = (N, 128)
    """
    vectors = np.asarray(vectors, dtype=np.float32)

    if vectors.ndim == 1:
        if vectors.shape[0] != 768:
            raise ValueError(f"期望输入 768 维向量，实际得到 {vectors.shape[0]} 维")
        return vectors.reshape(128, 6).mean(axis=1).astype(np.float32)

    if vectors.ndim == 2:
        if vectors.shape[1] != 768:
            raise ValueError(f"期望输入 shape=(N, 768)，实际得到 {vectors.shape}")
        return vectors.reshape(vectors.shape[0], 128, 6).mean(axis=2).astype(np.float32)

    raise ValueError(f"不支持的向量维度: {vectors.shape}")


def canine_mean_pooling(last_hidden_state, attention_mask):
    """
    对 CANINE 输出的 hidden states 做 mean pooling。

    last_hidden_state:
        shape = (batch_size, seq_len, hidden_size)

    attention_mask:
        shape = (batch_size, seq_len)

    输出：
        shape = (batch_size, hidden_size)
    """
    mask = attention_mask.unsqueeze(-1).float()
    masked_hidden = last_hidden_state * mask

    sum_hidden = masked_hidden.sum(dim=1)
    token_count = mask.sum(dim=1).clamp(min=1e-9)

    pooled = sum_hidden / token_count
    return pooled


def domains_to_canine_vectors(
    domains,
    tokenizer=None,
    model=None,
    model_path=None,
    batch_size=64,
    max_length=128,
    device=None,
    reduce_to_128=True
):
    """
    批量提取域名的 CANINE 深层特征。

    默认流程：
        域名字符串
        -> 本地 CANINE-S
        -> mean pooling 得到 768 维向量
        -> 每 6 维平均池化降到 128 维

    返回：
        reduce_to_128=True:
            shape = (N, 128)

        reduce_to_128=False:
            shape = (N, 768)
    """
    if tokenizer is None or model is None:
        tokenizer, model = load_canine_model(
            model_path=model_path,
            device=device
        )

    device = next(model.parameters()).device

    all_vectors = []

    for start in range(0, len(domains), batch_size):
        batch_domains = domains[start:start + batch_size]

        encoded = tokenizer(
            batch_domains,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt"
        )

        encoded = {k: v.to(device) for k, v in encoded.items()}

        with torch.no_grad():
            outputs = model(**encoded)

            pooled = canine_mean_pooling(
                outputs.last_hidden_state,
                encoded["attention_mask"]
            )

        batch_vectors = pooled.detach().cpu().numpy().astype(np.float32)

        if reduce_to_128:
            batch_vectors = reduce_768_to_128_by_group_mean(batch_vectors)

        all_vectors.append(batch_vectors)

    return np.vstack(all_vectors).astype(np.float32)


# =========================
# 域名标准化
# =========================

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


# =========================
# 人工特征函数
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


def extract_manual_features(domains):
    """
    提取人工特征。

    输出：
        shape = (N, 18)
    """
    result = []

    load()

    for domain in domains:
        domain = normalize_domain(domain)

        feature = []
        combined_word_list = []
        domain_word_list = []

        # 1. 长度、结构、字符统计特征
        feature.extend(length(domain))
        feature.extend(count_subdomain(domain))
        feature.extend(consecutive(domain))
        feature.extend(count_special_char(domain))
        feature.extend(count_digit(domain))
        feature.extend(known_top(domain))

        # 2. 分隔符切分
        parts = re.split(r'[-—._]', domain)
        parts = [part for part in parts if part]

        # 3. 原始词统计
        feature.extend(raw_word(parts))

        # 4. 长字符串分词统计
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

        # 5. 分割词总数
        feature.append(len(domain_word_list))

        # 6. 组合词统计
        feature.extend(combined_word(combined_word_list))

        # 7. 信息熵
        feature.append(calculate_entropy(domain))

        result.append(np.array(feature, dtype=np.float32))

    return np.array(result, dtype=np.float32)


# =========================
# 融合人工特征 + 本地 CANINE 特征
# =========================

def feature_extract(
    domains,
    tokenizer=None,
    model=None,
    model_path=None,
    batch_size=64,
    max_length=128,
    device=None,
    use_canine=True
):
    """
    提取最终域名特征。

    use_canine=False:
        只输出人工特征，维度为 18。

    use_canine=True:
        人工特征 18 维 + CANINE 分组平均池化特征 128 维
        最终输出 146 维。
    """
    normalized_domains = [normalize_domain(domain) for domain in domains]

    # 1. 人工特征
    manual_features = extract_manual_features(normalized_domains)

    if not use_canine:
        return manual_features

    # 2. 本地 CANINE 深层特征，默认 768 -> 128
    canine_features = domains_to_canine_vectors(
        normalized_domains,
        tokenizer=tokenizer,
        model=model,
        model_path=model_path,
        batch_size=batch_size,
        max_length=max_length,
        device=device,
        reduce_to_128=True
    )

    # 3. 拼接最终特征
    final_features = np.concatenate(
        [manual_features, canine_features],
        axis=1
    ).astype(np.float32)

    return final_features
