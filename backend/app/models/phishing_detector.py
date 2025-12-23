import os
import zipfile
import numpy as np
import torch
from transformers import CanineTokenizer, CanineModel
from sklearn.metrics.pairwise import cosine_similarity
from collections import OrderedDict
import pandas as pd
from datetime import datetime
from tqdm import tqdm
from typing import List, Tuple
import io

# 新增部分：初始化CANINE模型
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"使用设备: {device}")

# 使用基于脚本文件位置的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))
pretrained_model_path = os.path.join(current_dir, 'pretrained_model', 'canine-s')

# 延迟加载模型，避免导入时立即加载
tokenizer = None
model = None

def _ensure_models_loaded():
    """确保模型已加载，延迟加载模式"""
    global tokenizer, model
    if tokenizer is None or model is None:
        if not os.path.exists(pretrained_model_path):
            raise FileNotFoundError(f"CANINE模型路径不存在: {pretrained_model_path}")
        print(f"正在加载CANINE模型: {pretrained_model_path}")
        tokenizer = CanineTokenizer.from_pretrained(pretrained_model_path)
        model = CanineModel.from_pretrained(pretrained_model_path).to(device)
        print("CANINE模型加载完成")



# 编辑距离函数 - 高效实现（滚动数组优化）
def levenshtein_distance(s1, s2, k):
    """
    计算两个字符串的编辑距离（Levenshtein距离）
    添加提前终止优化：当当前行最小值已超过k时提前返回
    使用滚动数组优化空间复杂度
    """
    m, n = len(s1), len(s2)

    # 长度差过滤：如果长度差大于k，直接返回False
    if abs(m - n) > k:
        return False

    # 创建一个滚动数组 (只存储两行)
    prev_row = list(range(n + 1))
    current_row = [0] * (n + 1)

    # 遍历每一行
    for i in range(1, m + 1):
        current_row[0] = i  # 第一列的值总是等于i

        # 当前行最小值初始化（确保能捕获最小值）
        min_in_row = float('inf')

        # 遍历每一列
        for j in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1

            # 计算操作成本（插入、删除、替换）
            insertion = prev_row[j] + 1
            deletion = current_row[j - 1] + 1
            substitution = prev_row[j - 1] + cost

            # 取最小值作为当前单元格的编辑距离
            current_row[j] = min(insertion, deletion, substitution)

            # 更新当前行最小值
            if current_row[j] < min_in_row:
                min_in_row = current_row[j]

        # 提前终止：如果当前行所有值都已大于k，则后续必然大于k
        if min_in_row > k:
            return False

        # 滚动数组：交换当前行和上一行
        prev_row, current_row = current_row, prev_row

    # 最终编辑距离在prev_row[n]（最后位置的编辑距离）
    return prev_row[n] <= k


# 函数：提取关键部分（二级域名+一级域名）
def extract_key_domain(domain):
    """
    提取关键部分：整个域名去掉点号的部分
    优化处理多层域名结构
    """
    # 转换为小写
    domain_lower = domain.lower()
    # 移除所有点号，保留完整的域名结构
    key_part = domain_lower.replace('.', '')

    return key_part


# 函数：批量生成域名嵌入向量
def generate_embeddings(domains, batch_size=64):
    """使用CANINE模型生成域名嵌入向量"""
    _ensure_models_loaded()  # 确保模型已加载
    embeddings = []

    # 分批处理域名
    for i in range(0, len(domains), batch_size):
        batch_domains = domains[i:i + batch_size]

        # 使用CANINE tokenizer处理文本
        inputs = tokenizer(
            batch_domains,
            padding=True,
            truncation=True,
            return_tensors="pt",
            max_length=128  # 限制最大长度
        ).to(device)

        # 使用模型生成嵌入
        with torch.no_grad():
            outputs = model(**inputs)

        # 平均池化获取域名表示向量
        # 使用注意力掩码计算实际序列长度的平均
        sequence_output = outputs.last_hidden_state
        attention_mask = inputs.attention_mask
        # 扩展维度以匹配序列输出
        mask = attention_mask.unsqueeze(-1).expand(sequence_output.size()).float()
        # 对实际字符的表示求和，然后除以实际字符数量
        sum_embeddings = torch.sum(sequence_output * mask, 1)
        sum_mask = torch.clamp(mask.sum(1), min=1e-9)
        batch_embeddings = sum_embeddings / sum_mask

        embeddings.append(batch_embeddings.cpu().numpy())

    return np.concatenate(embeddings, axis=0)


def read_detection_domains_from_file(file_content: bytes, filename: str) -> List[str]:
    """
    从文件内容读取待检测域名列表（只有一列，每行为一条域名）
    
    参数:
        file_content: 文件内容的bytes
        filename: 文件名，用于判断文件类型
    
    返回:
        domains: 域名列表
    """
    domains = []
    file_ext = filename.split(".")[-1].lower() if "." in filename else ""
    
    try:
        if file_ext == "csv":
            df = pd.read_csv(io.BytesIO(file_content))
            if 'domain' in df.columns:
                domains = df['domain'].dropna().tolist()
            else:
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
        elif file_ext == "xlsx":
            df = pd.read_excel(io.BytesIO(file_content))
            if 'domain' in df.columns:
                domains = df['domain'].dropna().tolist()
            else:
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
        elif file_ext == "txt":
            content = file_content.decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
        else:
            raise ValueError(f"不支持的文件类型: {file_ext}")
        
        domains = [d for d in domains if d and isinstance(d, str) and d.strip()]
        return domains
    except Exception as e:
        raise ValueError(f"读取待检测域名文件失败: {str(e)}")


def read_official_domains_from_file(file_content: bytes, filename: str) -> List[Tuple[str, str]]:
    """
    从文件内容读取官方域名列表（企业名,域名格式）
    
    参数:
        file_content: 文件内容的bytes
        filename: 文件名，用于判断文件类型
    
    返回:
        official_domains: (公司名, 域名)元组列表
    """
    official_domains = []
    file_ext = filename.split(".")[-1].lower() if "." in filename else ""
    
    try:
        if file_ext == "csv":
            # 读取CSV文件
            df = pd.read_csv(io.BytesIO(file_content))
            # 假设第一列是企业名，第二列是域名
            if len(df.columns) >= 2:
                for _, row in df.iterrows():
                    company = str(row.iloc[0]).strip()
                    domain = str(row.iloc[1]).strip()
                    if company and domain:
                        official_domains.append((company, domain))
            else:
                # 尝试按逗号分隔
                content = file_content.decode('utf-8', errors='ignore')
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',', 1)
                        if len(parts) == 2:
                            company = parts[0].strip()
                            domain = parts[1].strip()
                            if company and domain:
                                official_domains.append((company, domain))
        elif file_ext == "xlsx":
            # 读取Excel文件
            df = pd.read_excel(io.BytesIO(file_content))
            # 假设第一列是企业名，第二列是域名
            if len(df.columns) >= 2:
                for _, row in df.iterrows():
                    company = str(row.iloc[0]).strip()
                    domain = str(row.iloc[1]).strip()
                    if company and domain:
                        official_domains.append((company, domain))
        elif file_ext == "txt":
            # 读取TXT文件，每行格式：企业名,域名
            content = file_content.decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        company = parts[0].strip()
                        domain = parts[1].strip()
                        if company and domain:
                            official_domains.append((company, domain))
        else:
            raise ValueError(f"不支持的文件类型: {file_ext}")
        
        return official_domains
    except Exception as e:
        raise ValueError(f"读取官方域名文件失败: {str(e)}")


def detect_phishing_domains(
    official_domains: List[Tuple[str, str]], 
    detection_domains: List[str]
) -> Tuple[pd.DataFrame, dict]:
    """
    检测仿冒域名
    
    参数:
        official_domains: 官方域名列表，每个元素为(公司名, 域名)的元组
        detection_domains: 待检测域名列表
    
    返回:
        df: 包含检测结果的DataFrame，包含列：钓鱼域名、目标域名、公司名称、相似度、匹配类型
        statistics: 统计信息字典
    """
    if not official_domains or not detection_domains:
        return pd.DataFrame(), {"total": 0, "phishing": 0, "benign": 0}
    
    # 创建域名到公司名称的映射
    domain_to_company = {}
    for company, domain in official_domains:
        domain_lower = domain.lower().strip()
        domain_to_company[domain_lower] = company
    
    # 主域名列表（目标域名）
    targets = list(domain_to_company.keys())
    print(f"加载了 {len(targets)} 个目标域名")
    
    if not targets:
        return pd.DataFrame(), {"total": len(detection_domains), "phishing": 0, "benign": len(detection_domains)}
    
    # 提取目标域名的关键部分
    targets_key = [extract_key_domain(target) for target in targets]
    target_to_key = dict(zip(targets, targets_key))
    
    # 计算目标关键部分的长度，用于自适应阈值
    target_key_lengths = {target: len(key) for target, key in zip(targets, targets_key)}
    
    # 编辑距离筛选
    dist_domains = []
    detection_domains_lower = [d.lower().strip() for d in detection_domains]
    
    for domain in detection_domains_lower:
        domain_key = extract_key_domain(domain)
        for target in targets:
            target_key = target_to_key[target]
            
            # 根据关键部分长度自适应调整阈值
            key_len = len(target_key)
            k = max(2, min(6, int(key_len * 0.5)))
            
            # 计算关键部分的编辑距离
            if levenshtein_distance(domain_key, target_key, k):
                dist_domains.append(domain)
                break  # 找到一个匹配即跳出内层循环
    
    print(f"检测到编辑距离匹配的域名数量: {len(dist_domains)}")
    
    # 如果dist_domains为空，则跳过嵌入计算
    phs_domains = []
    combined_similarity_matrix = None
    
    if dist_domains and targets:
        print("开始计算CANINE嵌入...")
        
        # 1. 收集所有需要处理的域名
        all_domains = list(set(dist_domains + targets))
        
        # 提取关键部分
        all_key_domains = [extract_key_domain(domain) for domain in all_domains]
        
        # 2. 生成完整域名的嵌入向量
        full_embeddings = generate_embeddings(all_domains)
        
        # 3. 生成关键部分的嵌入向量
        key_embeddings = generate_embeddings(all_key_domains)
        
        # 4. 创建域名到嵌入向量的映射
        domain_to_full_embedding = {domain: emb for domain, emb in zip(all_domains, full_embeddings)}
        domain_to_key_embedding = {domain: emb for domain, emb in zip(all_domains, key_embeddings)}
        
        # 5. 分离出targets和dist_domains的嵌入向量
        target_full_embeddings = np.array([domain_to_full_embedding[domain] for domain in targets])
        target_key_embeddings = np.array([domain_to_key_embedding[domain] for domain in targets])
        
        dist_full_embeddings = np.array([domain_to_full_embedding[domain] for domain in dist_domains])
        dist_key_embeddings = np.array([domain_to_key_embedding[domain] for domain in dist_domains])
        
        # 6. 计算分层相似度矩阵
        full_similarity_matrix = cosine_similarity(dist_full_embeddings, target_full_embeddings)
        key_similarity_matrix = cosine_similarity(dist_key_embeddings, target_key_embeddings)
        
        # 7. 加权综合相似度
        combined_similarity_matrix = 0.7 * key_similarity_matrix + 0.3 * full_similarity_matrix
        
        # 8. 查找所有满足相似度条件的域名
        similar_domains = []
        for i, domain in enumerate(dist_domains):
            max_sim_idx = np.argmax(combined_similarity_matrix[i])
            target = targets[max_sim_idx]
            key_len = target_key_lengths[target]
            
            # 根据关键部分长度动态调整阈值
            if key_len <= 4:
                threshold = 0.92
            elif key_len <= 6:
                threshold = 0.88
            else:
                threshold = 0.85
            
            # 检查综合相似度是否超过阈值
            if combined_similarity_matrix[i][max_sim_idx] > threshold:
                similar_domains.append(domain)
        
        # 9. 去除重复项
        phs_domains = list(OrderedDict.fromkeys(similar_domains))
        print(f"通过CANINE相似度匹配的钓鱼域名数量: {len(phs_domains)}")
    
    # 找出每个域名对应的目标域名和公司名称
    target_domains = []
    company_names = []
    similarity_info = []
    
    for domain in phs_domains:
        matched_targets = []
        matched_companies = set()
        max_sim = 0.0
        
        if combined_similarity_matrix is not None:
            # 获取域名在dist_domains中的索引
            if domain in dist_domains:
                idx = dist_domains.index(domain)
                max_sim_idx = np.argmax(combined_similarity_matrix[idx])
                target = targets[max_sim_idx]
                matched_targets.append(target)
                if target in domain_to_company:
                    matched_companies.add(domain_to_company[target])
                max_sim = combined_similarity_matrix[idx][max_sim_idx]
        else:
            # 使用编辑距离匹配的目标
            for target in targets:
                if levenshtein_distance(extract_key_domain(domain), target_to_key[target], 3):
                    matched_targets.append(target)
                    if target in domain_to_company:
                        matched_companies.add(domain_to_company[target])
                    break
        
        target_domains.append(",".join(matched_targets))
        company_names.append(",".join(matched_companies))
        similarity_info.append(f"{max_sim:.4f}" if max_sim > 0 else "")
    
    # 创建包含域名的 DataFrame
    if phs_domains:
        df = pd.DataFrame({
            "钓鱼域名": phs_domains,
            "目标域名": target_domains,
            "公司名称": company_names,
            "相似度": similarity_info,
            "匹配类型": "相似度"
        })
    else:
        df = pd.DataFrame(columns=["钓鱼域名", "目标域名", "公司名称", "相似度", "匹配类型"])
    
    # 统计信息
    statistics = {
        "total": len(detection_domains),
        "phishing": len(phs_domains),
        "benign": len(detection_domains) - len(phs_domains),
        "phishing_rate": len(phs_domains) / len(detection_domains) * 100 if detection_domains else 0
    }
    
    return df, statistics


def predict_from_file(
    official_file_content: bytes,
    official_filename: str,
    detection_file_content: bytes | None = None,
    detection_filename: str | None = None,
    detection_domains: List[str] | None = None
) -> Tuple[bytes, dict]:
    """
    从文件内容进行仿冒域名检测并生成结果Excel文件
    
    参数:
        official_file_content: 官方域名文件内容的bytes
        official_filename: 官方域名文件名
        detection_file_content: 待检测域名文件内容的bytes（可选）
        detection_filename: 待检测域名文件名（可选）
        detection_domains: 待检测域名列表（可选，与detection_file_content二选一）
    
    返回:
        excel_bytes: Excel文件的bytes内容
        statistics: 统计信息字典
    """
    # 1. 读取官方域名
    official_domains = read_official_domains_from_file(official_file_content, official_filename)
    if not official_domains:
        raise ValueError("官方域名文件中没有找到有效数据")
    
    # 2. 读取待检测域名
    if detection_domains:
        detection_domains_list = detection_domains
    elif detection_file_content and detection_filename:
        detection_domains_list = read_detection_domains_from_file(detection_file_content, detection_filename)
    else:
        raise ValueError("必须提供待检测域名文件或域名列表")
    
    if not detection_domains_list:
        raise ValueError("待检测域名列表为空")
    
    # 3. 执行检测
    df, statistics = detect_phishing_domains(official_domains, detection_domains_list)
    
    # 4. 生成Excel文件
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
        # 写入检测结果
        if not df.empty:
            df.to_excel(writer, sheet_name='检测结果', index=False)
        else:
            # 如果没有结果，创建一个空表
            empty_df = pd.DataFrame(columns=["钓鱼域名", "目标域名", "公司名称", "相似度", "匹配类型"])
            empty_df.to_excel(writer, sheet_name='检测结果', index=False)
        
        # 创建统计信息工作表
        stats_df = pd.DataFrame({
            '统计项': ['总域名数', '钓鱼域名数', '正常域名数', '钓鱼域名占比'],
            '数值': [
                statistics.get('total', 0),
                statistics.get('phishing', 0),
                statistics.get('benign', 0),
                f"{statistics.get('phishing_rate', 0):.2f}%"
            ]
        })
        stats_df.to_excel(writer, sheet_name='统计信息', index=False)
        
        # 如果有钓鱼域名，单独创建一个工作表
        if not df.empty and len(df) > 0:
            df.to_excel(writer, sheet_name='钓鱼域名列表', index=False)
    
    excel_bytes = excel_buffer.getvalue()
    
    return excel_bytes, statistics


def predict_from_domains(
    official_domains: List[Tuple[str, str]],
    detection_domains: List[str]
) -> Tuple[bytes, dict]:
    """
    直接从域名列表进行仿冒域名检测并生成结果Excel文件
    
    参数:
        official_domains: 官方域名列表，每个元素为(公司名, 域名)的元组
        detection_domains: 待检测域名列表
    
    返回:
        excel_bytes: Excel文件的bytes内容
        statistics: 统计信息字典
    """
    if not official_domains:
        raise ValueError("官方域名列表为空")
    if not detection_domains:
        raise ValueError("待检测域名列表为空")
    
    # 执行检测
    df, statistics = detect_phishing_domains(official_domains, detection_domains)
    
    # 生成Excel文件
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
        # 写入检测结果
        if not df.empty:
            df.to_excel(writer, sheet_name='检测结果', index=False)
        else:
            empty_df = pd.DataFrame(columns=["钓鱼域名", "目标域名", "公司名称", "相似度", "匹配类型"])
            empty_df.to_excel(writer, sheet_name='检测结果', index=False)
        
        # 创建统计信息工作表
        stats_df = pd.DataFrame({
            '统计项': ['总域名数', '钓鱼域名数', '正常域名数', '钓鱼域名占比'],
            '数值': [
                statistics.get('total', 0),
                statistics.get('phishing', 0),
                statistics.get('benign', 0),
                f"{statistics.get('phishing_rate', 0):.2f}%"
            ]
        })
        stats_df.to_excel(writer, sheet_name='统计信息', index=False)
        
        # 如果有钓鱼域名，单独创建一个工作表
        if not df.empty and len(df) > 0:
            df.to_excel(writer, sheet_name='钓鱼域名列表', index=False)
    
    excel_bytes = excel_buffer.getvalue()
    
    return excel_bytes, statistics