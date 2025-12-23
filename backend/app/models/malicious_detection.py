import os
import numpy as np
import joblib
import pandas as pd
import utils_ML
import io
from typing import List, Dict, Tuple, Optional, Any

# 设置全局变量 keywords（feature_extract 函数中的 edit_dist 需要用到）
# 需要在调用 feature_extract 之前设置
utils_ML.keywords = ['gov', 'pk', 'mail', 'serve']

# 基准目录：models 目录的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# 模型缓存（避免重复加载同一模型）
_model_cache: Dict[str, Tuple[Any, Any]] = {}


def _get_scaler_path_from_model_path(model_path: str) -> str:
    """
    根据模型路径生成标准化器路径
    
    规则：将文件名中的 'model' 替换为 'scaler'
    例如：saved_model/model_123.pkl -> saved_model/scaler_123.pkl
    
    参数:
        model_path: 模型文件的相对路径（相对于 models 目录）或绝对路径
    
    返回:
        scaler_path: 标准化器文件的路径
    """
    # 如果是相对路径，转换为绝对路径
    if not os.path.isabs(model_path):
        model_path_abs = os.path.join(current_dir, model_path)
    else:
        model_path_abs = model_path
    
    # 获取目录和文件名
    dir_name = os.path.dirname(model_path_abs)
    file_name = os.path.basename(model_path_abs)
    
    # 将文件名中的 'model' 替换为 'scaler'
    scaler_file_name = file_name.replace('model', 'scaler', 1)
    scaler_path = os.path.join(dir_name, scaler_file_name)
    
    return scaler_path


def load_model(model_path: Optional[str] = None):
    """
    加载模型和标准化器
    
    参数:
        model_path: 模型文件的相对路径（相对于 models 目录）或绝对路径
                   如果为 None，则使用默认路径（向后兼容）
    
    返回:
        (model, scaler): 模型和标准化器的元组
    """
    # 如果没有指定路径，使用默认路径（向后兼容）
    if model_path is None:
        model_path = os.path.join('saved_model', 'svm_model2.pkl')
    
    # 转换为绝对路径并规范化（移除 ../ 等符号）
    if not os.path.isabs(model_path):
        model_path_abs = os.path.normpath(os.path.abspath(os.path.join(current_dir, model_path)))
    else:
        model_path_abs = os.path.normpath(os.path.abspath(model_path))
    
    # 使用规范化后的绝对路径作为缓存键，避免同一模型被重复加载
    cache_key = model_path_abs
    if cache_key in _model_cache:
        return _model_cache[cache_key]
    
    # 验证模型文件是否存在
    if not os.path.exists(model_path_abs):
        raise FileNotFoundError(f"模型文件不存在: {model_path_abs}")
    
    # 生成标准化器路径
    scaler_path_abs = _get_scaler_path_from_model_path(model_path_abs)
    
    # 验证标准化器文件是否存在
    if not os.path.exists(scaler_path_abs):
        raise FileNotFoundError(f"标准化器文件不存在: {scaler_path_abs}")
    
    try:
        # 加载模型
        model = joblib.load(model_path_abs)
        print(f"✅ 模型加载成功: {model_path_abs}")
    except Exception as e:
        print(f"❌ 模型加载失败: {e}")
        raise
    
    try:
        # 加载标准化器
        scaler = joblib.load(scaler_path_abs)
        print(f"✅ 标准化器加载成功: {scaler_path_abs}")
    except Exception as e:
        print(f"❌ 标准化器加载失败: {e}")
        raise
    
    # 缓存模型和标准化器（使用规范化后的绝对路径作为键）
    _model_cache[cache_key] = (model, scaler)
    
    return model, scaler


def predict_malicious_domains(domains: List[str], model_path: Optional[str] = None):
    """
    对域名列表进行恶意性检测
    
    参数:
        domains: 域名列表，如 ['example.com', 'malicious-domain.org']
        model_path: 模型文件的相对路径（相对于 models 目录）或绝对路径
                   如果为 None，则使用默认路径（向后兼容）
    
    返回:
        results: 字典列表，包含域名、预测标签和预测结果
    """
    if not domains:
        print("⚠️  警告: 域名列表为空")
        return []
    
    # 加载模型和标准化器
    model, scaler = load_model(model_path)
    
    print(f"\n开始处理 {len(domains)} 个域名...")
    print("=" * 60)
    
    # 1. 提取特征
    print("📊 正在提取特征...")
    try:
        features = utils_ML.feature_extract(domains)
        features = np.array(features)
        print(f"✅ 特征提取完成，特征维度: {features.shape}")
    except Exception as e:
        print(f"❌ 特征提取失败: {e}")
        raise
    
    # 2. 标准化特征
    print("📏 正在标准化特征...")
    try:
        features_scaled = scaler.transform(features)
        print("✅ 特征标准化完成")
    except Exception as e:
        print(f"❌ 特征标准化失败: {e}")
        raise
    
    # 3. 预测
    print("🔮 正在进行预测...")
    try:
        predictions = model.predict(features_scaled)
        print("✅ 预测完成")
    except Exception as e:
        print(f"❌ 预测失败: {e}")
        raise
    
    # 4. 处理预测结果
    results = []
    malicious_count = 0
    benign_count = 0
    
    for i, (domain, label) in enumerate(zip(domains, predictions)):
        result = {
            '域名': domain,
            '预测标签': int(label),
            '预测结果': '恶意' if label == 1 else '正常'
        }
        results.append(result)
        
        if label == 1:
            malicious_count += 1
        else:
            benign_count += 1
    
    # 5. 打印统计信息
    print("\n" + "=" * 60)
    print("📈 预测统计:")
    print(f"  总域名数: {len(domains)}")
    print(f"  恶意域名: {malicious_count} 个")
    print(f"  正常域名: {benign_count} 个")
    print(f"  恶意域名占比: {malicious_count/len(domains)*100:.2f}%")
    print("=" * 60)
    
    # 6. 打印详细结果
    print("\n📋 详细预测结果:")
    print("-" * 60)
    print(f"{'序号':<6} {'域名':<40} {'标签':<8} {'结果':<8}")
    print("-" * 60)
    
    for i, result in enumerate(results, 1):
        print(f"{i:<6} {result['域名']:<40} {result['预测标签']:<8} {result['预测结果']:<8}")
        
        # 如果是恶意域名，高亮显示
        if result['预测标签'] == 1:
            print(f"      ⚠️  检测到恶意域名!")
    
    print("-" * 60)
    
    # 7. 如果有恶意域名，单独列出
    if malicious_count > 0:
        print(f"\n⚠️  检测到的恶意域名列表 ({malicious_count} 个):")
        print("-" * 60)
        for i, result in enumerate(results, 1):
            if result['预测标签'] == 1:
                print(f"  {i}. {result['域名']}")
        print("-" * 60)
    
    return results


def read_domains_from_file(file_content: bytes, filename: str) -> List[str]:
    """
    从文件内容（bytes）中读取域名列表
    
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
            # 读取CSV文件
            df = pd.read_csv(io.BytesIO(file_content))
            # 假设第一列是域名，或者查找包含"domain"的列
            if 'domain' in df.columns:
                domains = df['domain'].dropna().tolist()
            else:
                # 使用第一列
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
        elif file_ext == "xlsx":
            # 读取Excel文件
            df = pd.read_excel(io.BytesIO(file_content))
            # 假设第一列是域名，或者查找包含"domain"的列
            if 'domain' in df.columns:
                domains = df['domain'].dropna().tolist()
            else:
                # 使用第一列
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
        elif file_ext == "txt":
            # 读取TXT文件，每行一个域名
            content = file_content.decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):  # 跳过空行和注释行
                    domains.append(line)
        else:
            raise ValueError(f"不支持的文件类型: {file_ext}")
        
        # 过滤空值和无效域名
        domains = [d for d in domains if d and isinstance(d, str) and d.strip()]
        
        return domains
    except Exception as e:
        raise ValueError(f"读取文件失败: {str(e)}")


def _generate_excel_and_stats(results: List[Dict]) -> Tuple[bytes, Dict]:
    df = pd.DataFrame(results)
    malicious_count = sum(1 for r in results if r['预测标签'] == 1)
    benign_count = len(results) - malicious_count

    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='预测结果', index=False)

        stats_df = pd.DataFrame({
            '统计项': ['总域名数', '恶意域名数', '正常域名数', '恶意域名占比'],
            '数值': [
                len(results),
                malicious_count,
                benign_count,
                f"{malicious_count / len(results) * 100:.2f}%"
            ]
        })
        stats_df.to_excel(writer, sheet_name='统计信息', index=False)

        if malicious_count > 0:
            malicious_df = pd.DataFrame([r for r in results if r['预测标签'] == 1])
            malicious_df.to_excel(writer, sheet_name='恶意域名列表', index=False)

    excel_bytes = excel_buffer.getvalue()
    statistics = {
        'total': len(results),
        'malicious': malicious_count,
        'benign': benign_count,
        'malicious_rate': malicious_count / len(results) * 100
    }
    return excel_bytes, statistics


def predict_from_domains(domains: List[str], source_label: Optional[str] = None, model_path: Optional[str] = None) -> Tuple[bytes, Dict]:
    """
    直接从域名列表进行检测
    
    参数:
        domains: 域名列表
        source_label: 数据源标签（可选，用于日志）
        model_path: 模型文件的相对路径（相对于 models 目录）或绝对路径
    """
    if not domains:
        raise ValueError("域名列表为空")
    results = predict_malicious_domains(domains, model_path)
    return _generate_excel_and_stats(results)


def predict_from_file(file_content: bytes, filename: str, model_path: Optional[str] = None) -> Tuple[bytes, Dict]:
    """
    从文件内容进行恶意域名检测并生成结果Excel文件
    
    参数:
        file_content: 文件内容的bytes
        filename: 原始文件名
        model_path: 模型文件的相对路径（相对于 models 目录）或绝对路径
    """
    domains = read_domains_from_file(file_content, filename)
    if not domains:
        raise ValueError("文件中没有找到有效的域名")
    return predict_from_domains(domains, filename, model_path)


if __name__ == "__main__":
    # 测试用例
    test_domains = [
        'google.com',
        'example.org',
        'mofa-services-server.top',
        'www-army-mil-bd.dirctt88.co',
    ]
    
    print("🚀 恶意域名检测系统")
    print("=" * 60)
    
    # 执行预测
    results = predict_malicious_domains(test_domains)
    
    # 可选: 将结果保存为 DataFrame 并导出
    # df = pd.DataFrame(results)
    # print("\n💾 保存结果到文件...")
    # output_path = os.path.join(current_dir, 'prediction_results.xlsx')
    # df.to_excel(output_path, index=False)
    # print(f"✅ 结果已保存到: {output_path}")

