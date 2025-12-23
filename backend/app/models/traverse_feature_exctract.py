import os
import zipfile
from utils_ML import feature_extract
import numpy as np

# 指定文件夹路径
#top_folder_path = 'E:\项目\APT组织域名预测\预测结果\\traverse'
#top_folder_path = 'E:\项目\APT组织域名预测\预测结果\在野'
top_folder_path = 'E:\项目\APT组织域名预测\预测结果\\test'

# 遍历顶层文件夹中的所有文件和子文件夹
for item in os.listdir(top_folder_path):
    item_path = os.path.join(top_folder_path, item)

    # 检查是否是zip压缩文件
    if item.endswith('.zip') and os.path.isfile(item_path):
        print(f"正在解压文件: {item_path}")

        # 创建解压目录（使用zip文件名去掉扩展名作为目录名）
        extract_dir = os.path.join(top_folder_path, os.path.splitext(item)[0])
        os.makedirs(extract_dir, exist_ok=True)

        # 解压zip文件
        with zipfile.ZipFile(item_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)

        # 删除原始zip文件
        os.remove(item_path)
        print(f"已删除原始压缩文件: {item_path}")

        # 将解压后的目录作为新的folder_path
        folder_path = extract_dir
    else:
        # 如果不是zip文件，直接使用原路径
        folder_path = item_path

    print("folder_path为", folder_path)
    file_path = os.path.join(folder_path, 'dailyupdate.txt')

    if os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # 处理文件内容
        domains = []
        for line in lines:
            line = line.strip()
            domains.append(line)

        # 特征提取
        X = feature_extract(domains)
        X = np.array(X)

        # 保存提取好的特征
        np.save(os.path.join(folder_path, 'features.npy'), X)


