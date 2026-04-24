import os
import numpy as np
from tqdm import tqdm
import joblib
import pandas as pd
import requests
import socket

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except (socket.gaierror, AttributeError):  #断言
        return None

def get_location(ip):
    try:
        # 发起GET请求，查询IP地址归属地
        response = requests.get(f"{api_url}{ip}/json")
        result = []
        if response.status_code == 200:
            ip_info = response.json()
            result.append(ip_info.get('country'))
            result.append(ip_info.get('city'))
            return result
        else:
            print(f"Error retrieving data for IP: {ip}")
            return "None"
    except Exception as e:
        print(f"Error: {e}")
        return None


#model = joblib.load('./saved_model_ML/SVM_model_2k.pkl')
model = joblib.load('./saved_model_ML/SVM_model2.pkl')
#model = joblib.load('./saved_model_ML/rf_model.pkl')
# model = joblib.load('./saved_model_ML/KNN_model.pkl')
# model = joblib.load('./saved_model_ML/bayes_Ber_model.pkl')
# model = joblib.load('./saved_model_ML/dt_model.pkl')

# 加载标准化器
#scaler = joblib.load('./saved_model_ML/scaler_2k.pkl')
scaler = joblib.load('./saved_model_ML/scaler2.pkl')
# scaler = joblib.load('./saved_model_ML/RF_scaler.pkl')
# scaler = joblib.load('./saved_model_ML/KNN_scaler.pkl')
# scaler = joblib.load('./saved_model_ML/NB_scaler.pkl')
# scaler = joblib.load('./saved_model_ML/DT_scaler.pkl')



# 指定文件夹路径
#top_folder_path = 'E:\项目\APT组织域名预测\预测结果\\traverse'
#top_folder_path = 'E:\项目\APT组织域名预测\预测结果\\在野'
top_folder_path = 'E:\项目\APT组织域名预测\预测结果\\test'





predictions = []
# 遍历文件夹中的所有文件和子文件夹
for folder_name in tqdm(os.listdir(top_folder_path)):
    folder_path = os.path.join(top_folder_path , folder_name)  # 获取文件的完整路径


    # 2. 读取txt文件中的数据
    with open(folder_path + '\dailyupdate.txt', 'r') as file:
        # with open(path, 'r') as file:
        lines = file.readlines()

    domains = []
    # 检查三个字符串
    #targets = ["pipechina"]
    targets = ["crbc", "pdiwt", "ccccltd", "pipechina"]
    # 消除回车\n
    for line in lines:
        line = line.strip()
        domains.append(line)
        '''for target in targets: #crbc
            if target in line:
                predictions.append(line)
                print("三个字符串,", line)'''

    # 第一次预测时使用
    # X = feature_extract(domains)
    # X = np.array(X)

    # 保存提取好的特征
    # np.save(path+'features.npy', X)
    X = np.load(folder_path + '\\features.npy')  # 读取保存的特征

    # 标准化
    X = scaler.transform(X)
    labels = model.predict(X)
    i = 0
    APT = 0
    # print("预测的标签为",labels)
    for label in labels:
        if label == 1:
            APT += 1
            predictions.append(domains[i])
        i += 1
    #print("APT数量为,", APT)
    print("总数为",i)
    # print(predictions)

'''#查ip
ips = []
locations = []
api_url = "http://ipinfo.io/"
for domain in predictions:
    ip = get_ip(domain)
    ips.append(ip)
    location = get_location(ip)
    locations.append(location)'''

#df = {'domain':predictions,'IP':ips,'归属地':locations}
df = {'domain': predictions}
df = pd.DataFrame(df)
print(df)
df.to_excel(top_folder_path+'\ML_SVM_predictions.xlsx',index=False) #导出为excel