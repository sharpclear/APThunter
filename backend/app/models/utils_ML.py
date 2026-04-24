import numpy as np
import pandas as pd
import re
import math
from collections import Counter
import Levenshtein
from wordsegment import load, segment


#特征提取
#长度 域名、二级域名和子域名
def length(domain):  #这里统计的分别是二级域名、顶级域名、其余部分的长度，因为域名长度只是这三个的加减组合，故就直接用了前三个
    feature = []
    parts = domain.split('.')
    if len(parts) < 2:
        for i in range(0,3):
            feature.append(0)
    else:
        #主域名
        main_domain = parts[-2] #最后两个部分
        top_level_domain = parts[-1]  #最后一个部分
        #子域名的剩下部分
        subdomains = parts[:-2]  #
        #计算长度
        main_domain_length = len(main_domain)
        top_level_domain_length = len(top_level_domain)
        subdomain_length = sum(len(sub) for sub in subdomains)
        feature.append(main_domain_length)
        feature.append(top_level_domain_length)
        feature.append(subdomain_length)
    return feature

def count_subdomain(domain):  #即二级域名之下的"."的数量
    feature = []
    parts = domain.split('.')
    if len(parts) < 3:
        feature.append(0)
    else:
        subdomain_count = len(parts) - 2
        feature.append(subdomain_count)
    return feature

def consecutive(domain):  #没去除符号，连续的符号也会被统计进去。但如果去除符号，两个本来被符号分开的同一字符又会被统计
    feature = []
    char_list = []
    consecutive_char_list = []
    for char in domain:
        char_list.append(char)
    for i in range(0,len(char_list)-1): #最大长度-1防止访问超出范围
        if char_list[i] == char_list[i + 1]: #判断连续出现
            if char_list[i] not in consecutive_char_list:  #计算种类数
                consecutive_char_list.append(char_list[i])
    consecutive_kind_count = len(consecutive_char_list)
    feature.append(consecutive_kind_count)
    return feature

def count_special_char(domain):  #需要固定特殊字符与特征数组索引对应位置  改为统计"-"的数量
    feature = []
    count = 0
    special = ["-", "—"]
    for char in domain:
        if char in special:
            count += 1
    feature.append(count)
    return feature

def count_digit(domain):
    feature = []
    parts = domain.split('.')

    def count_digits(word):
        return sum(c.isdigit() for c in word)
    if len(parts) < 2:
        #for i in range(0,2):
            #feature.append(0)
        main_domain_digit_count = count_digits(parts)
        subdomain_digit_count = 0
    else:
        main_domain = parts[-2]
        # top_domain = parts[-1]
        subdomains = parts[:-2]
        main_domain_digit_count = count_digits(main_domain)
        # top_domain_digit_count = count_digits(top_domain)
        subdomain_digit_count = sum(count_digits(sub) for sub in subdomains)
    feature.append(main_domain_digit_count+subdomain_digit_count)
    feature.append(subdomain_digit_count)
    #如"11a21.sub12.example456.com",域名数字数为9，子域名数字数为6, 顶级域名一般不出现数字，不参与统计
    return feature


def known_top(domain):
    feature = []
    parts = domain.split('.')
    known_tlds = ["com", "org", "net", "gov", "edu"]
    top_domain = parts[-1]
    if top_domain in known_tlds:
        feature.append(1)
    else: #若没有顶级域名，也算这种情况
        feature.append(0)
    return feature

def raw_word(parts):  #初始单词数、平均、最长、最短词长、初始词长标准差  五个
    feature = []
    raw_word_count = len(parts)
    word_len = []
    for part in parts:
        word_len.append(len(part))
    ave_word_len = sum(word_len)/raw_word_count
    max_word_len = max(word_len)
    min_word_len = min(word_len)
    std_deviation = np.std(word_len)
    feature.append(raw_word_count)
    feature.append(ave_word_len)   #列表可以同时存储不同类型的数据
    feature.append(max_word_len)
    feature.append(min_word_len)
    feature.append(std_deviation)
    return feature

def combined_word(words):  #目前统计的是长度>7的非随机词。  后期结合分词器，将分词器能分出至少两个词的作为相邻词
    feature = []
    num = len(words)
    ave_word_len = 0
    if num>0: #num为0不能做分母
        total_word_len = 0
        for word in words:
            total_word_len += len(word)
        ave_word_len = total_word_len/num
    feature.append(num)
    feature.append(ave_word_len)
    return feature

def calculate_entropy(domain):
    # 统计域名中每个字符的频率
    char_counts = Counter(domain)
    total_chars = len(domain)
    # 计算熵
    entropy = 0.0
    for char, count in char_counts.items():
        prob = count / total_chars
        entropy -= prob * math.log2(prob)
    return entropy

def www_com(parts):
    feature = []
    subdomain = parts[:-1] #列表最后一个之前的所有
    #www, com = 0, 0
    www, com, gov = 0, 0, 0
    for part in subdomain:
        if "www" in part:
            www = 1
        if "com" in part:
            com = 1
        gov += part.count('gov')
    feature.append(www)
    feature.append(com)
    feature.append(gov)
    return feature

def edit_dist(words, min_nums): #恶意性判断
    i = 0
    for keyword in keywords: #每个keyword即特征中每一维
        min = 20
        for word in words:
            dist = Levenshtein.distance(word, keyword)
            if dist < min:  #找域名到某个keyword的最小值
                min = dist
        if min < min_nums[i]: #是否更新某个最小值
            min_nums[i] = min
        i += 1
    #结果中的三维分别对应serve, mail, gov
    return min_nums


def feature_extract(domains):
    result = []
    load()
    for domain in domains:
        # DNS和whois查询特征
        '''dns_data = query_dns(domain)  #dns_data[0]为是否含有缺失值
        if dns_data == 1:
            continue
        else:'''
        #进度条
        w2v_words = []  #输入w2v中的词
        # 人工特征
        feature = []  # 暂定29维
        combined_word_list = []  # 相邻词表
        domain_word_list = []
        feature.extend(length(domain))  # 这里有六个  下面有两个随机性的
        feature.extend(count_subdomain(domain))
        feature.extend(consecutive(domain))
        feature.extend(count_special_char(domain))
        feature.extend(count_digit(domain))
        feature.extend(known_top(domain))
        parts = re.split(r'[-—._]', domain)  # parts ['google','com']
        feature.extend(raw_word(parts))
        # 若有brand name 加在下一行
        '''randomness = 0
        random_count = 0'''
        dists = edit_dist(parts[:-1], [20, 20, 20, 20])  #先对分隔符结果做一遍  顶级域名不参与
        for part in parts:  # part  'google'  'com'
            '''# 判断随机性
            if (is_gibberish(part)):  # 若为随机词 随机性特征设置为1且统计随机字符数
                # 随机性特征设置为1
                randomness = 1
                # 统计随机单词数
                random_count += len(part)
                # 随机字符要参与训练吗
            else:  # 不为随机词，判断长度'''
            if len(part) > 7:  # 较长，再次分词
                #res = Decomposer(part, dists)  #分词，并对所有子串衡量编辑距离
                # 正则表达式去除数字
                without_digit = re.sub(r'\d+', '', part)
                if without_digit:  # 排除某序列全为数字的可能
                    words = segment(without_digit)  #连续词分词
                    #words = res[:-3]
                    #print("分词结果", words)
                    dists = edit_dist(words, dists)
                    #dists = res[-3:]  # 分词器结果最后三位
                    # 相邻单词
                    if len(words)>1: #代表做了分词，即part由多个词组成
                        combined_word_list.append(part)
                    for word in words:
                        domain_word_list.append(word)
            else:
                domain_word_list.append(part)  # 较短，直接加入
        #print("dists为", dists)
        feature.extend(dists)  #关键词特征
        feature.append(len(domain_word_list))  #域名分割出的单词总数
        feature.extend(combined_word(combined_word_list))
        feature.append(calculate_entropy(domain))  #信息熵
        feature.extend(www_com(parts))  #
        '''feature.append(randomness)   #是否随机
        feature.append(random_count)   #随机字符数'''
        # word2vec
        #domain_vector = domain_to_word_vector(domain, domain_word_list,w2v_model)
        # 特征融合
        feature = np.array(feature)
        #hybrid_feature = np.concatenate((domain_vector, feature))
        #result.append(hybrid_feature)  #融合特征
        result.append(feature)  # 融合特征
        #print("shape", hybrid_feature.shape)
    return result


'''data = pd.read_excel('E:\项目\APT组织域名预测\数据集\域名数据\应用数据\应用训练数据.xlsx')

domains = []
labels = []
keywords = ['gov', 'pk', 'mail', 'serve']
a, b, c = 0, 0, 0

if __name__ == "__main__":
    data = data.sample(frac=1).reset_index(drop=True)

    for line in data.values:
        #print(line)
        domains.append(line[0])
        #labels.append(line[1])
        a = a+1
        if line[1]=='白名单':
            b = b+1
            labels.append(0)  #0为负样本
        else:
            c = c+1
            labels.append(1)  #1为正样本，即要识别的样本
    
    
    
    #domains = ['www-army-mil-bd.dirctt88.co']
    #按分隔符分割   分隔符：.  _  -
    
    #预测时注释这两行
    #domains = ['mofa-services-server.top']
    features = feature_extract(domains)
    features = np.array(features)
    np.save('./dataset/提取后的特征/10w/features2.npy', features)
    np.save('./dataset/提取后的特征/10w/labels2.npy', labels)
    #print(features.shape)
    #print(np.array(features))
    #print(word_list)'''












