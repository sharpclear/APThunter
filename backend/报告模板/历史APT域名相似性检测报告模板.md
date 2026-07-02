# APTHunter 历史APT域名相似性检测报告

报告编号：{{ report_no }}

生成时间：{{ generated_at }}

## 一、报告基本信息

| 项目 | 内容 | 项目 | 内容 |
| --- | --- | --- | --- |
| 任务编号 | {{ task_id | mdcell }} | 检测模型 | {{ model_name | mdcell }} |
| 数据来源 | {{ data_source_label | mdcell }} | 检测范围 | {{ detection_scope | mdcell }} |
| 报告类型 | PDF | 生成时间 | {{ generated_at | mdcell }} |
| 检测域名总数 | {{ total }} | 命中域名数量 | {{ hit_count }} |
| 未命中域名数 | {{ normal_count }} | 命中占比 | {{ rate_text }} |
| 最低相似度 | {{ min_score_text }} | TopK 召回数量 | {{ top_k }} |

## 二、总体检测结论

{{ conclusion }}

## 三、真实算法流程

- 加载历史APT及恶意域名样本，完成域名规范化、去重和历史样本索引准备。
- 基于字符级 TF-IDF 对待测域名召回 TopK 历史相似样本。
- 对候选样本计算编辑距离、Jaro-Winkler、公共前后结构、token 重合、数字位置和长度相似等特征。
- 根据综合相似度与最低相似度阈值判定历史APT相似域名，并输出命中原因和匹配历史域名。

| 指标 | 数值 | 指标 | 数值 |
| --- | --- | --- | --- |
| 历史样本数 | {{ history_domains }} | 索引样本数 | {{ index_seeds }} |
| 历史匹配对数 | {{ candidate_pairs }} | 有效输入数 | {{ valid_count }} |
| 无效输入数 | {{ invalid_count }} | 重复输入数 | {{ duplicate_count }} |

## 四、风险等级分布

| 风险等级 | 域名数量 | 占比 | 处置建议 |
| --- | --- | --- | --- |
{% for item in risk_levels -%}
| {{ item.level | mdcell }} | {{ item.count }} | {{ item.percent }} | {{ item.action | mdcell }} |
{% endfor %}

## 五、历史APT相似域名清单

| 域名 | 综合相似度 | 匹配历史APT域名 | 命中原因 |
| --- | --- | --- | --- |
{% for item in top_domains -%}
| {{ item.domain | mdcell }} | {{ item.score }} | {{ item.matched_domain | mdcell }} | {{ item.reason | mdcell }} |
{% endfor %}

## 六、命中特征概览

| 命中原因 | 域名数量 | 占比 |
| --- | --- | --- |
{% for item in feature_overview -%}
| {{ item.reason | mdcell }} | {{ item.count }} | {{ item.percent }} |
{% endfor %}

{% if matched_history %}
| 被匹配历史APT域名 | 匹配次数 |
| --- | --- |
{% for item in matched_history -%}
| {{ item.domain | mdcell }} | {{ item.count }} |
{% endfor %}
{% endif %}

## 七、处置建议

- 优先复核综合相似度高、命中原因多或重复匹配同一历史APT域名的对象。
- 如域名同时具备新注册、可疑解析、证书复用或外部情报命中，应提升处置优先级。
- 对严重和高危域名可先进行 DNS、代理网关或防火墙阻断；对中危和待确认域名建议加入持续监测列表。
- 未命中域名不代表绝对安全，建议结合后续新注册数据、访问日志和基础设施变化持续复检。

## 八、报告结论

{{ final_conclusion }}
