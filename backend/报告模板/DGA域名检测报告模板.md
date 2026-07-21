# APTHunter DGA域名检测报告

报告编号：{{ report_no }}

生成时间：{{ generated_at }}

## 一、报告基本信息

| 项目 | 内容 | 项目 | 内容 |
| --- | --- | --- | --- |
| 任务编号 | {{ task_id | mdcell }} | 检测模型 | {{ model_name | mdcell }} |
| 数据来源 | {{ data_source_label | mdcell }} | 检测范围 | {{ detection_scope | mdcell }} |
| 报告类型 | PDF | 生成时间 | {{ generated_at | mdcell }} |
| 检测域名总数 | {{ total }} | 高置信DGA域名数 | {{ dga_count }} |
| DGA候选数 | {{ candidate_count }} | 正常域名数 | {{ normal_count }} |
| 高置信DGA占比 | {{ dga_rate_text }} | 候选阈值 | {{ candidate_threshold_text }} |
| 主模型高置信数 | {{ direct_count }} | 家族确认提升数 | {{ family_promoted_count }} |

## 二、总体检测结论

{{ conclusion }}

## 三、真实算法流程

- 对输入域名进行规范化、去重和 SLD 拆解，过滤空值和异常输入。
- 使用本地 DGA 主模型对域名进行序列特征评分，输出 DGA_score 和候选标签。
- 对达到候选阈值的域名进入 DGA 家族识别流程，结合序列 GRU 家族模型和审计阈值判断家族归因是否可展示。
- 按真实检测口径输出高置信DGA：主模型直接高置信，或 DGA_score 达到候选阈值且家族识别可展示。
- 输出预测结果、命中方式、DGA家族、家族置信度、组织关联线索和命中原因，用于在线查看、预警和报告归档。

| 指标 | 数值 | 指标 | 数值 |
| --- | --- | --- | --- |
| 有效输入数 | {{ valid_count }} | 无效输入数 | {{ invalid_count }} |
| 重复输入数 | {{ duplicate_count }} | 检测口径 | {{ detection_policy | mdcell }} |
| 家族识别域名数 | {{ family_attributed_count }} | 识别家族种类数 | {{ unique_family_count }} |

## 四、风险分布

| 风险类别 | 域名数量 | 占比 | 处置建议 |
| --- | --- | --- | --- |
{% for item in risk_levels -%}
| {{ item.level | mdcell }} | {{ item.count }} | {{ item.percent }} | {{ item.action | mdcell }} |
{% endfor %}

## 五、高置信DGA域名清单

| 域名 | DGA_score | 命中方式 | DGA家族 | 家族置信度 | APT组织名 | 关联方式 |
| --- | --- | --- | --- | --- | --- | --- |
{% for item in top_domains -%}
| {{ item.domain | mdcell }} | {{ item.score }} | {{ item.hit_type | mdcell }} | {{ item.family | mdcell }} | {{ item.family_confidence }} | {{ item.apt_organization_names | mdcell }} | {{ item.apt_relationship_types_cn | mdcell }} |
{% endfor %}

## 六、DGA家族统计

| DGA家族 | 高置信DGA数量 | 占比 |
| --- | --- | --- |
{% for item in family_overview -%}
| {{ item.family | mdcell }} | {{ item.count }} | {{ item.percent }} |
{% endfor %}

## 七、命中方式统计

| 命中方式 | 域名数量 | 占比 |
| --- | --- | --- |
{% for item in hit_type_overview -%}
| {{ item.hit_type | mdcell }} | {{ item.count }} | {{ item.percent }} |
{% endfor %}

## 八、处置建议

- 优先复核高 DGA_score、家族识别状态为可展示、或由家族确认提升为高置信的域名。
- 对确认异常的高置信DGA域名建议在 DNS、代理网关、防火墙或威胁情报平台中阻断，并回溯历史访问记录。
- 对 DGA候选但未达到高置信口径的域名建议加入持续观察，重点关注解析、证书、注册商和访问行为变化。
- 对识别出的高频家族建议结合外部情报、内部日志和关联基础设施进一步确认攻击活动背景。

## 九、报告结论

{{ final_conclusion }}
