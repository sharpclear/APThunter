# APTHunter 模板化APT域名检测报告

报告编号：{{ report_no }}

生成时间：{{ generated_at }}

## 一、报告基本信息

| 项目 | 内容 | 项目 | 内容 |
| --- | --- | --- | --- |
| 任务编号 | {{ task_id | mdcell }} | 检测模型 | {{ model_name | mdcell }} |
| 数据来源 | {{ data_source_label | mdcell }} | 检测范围 | {{ detection_scope | mdcell }} |
| 报告类型 | PDF | 生成时间 | {{ generated_at | mdcell }} |
| 检测域名总数 | {{ total }} | 模板化APT域名数 | {{ matched_count }} |
| 高风险域名数 | {{ high_risk_count }} | 正常域名数 | {{ normal_count }} |
| 模板化APT域名占比 | {{ matched_rate_text }} | 高风险域名占比 | {{ high_risk_rate_text }} |
| 预警阈值 | {{ score_threshold_text }} | 模板数量 | {{ template_count }} |

## 二、总体检测结论

{{ conclusion }}

## 三、真实算法流程

- 加载模板化APT域名模板库，读取模板、判定依据、模板命中注册域名数和原始行数。
- 对待检测域名进行规范化解析，拆解注册域名、SLD 和后缀。
- 将模板编译为匹配规则，支持固定 token、可变 token 和指定后缀或通配后缀。
- 命中模板后根据模板结构、固定 token 数量、通配 token 数量、后缀约束和模板历史命中规模计算风险分。
- 风险分达到预警阈值的域名进入高风险列表，并保留匹配模板、变量 JSON 和命中原因。

| 指标 | 数值 | 指标 | 数值 |
| --- | --- | --- | --- |
| 模板数量 | {{ template_count }} | 高风险阈值 | {{ score_threshold_text }} |
| 有效输入数 | {{ valid_count }} | 无效输入数 | {{ invalid_count }} |
| 重复输入数 | {{ duplicate_count }} | 命中模板数量 | {{ matched_template_count }} |

## 四、风险等级分布

| 风险等级 | 域名数量 | 占比 | 处置建议 |
| --- | --- | --- | --- |
{% for item in risk_levels -%}
| {{ item.level | mdcell }} | {{ item.count }} | {{ item.percent }} | {{ item.action | mdcell }} |
{% endfor %}

## 五、模板化APT域名清单

| 域名 | 风险分 | 风险等级 | 匹配模板 | 命中原因 |
| --- | --- | --- | --- | --- |
{% for item in top_domains -%}
| {{ item.domain | mdcell }} | {{ item.score }} | {{ item.risk_level | mdcell }} | {{ item.template | mdcell }} | {{ item.reason | mdcell }} |
{% endfor %}

## 六、命中模板统计

| 匹配模板 | 命中数量 | 占比 |
| --- | --- | --- |
{% for item in template_overview -%}
| {{ item.template | mdcell }} | {{ item.count }} | {{ item.percent }} |
{% endfor %}

## 七、命中特征与样本依据

| 命中原因 | 域名数量 | 占比 |
| --- | --- | --- |
{% for item in reason_overview -%}
| {{ item.reason | mdcell }} | {{ item.count }} | {{ item.percent }} |
{% endfor %}

## 八、处置建议

- 优先复核风险分高、模板命中规模大、固定 token 较多或命中多个敏感业务词的域名。
- 对高风险域名建议结合 DNS 解析、证书、WHOIS、访问日志和外部情报完成二次研判。
- 对确认异常的域名可在 DNS、代理网关、防火墙或威胁情报平台中阻断，并回溯历史访问记录。
- 对中低风险但命中模板的域名建议纳入持续监测，关注解析变更和后续新增相似域名。

## 九、报告结论

{{ final_conclusion }}
