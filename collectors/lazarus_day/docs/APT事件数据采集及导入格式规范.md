# APTHunter APT 事件数据采集及导入格式规范

## 1. 文档目的

本文档只用于自动采集、校验和更新 APTHunter 的 APT 事件数据。

本次数据维护范围：

```text
允许读取：apt_organizations
允许更新：apt_events、region_event_stats
允许重算：apt_organizations.event_count
禁止新增或删除组织
禁止修改组织名称、别名、描述、来源、地区、目标等基础资料
```

采集程序必须使用现有组织表完成事件归属。遇到无法匹配的组织时，应将事件写入待审核文件，不得自动创建组织，也不得修改现有组织名称、别名、来源国家或地区。`event_count` 是事件导入后的派生统计，不属于组织资料采集。

推荐流程：

```text
公开情报源
    ↓
采集原始事件
    ↓
UTF-8 JSONL 标准化
    ↓
校验日期、来源、组织归属和重复事件
    ↓
生成 dry-run 报告
    ↓
事务化写入 apt_events
    ↓
重算组织 event_count 和地区聚合
```

前后端运行时只查询 MySQL，不应依赖 CSV 修复事件内容。

---

## 2. 当前事件数据结构

### 2.1 当前 CSV 字段

现有 `apt_events.csv` 包含以下 8 个字段：

```csv
id,event_date,title,description,threat_type,organization_id,releasing_product,link
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | integer | 现有事件 ID；新事件采集时不生成 |
| `event_date` | date | 事件发生、首次发现或报告发布日期 |
| `title` | string | 事件标题 |
| `description` | string | 事件中文描述 |
| `threat_type` | string | 受控威胁类型 |
| `organization_id` | integer | 现有组织表中的组织 ID |
| `releasing_product` | string | 发布该事件报告的厂商、产品或机构 |
| `link` | string | 主要来源链接 |

### 2.2 当前数据库字段

MySQL `apt_events` 表包含：

| 字段 | 类型 | 来源 |
|---|---|---|
| `id` | int，主键，自增 | 数据库生成或现有记录 |
| `event_date` | date | 采集数据 |
| `title` | varchar(500) | 采集数据 |
| `description` | longtext | 采集数据 |
| `threat_type` | varchar(64) | 采集数据 |
| `organization_id` | int，外键 | 通过现有组织表匹配 |
| `releasing_product` | varchar(255) | 采集数据 |
| `link` | text | 采集数据 |
| `event_type` | enum | 导入程序派生 |
| `severity` | int | 导入程序派生 |
| `region` | varchar(64) | 从现有组织表复制，保持当前系统兼容 |
| `latitude` | decimal/null | 本次采集不更新 |
| `longitude` | decimal/null | 本次采集不更新 |
| `created_at` | datetime | 数据库生成 |

以下字段禁止由采集模型自由生成：

```text
id
event_type
severity
region
latitude
longitude
created_at
```

---

## 3. 推荐采集文件格式

### 3.1 使用 JSONL 作为标准采集格式

建议采集脚本输出 `events.jsonl`，每行一个完整 JSON 对象。

统一要求：

```text
编码：UTF-8
换行：LF（\n）
日期：YYYY-MM-DD
时间：ISO 8601
```

使用 JSONL 而不是让大模型直接输出 CSV，原因包括：

- 事件描述可能包含逗号、引号和换行。
- 可以同时保留多条证据和审核信息。
- 单条失败不会破坏整个文件。
- 更容易严格校验数据类型。
- 校验完成后仍可转换为现有 CSV。

不要继续生成 GBK 或 GB18030 编码的新事件文件。

### 3.2 标准字段

| 字段 | 类型 | 必填 | 约束 |
|---|---|---:|---|
| `schema_version` | string | 是 | 固定为 `"1.0"` |
| `record_type` | string | 是 | 固定为 `"event"` |
| `db_id` | integer/null | 是 | 更新已知事件时填写；新事件为 `null` |
| `event_date` | string | 是 | `YYYY-MM-DD` |
| `date_precision` | string | 是 | `day`、`month`、`year`、`publication_date` |
| `title` | string | 是 | 1～500 字符 |
| `description` | string | 是 | 中文概述，建议 100～5000 字 |
| `threat_type` | string | 是 | 必须使用受控词表 |
| `organization_id` | integer/null | 是 | 已有组织 ID；不能确定时为 `null` |
| `organization_name` | string | 是 | 用于验证 ID 与名称是否一致 |
| `releasing_product` | string/null | 是 | 报告发布厂商、产品或机构 |
| `link` | string | 是 | 主要来源的规范化 URL |
| `confidence` | number | 是 | 0～1 |
| `review_status` | string | 是 | `accepted`、`needs_review`、`rejected` |
| `evidence` | array[object] | 是 | 证据列表，至少一项 |
| `collection_notes` | string/null | 否 | 归属、日期和来源冲突说明 |
| `collected_at` | string | 是 | 采集时间，ISO 8601 |

### 3.3 `evidence` 字段

每个证据对象包含：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---:|---|
| `url` | string | 是 | 具体报告或公告 URL |
| `title` | string | 是 | 来源标题 |
| `publisher` | string | 是 | 发布机构 |
| `published_date` | string/null | 是 | `YYYY-MM-DD` |
| `accessed_at` | string | 是 | 访问时间，ISO 8601 |
| `source_level` | string | 是 | `A`、`B`、`C`、`D` |
| `supports` | array[string] | 是 | 该来源支撑的事件字段 |

### 3.4 JSONL 示例

以下内容仅展示格式，不代表真实情报：

```json
{"schema_version":"1.0","record_type":"event","db_id":null,"event_date":"2026-07-28","date_precision":"publication_date","title":"示例组织针对能源行业开展钓鱼活动","description":"某安全研究机构披露了一起针对能源行业的钓鱼活动。公开材料未说明攻击开始日期，因此本记录使用报告发布日期，并通过 date_precision 明确标注。","threat_type":"钓鱼攻击","organization_id":12,"organization_name":"示例组织","releasing_product":"示例安全实验室","link":"https://example.com/report/2026-07-28","confidence":0.86,"review_status":"accepted","evidence":[{"url":"https://example.com/report/2026-07-28","title":"示例事件报告","publisher":"示例安全实验室","published_date":"2026-07-28","accessed_at":"2026-07-29T10:30:00+08:00","source_level":"B","supports":["event_date","title","description","threat_type","organization_id"]}],"collection_notes":"公开材料未给出攻击开始日期，使用报告发布日期。","collected_at":"2026-07-29T10:30:00+08:00"}
```

---

## 4. 组织表只读与事件归属规则

### 4.1 采集前提供组织索引

采集脚本应先从 `apt_organizations` 读取以下只读索引：

```json
[
  {
    "id": 1,
    "name": "组织主名称",
    "aliases": ["别名一", "别名二"]
  }
]
```

提示词中只需要提供：

```text
id
name
aliases
```

不需要把组织描述、目标国家和其他大字段发送给采集模型。

### 4.2 匹配顺序

事件归属按以下顺序确定：

1. 来源明确使用的名称与组织主名称完全一致；
2. 来源名称与某个组织别名完全一致；
3. 名称存在大小写、空格或常见符号差异，但规范化后完全一致；
4. 其余情况进入人工审核。

模糊相似度只能产生候选组织，不能直接形成归属结论。

### 4.3 ID 和名称必须同时验证

当输出包含 `organization_id` 时，导入程序必须验证：

```text
organization_id 对应的主名称或别名
    =
采集结果中的 organization_name
```

如果不一致：

```json
{
  "organization_id": null,
  "review_status": "needs_review",
  "collection_notes": "组织 ID 与名称不一致，禁止自动导入。"
}
```

### 4.4 无法匹配的组织

当来源提到的组织不在现有组织表中：

- 不新增组织；
- 不使用名称最相似的组织代替；
- 不写入 `apt_events`；
- 将记录输出到 `events.unmatched-organizations.jsonl`；
- 保留来源、原始名称和候选匹配项供人工处理。

待审核记录建议增加：

```json
{
  "raw_organization_name": "来源中的组织名称",
  "candidate_organizations": [
    {"id": 1, "name": "候选组织", "reason": "别名相似"}
  ]
}
```

这些辅助字段只进入审核文件，不写入 `apt_events`。

---

## 5. 事件字段采集规则

### 5.1 事件日期

`event_date` 按以下顺序选择：

1. 来源明确给出的攻击发生日期；
2. 来源明确给出的首次发现日期；
3. 来源报告发布日期；
4. 只有月份或年份时进入人工审核。

日期精度对应：

| 情况 | `date_precision` |
|---|---|
| 有明确年月日 | `day` |
| 只有年月 | `month` |
| 只有年份 | `year` |
| 使用报告发布日期代替发生日期 | `publication_date` |

不得把 `collected_at` 当作 `event_date`。

如果来源只写“近期”“过去几个月”等模糊时间，不允许模型自行计算具体日期。

### 5.2 标题

标题要求：

- 客观、简洁、可检索；
- 包含组织名称和主要活动；
- 不使用“惊天攻击”“重大曝光”等宣传性措辞；
- 不在标题中添加来源没有说明的国家、行业或恶意软件；
- 最大长度 500 字符。

推荐格式：

```text
{组织名称}针对{目标或行业}开展{攻击类型/活动名称}
```

### 5.3 描述

描述建议覆盖：

1. 事件时间；
2. 目标国家、组织或行业；
3. 初始攻击方式；
4. 使用的漏洞、恶意软件或基础设施；
5. 攻击目的或影响；
6. 归属依据；
7. 来源未确认的内容。

要求：

- 使用中文客观概述；
- 不复制大段报告原文；
- 不加入来源不支持的攻击链细节；
- 区分“来源确认”“来源推测”和“采集程序无法确认”；
- 去除网页导航、广告、版权声明和无关内容。

### 5.4 威胁类型

只允许以下值：

```text
钓鱼攻击
C2通信
漏洞利用
恶意软件
凭证窃取
供应链攻击
勒索软件
APT攻击
其他
```

一条事件只能选择一个主要类型。

选择原则：

- 以事件核心攻击行为为主；
- 恶意邮件或恶意文档作为入口时优先使用 `钓鱼攻击`；
- 核心内容是远控基础设施和回连活动时使用 `C2通信`；
- 核心内容是具体 CVE 或零日漏洞时使用 `漏洞利用`；
- 主要披露木马、后门、加载器时使用 `恶意软件`；
- 无法归入受控类型时使用 `其他`，不要创造新分类。

### 5.5 发布机构

`releasing_product` 表示事件报告的发布方，例如：

```text
国家计算机病毒应急处理中心
某安全厂商威胁情报中心
某研究实验室
某威胁情报产品
```

优先填写来源页面明确显示的机构或产品名称，不要填写采集脚本名称。

### 5.6 来源链接

`link` 必须：

- 使用 `http://` 或 `https://`；
- 指向具体报告、公告或文章；
- 去除首尾空格、换行和 `\r`；
- 去除 `utm_source`、`utm_medium`、`utm_campaign` 等跟踪参数；
- 不使用搜索结果页作为最终来源；
- 不使用无法定位具体内容的网站首页。

---

## 6. 来源质量和证据要求

### 6.1 来源等级

| 等级 | 来源类型 | 处理方式 |
|---|---|---|
| A | 政府、CERT、执法机构、原始公告、正式研究报告 | 可作为主要证据 |
| B | 安全厂商研究博客、会议论文、可信威胁情报平台 | 可作为主要证据 |
| C | 专业安全媒体、有编辑审核的新闻报道 | 建议补充独立来源 |
| D | 聚合站、论坛、社交媒体、无作者转载 | 只作为线索 |

### 6.2 最低证据条件

自动进入 `accepted` 至少满足：

- 一个 A 级来源；或
- 一个 B 级原始研究来源；或
- 两个相互独立的 B/C 级来源提供一致证据。

以下情况必须设为 `needs_review`：

- 只有 D 级来源；
- 来源未明确组织归属；
- 多个来源对组织归属存在冲突；
- 事件日期只能推断；
- 来源名称无法匹配现有组织；
- 同一报告可能描述多次不同活动；
- 同一活动可能被不同来源重复报道。

---

## 7. 事件去重规则

### 7.1 URL 规范化

去重前先规范化 URL：

- 主机名转为小写；
- 删除 URL 片段标识；
- 删除常见跟踪参数；
- 去除末尾多余 `/`；
- 保存重定向前 URL 和最终 URL；
- 将同一文章的打印页、移动页、分享页归并。

### 7.2 稳定事件键

建议采集程序生成：

```text
event_key = SHA256(
  canonical_link + "\n" +
  organization_id + "\n" +
  event_date + "\n" +
  normalized_title
)
```

`event_key` 用于采集层和导入报告去重。当前 `apt_events` 尚无该字段时，可以暂存在导入批次记录中。

### 7.3 判重顺序

1. 已有 `db_id`：作为更新候选，验证 ID 对应记录；
2. 规范化链接、组织 ID、日期一致：视为同一事件；
3. 组织 ID、日期和规范化标题一致：视为重复候选；
4. 描述同一攻击活动但来源不同：进入人工审核，选择一个主来源；
5. 同一报告描述多个时间不同的活动：可以拆分为多条事件。

不要仅以标题相似度自动覆盖现有事件。

---

## 8. 派生字段规则

### 8.1 `event_type` 和 `severity`

导入程序根据 `threat_type` 生成：

| `threat_type` | `event_type` | `severity` |
|---|---|---:|
| 供应链攻击、漏洞利用、勒索软件、APT攻击 | `major` | 5 |
| C2通信、钓鱼攻击 | `normal` | 4 |
| 恶意软件、凭证窃取、其他 | `normal` | 3 |

采集模型不得自行输出或修改这两个字段。

### 8.2 `region`

为保持当前 APTHunter 数据结构兼容，本次事件导入可从现有组织表复制：

```sql
apt_events.region = apt_organizations.region
```

这表示组织来源地区的快照，不代表事件目标位置。

如果以后要实现真实事件地理态势，应另行设计目标国家、目标地区和坐标字段。不要在本次事件更新中根据组织来源国家生成虚假事件坐标。

### 8.3 组织事件数

事件导入完成后必须重算：

```sql
UPDATE apt_organizations o
LEFT JOIN (
    SELECT organization_id, COUNT(*) AS event_count
    FROM apt_events
    WHERE organization_id IS NOT NULL
    GROUP BY organization_id
) e ON e.organization_id = o.id
SET o.event_count = COALESCE(e.event_count, 0);
```

除 `event_count` 这一派生统计外，不更新组织表其他字段。

---

## 9. 与现有 CSV 的兼容输出

校验通过后，如仍需生成 CSV，字段顺序必须固定为：

```csv
id,event_date,title,description,threat_type,organization_id,releasing_product,link
```

转换规则：

| JSONL | CSV |
|---|---|
| `db_id` | `id`；新事件留空，由数据库生成 |
| `event_date` | `event_date` |
| `title` | `title` |
| `description` | `description` |
| `threat_type` | `threat_type` |
| `organization_id` | `organization_id` |
| `releasing_product` | `releasing_product` |
| 规范化后的 `link` | `link` |

CSV 输出要求：

- UTF-8 编码；
- LF 换行；
- 使用标准 CSV 库；
- 包含逗号、引号或换行的字段必须正确引用；
- 字段中的双引号按 CSV 标准转义；
- 禁止手工拼接 CSV 字符串；
- 禁止在 URL 尾部保留 `\r`。

Python 示例：

```python
import csv

fieldnames = [
    "id",
    "event_date",
    "title",
    "description",
    "threat_type",
    "organization_id",
    "releasing_product",
    "link",
]

with open("apt_events.csv", "w", encoding="utf-8", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
```

注意：当前旧初始化 SQL 按 GBK 读取事件 CSV。切换到 UTF-8 后，必须同步修改旧导入 SQL或改用新的 Python 导入工具，否则会产生乱码。

---

## 10. 导入程序要求

### 10.1 建议命令

```powershell
python backend/scripts/import_apt_events.py `
  --input data/events/normalized/events.jsonl `
  --dry-run
```

```powershell
python backend/scripts/import_apt_events.py `
  --input data/events/normalized/events.jsonl `
  --apply `
  --batch-id 2026-07-29
```

至少支持：

| 参数 | 作用 |
|---|---|
| `--dry-run` | 只校验和生成差异报告 |
| `--apply` | 执行数据库更新 |
| `--batch-id` | 标识导入批次 |
| `--fail-on-warn` | 存在待审核记录时终止 |
| `--prune` | 显式删除输入中不存在的旧事件，默认禁止 |

### 10.2 导入顺序

```text
1. 读取现有组织 ID、名称和别名
2. 解析 UTF-8 JSONL
3. 校验字段、日期、URL 和受控词表
4. 验证 organization_id 与 organization_name
5. 规范化 URL 并计算 event_key
6. 与现有 apt_events 判重
7. 生成新增、更新、重复、冲突和拒绝报告
8. dry-run 确认
9. 开启数据库事务
10. 更新已有事件
11. 插入新事件
12. 重算 apt_organizations.event_count
13. 重建 region_event_stats
14. 执行导入后完整性检查
15. 提交事务
```

任何一步失败都必须回滚整个事务。

### 10.3 更新与新增

- `db_id` 非空时，只能更新该 ID 对应事件。
- 更新前验证组织 ID、原始链接和标题，防止写错记录。
- `db_id` 为空时，由数据库生成新 ID。
- 新事件不得由采集程序读取最大 ID 后自行加一。
- 使用参数绑定，不拼接 SQL。
- 不使用 `REPLACE INTO`。

推荐使用：

```sql
INSERT INTO apt_events (...)
VALUES (...)
ON DUPLICATE KEY UPDATE ...;
```

由于当前表主要依赖主键判重，新导入程序仍必须在写入前执行 URL、组织、日期和标题组合去重。

### 10.4 删除

默认不删除任何旧事件。

输入文件中没有出现某条历史事件，不代表该事件应该删除。只有显式指定 `--prune` 并人工确认删除清单时才允许删除。

---

## 11. 校验要求

### 11.1 阻止导入

以下情况直接拒绝：

- JSON 无法解析；
- 文件不是 UTF-8；
- 缺少必填字段；
- `event_date` 不是 `YYYY-MM-DD`；
- 日期明显晚于来源发布日期；
- 标题为空或超过 500 字符；
- 描述为空；
- `threat_type` 不在受控词表；
- `organization_id` 不存在；
- `organization_id` 与 `organization_name` 不一致；
- `link` 不是 HTTP/HTTPS；
- 没有任何证据；
- `confidence` 不在 0～1；
- `review_status` 为 `rejected`；
- 同一批次出现重复 `event_key`。

### 11.2 进入人工审核

- `organization_id` 为 `null`；
- `confidence < 0.75`；
- 只有 C/D 级来源；
- 日期精度只有月份或年份；
- 组织归属存在冲突；
- 同一活动被多个来源重复报道；
- 标题相似但无法确认是否同一事件；
- 来源链接失效或需要登录；
- `review_status` 为 `needs_review`。

### 11.3 导入后 SQL 检查

检查孤立事件：

```sql
SELECT e.id, e.title, e.organization_id
FROM apt_events e
LEFT JOIN apt_organizations o ON o.id = e.organization_id
WHERE e.organization_id IS NULL OR o.id IS NULL;
```

检查组织事件数：

```sql
SELECT o.id, o.name, o.event_count, COUNT(e.id) AS actual_event_count
FROM apt_organizations o
LEFT JOIN apt_events e ON e.organization_id = o.id
GROUP BY o.id, o.name, o.event_count
HAVING o.event_count <> COUNT(e.id);
```

检查分类和严重度：

```sql
SELECT threat_type, event_type, severity, COUNT(*) AS event_count
FROM apt_events
GROUP BY threat_type, event_type, severity
ORDER BY event_count DESC;
```

检查尾部控制字符：

```sql
SELECT id, link
FROM apt_events
WHERE link REGEXP '[[:space:]]$';
```

检查重复候选：

```sql
SELECT organization_id, event_date, title, COUNT(*) AS duplicate_count
FROM apt_events
GROUP BY organization_id, event_date, title
HAVING COUNT(*) > 1;
```

---

## 12. 推荐文件目录

```text
data/
└── events/
    ├── raw/
    │   └── 2026-07-29/
    │       └── events.raw.jsonl
    ├── normalized/
    │   └── events.jsonl
    ├── review/
    │   ├── events.needs-review.jsonl
    │   └── events.unmatched-organizations.jsonl
    └── reports/
        ├── validation-2026-07-29.json
        └── import-2026-07-29.md
```

- `raw`：保存采集程序原始输出。
- `normalized`：只保存已经标准化的数据。
- `review`：保存不能自动导入的记录。
- `reports`：保存校验和导入结果。

不要把原始模型输出直接导入数据库。

---

## 13. 可直接使用的事件采集提示词

```text
你是一名网络安全威胁情报事件采集员。请根据给定的来源和现有 APT 组织索引，提取可以被 APTHunter 导入的 APT 事件。

采集时间范围：
{{collection_start}} 至 {{collection_end}}

现有组织索引：
{{existing_organizations_json}}

候选来源：
{{candidate_sources}}

任务范围：
- 只采集事件；
- 不新增、修改或删除组织；
- 只能将事件关联到现有组织索引；
- 无法匹配组织的事件必须标记 needs_review。

输出要求：
1. 只输出 UTF-8 JSONL，每行一个 JSON 对象。
2. 不要输出 Markdown、代码围栏、解释、汇总或其他文字。
3. schema_version 固定为 "1.0"。
4. record_type 固定为 "event"。
5. 新事件的 db_id 必须为 null，不得自行生成数据库 ID。
6. organization_id 必须来自现有组织索引，不得自行生成。
7. organization_name 必须与 organization_id 对应的主名称或别名一致。
8. 无法确定组织时，organization_id 为 null，review_status 为 "needs_review"。
9. 每条记录至少包含一个 evidence 对象和具体来源 URL。
10. event_date 优先使用攻击发生日期；没有发生日期时使用报告发布日期，并将 date_precision 设置为 "publication_date"。
11. 不得把 collected_at 当作 event_date。
12. threat_type 只能是：钓鱼攻击、C2通信、漏洞利用、恶意软件、凭证窃取、供应链攻击、勒索软件、APT攻击、其他。
13. 不要输出 event_type、severity、region、latitude、longitude、created_at。
14. description 使用中文客观概述，不复制大段原文，不添加来源没有说明的攻击链细节。
15. link 必须指向具体报告页面，并去除跟踪参数、尾部空格和换行。
16. 同一来源中的同一事件只输出一次。
17. 同一报告涉及多个组织时分别判断归属；不能确定时进入人工审核。
18. 组织归属、事件日期或不同来源存在冲突时，在 collection_notes 中说明。
19. confidence 必须为 0 到 1 之间的数值。

必须输出字段：
schema_version
record_type
db_id
event_date
date_precision
title
description
threat_type
organization_id
organization_name
releasing_product
link
confidence
review_status
evidence
collection_notes
collected_at

输出前自行检查：
- 每一行是否为独立且合法的 JSON；
- 是否误把报告发布日期当作攻击发生日期；
- organization_id 是否确实来自现有索引；
- organization_id 与 organization_name 是否一致；
- 是否存在无证据的组织归属；
- threat_type 是否属于受控词表；
- URL 是否指向具体来源；
- 是否重复输出同一事件；
- 是否输出了禁止由模型生成的派生字段。
```

---

## 14. 导入批次报告

每次采集和导入至少记录：

```text
批次 ID
采集时间范围
候选来源数量
原始事件数量
规范化事件数量
新增事件数量
更新事件数量
重复事件数量
待审核事件数量
无法匹配组织的事件数量
拒绝事件数量
导入前事件总数
导入后事件总数
输入文件 SHA-256
导入开始时间
导入结束时间
执行结果
```

---

## 15. 最低实施标准

事件采集脚本至少满足：

1. 输出 UTF-8 JSONL。
2. 每条事件保留来源、发布时间和采集时间。
3. 不生成数据库事件 ID。
4. 只关联现有组织，不修改组织表。
5. 无法匹配组织时进入待审核文件。
6. 使用受控威胁类型。
7. 区分事件发生日期、报告发布日期和采集时间。
8. 导入前执行日期、URL、组织外键和重复校验。
9. 支持 `--dry-run`。
10. 使用事务写入数据库。
11. 导入后重算 `apt_organizations.event_count`。
12. 导入后重建 `region_event_stats`。
13. 默认不删除旧事件。
14. API 运行时只读取 MySQL，不读取 CSV 修复数据。
