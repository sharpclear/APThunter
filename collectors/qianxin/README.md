# 奇安信 APT 历史报告 PDF 自动下载器

现有增量采集、PDF 解析和本地模型摘要流水线已封装为异步 HTTP API。业务系统只需提交任务、
轮询状态并按完整 SHA-256 拉取摘要、质量报告和 PDF；接入说明见
[`docs/api-integration.md`](docs/api-integration.md)。

API 同时提供 `GET /api/v1/events`，把经过证据校验的报告转换为
`apthunter.apt_events.v1` 结构。响应保留来源 SHA、版本、审核状态、PDF 页码证据和独立事件游标，
可由内网 APTHunter 虚拟机直接增量拉取。为防止与已经导入但标题不同的历史奇安信事件重复，
自动接受默认关闭，候选会明确标为 `needs_review`；完成主系统历史去重后才应显式启用
`QIANXIN_EVENT_AUTO_ACCEPT=true`。

事件描述在 API 适配层统一规范为完整句子：中英文分号会被拆成独立语句，缺少句末标点时补充中文句号。
APTHunter 消费端不再二次修改描述，确保所有 API 调用方获得相同文本。

本项目通过 Python Playwright 操作奇安信威胁情报平台的公开页面，严格匹配本地组织 CSV，筛选完整发布日期，取得 PDF 预览器实际加载的原始 PDF，并保存元数据、人工复核项和断点检查点。

项目现在覆盖下载、PDF 校验、PyMuPDF4LLM 快速解析、MinerU 低质量页回退，以及本地小模型证据化摘要。各阶段保持解耦并可独立续跑；不写数据库，也不会修改 `data/reference` 下的两个参考 CSV。

## 环境准备

项目已经在 `.venv` 中安装了依赖，可直接使用：

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py --help
```

重新安装环境时：

```powershell
python -m venv .venv
..venv\Scripts\python.exe -m pip install -r requirements.txt
```

下载器优先复用本机 Chrome，其次是 Edge 和 Playwright Chromium。若本机没有 Chrome/Edge，必须把 Playwright 浏览器也安装在项目内：

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\data\state\ms-playwright"
..venv\Scripts\python.exe -m playwright install chromium
```

运行时也要保留同一个 `PLAYWRIGHT_BROWSERS_PATH` 环境变量，避免在项目外创建浏览器文件。

## 首次登录

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py --login-only --headed
```

在浏览器中自行完成登录或验证码，然后回到终端按 Enter。程序不自动绕过验证码，不接收或保存账号密码，也不会输出 Cookie、Token 或认证请求头。浏览器状态保存在：

```text
data\state\browser-profile
```

2026-08-03 的实际测试中，APT 列表、组织详情、历史报告和 PDF 均可匿名访问；持久化目录仍会在每次运行中复用，以兼容后续登录要求变化。

## 推荐运行顺序

先审计一个存在日期范围内报告的组织：

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py `
  --mode audit `
  --organization-id 40 `
  --headed `
  --max-organizations 1 `
  --max-reports-per-organization 1
```

审计模式只打开一条预览，不保存 PDF，结果写入 `data\metadata\qianxin-page-audit.md`。不指定组织时，为安全起见审计模式默认只处理首个匹配组织；当前首个组织 id 1 的最新报告早于 `2026-04-01`，因此不会违反日期规则去打开旧报告。

执行日期边界和去重演练：

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py `
  --mode backfill `
  --organization-id 1 `
  --start-date 2026-04-01 `
  --end-date today `
  --dry-run `
  --headed
```

单组织小规模实际下载：

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py `
  --mode backfill `
  --organization-id 40 `
  --start-date 2026-04-01 `
  --end-date today `
  --max-reports-per-organization 3 `
  --headed
```

全量回填：

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py `
  --mode backfill `
  --start-date 2026-04-01 `
  --end-date today `
  --resume `
  --headed
```

后续增量运行：

```powershell
..venv\Scripts\python.exe scripts\qianxin\download_historical_reports.py `
  --mode incremental `
  --start-date 2026-04-01 `
  --end-date today `
  --resume `
  --headed
```

增量模式会重新访问组织以发现新报告，同时利用元数据、报告 URL、PDF URL 和 SHA-256 跳过已处理内容。回填模式配合 `--resume` 还会跳过已经完整处理的组织。使用 `--max-reports-per-organization` 提前停止时，不会把整个组织误标成完成。

## 命令行参数

- `--login-only`：只打开持久化浏览器供人工登录。
- `--mode audit|backfill|incremental`：默认 `audit`，防止误触发全量下载。
- `--headed` / `--headless`：显示或隐藏浏览器，默认无头。
- `--dry-run`：执行组织匹配、日期筛选和预览前去重，不打开 PDF。
- `--resume`：复用检查点；回填时跳过已完整处理组织。
- `--organization-id` / `--organization-name`：限定一个 CSV 组织；名称也可使用严格匹配的别名。
- `--max-organizations`：限制组织数。
- `--max-reports-per-organization`：限制每个组织在日期范围内尝试的报告数。
- `--start-date` / `--end-date`：完整日期边界；默认 `2026-04-01` 到 `today`。

日期必须来自报告表或预览中明确显示的完整日期。只有年、只有年月、缺失或无效日期不会被猜测补全，而会进入人工复核 CSV。倒序列表一旦遇到下界以前的报告，就直接停止向旧页遍历，不打开旧报告预览。

## 页面审计结论

2026-08-03 对 APT28 的实际审计结果：

- “APT组织画像”可按精确可见文本定位。
- 地图列表项使用可聚焦的 `li[tabindex="0"]`；观察到 58 个唯一组织，未发现组织级分页。
- 详情页“历史报告”是名称为 `历史报告` 的 `role=tab`。
- 历史报告表头为“编号 / 发现时间 / 报告名称 / 发布厂商”。
- APT28 有 100 条报告，使用页码分页，首页 10 条按日期倒序。
- 报告标题是按钮；点击后打开“pdf预览”模态框。
- 模态框中的 `iframe[title="Embedded PDF"]` 加载稳定地址 `/alpha-api/v2/apt-dossier/apt-report?name=<报告ID>`，响应为 `application/pdf`，随后由 Chromium 内置 PDF 查看器显示。
- 全量运行时，地图页只用于取得可见组织并执行严格匹配；页面自身的组织目录响应用于补充稳定详情路由。这样可以处理目录中精确同名但未显示在地图上的组织，并避免重复渲染地图导致的超时。

完整、带时间戳的记录见 `data\metadata\qianxin-page-audit.md`。

## 匹配、去重与下载规则

组织匹配只采用以下分层规则，任一层出现歧义都会拒绝自动选择：CSV `name` 完全一致、CSV 任一 `aliases` 完全一致、统一大小写/空格/连字符/下划线后完全一致。不使用模糊字符串相似度。

下载前检查现有元数据的组织/标题/日期三元组和已处理 URL，并与 `apt_events.csv` 的明确三元组及规范化来源链接比对。相同 PDF SHA-256 在取得文件内容后再次拦截。只有同组织同日期且标题存在包含关系等疑似情况时，才写入人工复核，不会自动下载。

PDF 捕获顺序为：

1. Playwright 正常下载事件；
2. `application/pdf` 网络响应；
3. `.pdf` 响应 URL；
4. `iframe`、`embed`、`object` 的原始地址；
5. Blob 预览背后的 PDF 网络响应。

文件请求使用同一个 Playwright 浏览器上下文。写盘前必须通过 `%PDF-` 文件头、非 HTML、非空、`pypdf` 基础解析和 SHA-256 校验。临时签名参数在元数据和检查点中会被移除，日志不记录下载 URL。已有文件绝不覆盖。

## 输出位置

```text
data\reports\{organization_id}_{organization_name}\
data\metadata\qianxin-reports.jsonl
data\metadata\qianxin-reports.csv
data\metadata\qianxin-page-audit.md
data\review\qianxin-manual-download.csv
data\review\qianxin-unmatched-organizations.csv
data\review\qianxin-possible-duplicates.csv
data\state\qianxin-checkpoint.json
data\state\browser-profile\
logs\qianxin-downloader.log
```

复核 CSV 在首次产生对应记录时才创建。PDF 文件名为：

```text
{report_date}_{safe_report_title}_{sha256前8位}.pdf
```

## PDF 快速解析

下载器与正文解析保持解耦。`parse_reports.py` 使用 PyMuPDF4LLM 将 PDF 转成带页码边界的 Markdown，并从同一次分页结果生成可供程序消费的 JSON 和质量指标：

```powershell
.\.venv\Scripts\python.exe scripts\qianxin\parse_reports.py `
  --pdf "data\reports\组织目录\报告.pdf"
```

不传 `--pdf` 时会递归处理 `data\reports` 下的全部 PDF；可用 `--limit N` 小批量验证，用 `--overwrite` 重建已存在的解析结果。输出按组织和 PDF SHA-256 前 8 位隔离：

```text
data\parsed\pymupdf4llm\{组织目录}\{sha256前8位}\report.md
data\parsed\pymupdf4llm\{组织目录}\{sha256前8位}\document.json
data\parsed\pymupdf4llm\{组织目录}\{sha256前8位}\quality.json
data\parsed\pymupdf4llm\batch-summary.json
```

Markdown 在每一页前保留 `<!-- page: N -->`，方便后续小模型返回证据页码。质量门使用 `ready_for_small_model`、`needs_review` 和 `needs_ocr` 三种状态；低文本覆盖率的扫描件不会被误当成可用输入。

2026-08-05 已对 5 篇分层样本完成实际解析和人工抽查，结论见 `data\parsed\pymupdf4llm\quality-assessment.md`。PyMuPDF/PyMuPDF4LLM 采用 AGPL 或 Artifex 商业双许可；将本流程用于闭源或商业产品前需确认许可合规。本项目没有安装额外的 PyMuPDF-Layout 扩展。

### MinerU 低质量页回退与合并

快速解析后，可只对质量检查标出的低文本页执行 MinerU OCR，再按原始页码合并为统一 Markdown/JSON。MinerU 使用独立虚拟环境和项目内模型缓存，原 PDF 与 PyMuPDF4LLM 结果不会被修改。

```powershell
# 首次安装（CPU / Windows）
py -3.10 -m venv .venv-mineru
.\.venv-mineru\Scripts\python.exe -m pip install -r requirements-mineru.txt

# 对所有异常报告 OCR，并为全部报告生成合并结果；已有结果会自动续跑
.\.venv\Scripts\python.exe scripts\qianxin\enrich_reports.py
```

主要结果：

- `data/parsed/merged/<组织>/<sha8>/report.md`：含原始 PDF 页码的最终 Markdown。
- `data/parsed/merged/<组织>/<sha8>/document.json`：逐页解析器来源、OCR 前后字符数及 MinerU 内容块。
- `data/parsed/merged/<组织>/<sha8>/quality.json`：最终质量路由与仍需人工检查的页面。
- `data/parsed/merged/batch-summary.json`：全量处理统计。
- `data/parsed/mineru/work/<sha8>/page-map.json`：OCR 子集页到原 PDF 页码的映射。

可用 `--sha 04975abb` 仅处理一份报告，`--prepare-only` 只生成 OCR 子集，`--merge-only` 使用已有 OCR 结果重建合并文件。MinerU 采用 Apache-2.0 附加商业条款；部署前请结合实际使用方式确认许可证要求。

### 本地小模型结构化摘要

项目内已配置官方 `llama.cpp b10278` Windows CPU 版和 `Qwen3-4B-Q4_K_M`。运行时只监听 `127.0.0.1`，PDF 正文不会发送到远程 API；版本、来源、许可证与 SHA-256 见 `data/state/local-llm.json`。

```powershell
# 先处理一份；脚本负责启动和关闭本地服务
.\.venv\Scripts\python.exe scripts\qianxin\summarize_reports.py `
  --sha 04975abb --start-server

# 处理全部报告；已有同解析内容、提示词、模型名和校验器版本的结果自动跳过
.\.venv\Scripts\python.exe scripts\qianxin\summarize_reports.py --start-server

# 提示词不变、仅更新证据定位/过滤规则时，不调用模型即可重新校验
.\.venv\Scripts\python.exe scripts\qianxin\summarize_reports.py `
  --sha 04975abb --revalidate-only
```

每份报告输出到 `data/summaries/<组织>/<sha8>/`：

- `summary.md`：中文可读摘要和 `[PDF p.N]` 证据页。
- `summary.json`：归因、目标、工具、漏洞、攻击链、时间线和确定性指标。
- `quality.json`：越界页、未落地短引、误分类工具和反写防御建议等校验结果。
- `raw-model-output.json`：过滤前的模型原始 JSON，便于审计。
- `chunks/`：超过上下文的长报告分块检查点。

CVE、显式 MITRE 编号、IP、URL、域名、邮箱和文件哈希由代码提取；参考文献页的链接标记为 `reference`，不作为 IOC 展示。语义事实必须携带原文短引，程序通过精确匹配或唯一高相似匹配确定页码；无法定位的条目不会进入最终摘要。当前 CPU 上短报告通常需要数分钟，全量运行预计需要数小时，建议利用自动续跑分批完成。5 份中英韩分层样本的结果见 `data/summaries/quality-assessment.md`。

普通正文中的 URL、域名和邮箱默认标记为 `candidate`，只有报告明确 defang 的值或 IOC 章节中的值才自动标记为 `observable`；私网/回环地址标记为 `local`。执行摘要直接选用已定位的原文证据句，避免已过滤事实或模型改写重新进入摘要。长报告通过带检查点的 map-reduce 处理，最终归并只能选择分块阶段已经落地的事实，不能改写事实字段。

2026-08-11 已完成 83/83 份摘要，最终未解决失败为 0；其中本轮新增 6 份的结果见 `data/summaries/incremental-2026-08-11.md`。当前 CPU 上短报告通常需要约 3–11 分钟；长报告按块续跑。全量结果与模型对照见 `data/summaries/quality-assessment.md`。

### 后续定时增量

正式周任务使用带独占锁、完整 SHA 基线、持久运行清单和失败恢复的包装器。没有新增时会正常退出，不启动 MinerU 或本地模型：

```powershell
# 只读检查配置、全库 SHA 和端口，不运行网络、OCR 或模型
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  ".\scripts\qianxin\run_weekly_incremental.ps1" -DryRun

# 手工执行一次完整增量
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  ".\scripts\qianxin\run_weekly_incremental.ps1"
```

本机 Windows 计划任务 `QianxinAPTWeeklyIncremental` 已设置为每周日 03:00（北京时间）运行，下次运行时间为 2026-08-16 03:00。任务启用 `StartWhenAvailable`、网络可用条件、`IgnoreNew` 单实例、12 小时上限和失败后 1 小时重试一次。任务采用当前用户的交互式登录令牌，因此电脑关机或用户已注销时不会立即执行；再次登录且条件满足后由 `StartWhenAvailable` 补跑。

每次真实运行的清单位于 `data/state/weekly-incremental-runs/`，独立日志位于 `logs/weekly-incremental-*.log`。连续三次技术失败的单份 PDF 会进入人工复核隔离，不会永久阻断后续周度抓取。

定时发布或告警前，仍应检查 `quality.json`；`ready_with_filtered_items` 表示安全门删除过模型项，不等于报告失败。结构化 claim 与证据短引之间目前没有完整 NLI 蕴含判定，因此高风险归因、目标和漏洞仍建议抽查原页。

## 测试结果

离线测试：

```powershell
.\.venv\Scripts\python.exe -m pytest
```

当前为 59 项全部通过。测试临时文件被固定在项目内的 `tests\.tmp`。

APT28 单组织测试最初验证了 3 份 PDF；随后已完成 `2026-04-01` 至 `2026-08-03` 的全量回填，并在 2026-08-11 完成首次真实增量。58 个参考组织中，57 个通过严格规则匹配并完成检查点，1 个进入人工复核。当前保存 83 个唯一 PDF，共 264,493,265 字节、1,444 页，全部重新通过文件头、基础解析和完整 SHA-256 集合交叉检查。

元数据历史状态（包含断点重试过程）为：

```text
downloaded       83
already_exists   132
duplicate_event  0
skipped          119
failed           10（均为中间尝试，后续已成功）
manual_required  0
```

最终未解决失败数为 0。检查点包含 57 个完成组织、84 个已处理 PDF URL 和 83 个唯一 SHA-256；URL 数多 1 是因为两个不同平台报告地址返回了同一 PDF 内容。唯一未自动匹配的是 CSV 组织 `Sandworm Team`（id 42）：平台名称为 `Sandworm`，既不与 CSV `name` 相同，也不与其任一 `aliases` 相同，因此按规则写入 `data\review\qianxin-unmatched-organizations.csv`，没有使用相似度猜测。

## 已知限制

- 页面定位依赖当前可见文本、ARIA role、稳定元素属性和表格结构；平台改版后应重新运行审计模式。
- 站点当前将 PDF 放在模态框 iframe 中；若以后改为新窗口或 Blob，下载器会尝试已实现的其他捕获路径，但仍应先小范围审计。
- 平台组织列表只会与参考 CSV 中现有组织匹配；不会自动新增或修订组织。
- `Sandworm Team` 与平台名称 `Sandworm` 不满足项目规定的精确名称/别名规则，需要人工确认后才能采集。
- 疑似重复、缺失/不完整日期和无法确认的页面项只进入人工复核，不会自动猜测。
- 出现登录失效、验证码或访问限制时，无头模式会停止并提示先人工处理；程序不会绕过访问控制或无限重试。
- 下载阶段不读取 PDF 正文；解析、OCR 与摘要是相互独立且可续跑的后处理步骤。
- 本地模型仍可能让“结论字段”与真实短引发生语义错配；执行摘要已改为原文证据句，但结构化归因、目标、漏洞等高风险字段仍应以 `quality.json`、证据页和原 PDF 为准。
- map-reduce 的最终输入目前仍是单层归并；极端超长、分块数量远多于当前样本的 PDF 需要增加分层归并后再完全无人值守运行。
