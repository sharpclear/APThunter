# DGA 家族与组织线索离线关联库

本目录用于在 DGA 家族识别完成后，离线查询公开情报中与该家族有关的攻击组织、网络犯罪团伙、运营者或分发组织。

## 文件

| 文件 | 说明 |
|---|---|
| `dga_family_actor_associations.csv` | 核心关联表；一行表示一条“DGA 家族到组织或运营者”的公开情报线索，支持一对多 |
| `current_model_dga_family_catalog.csv` | 当前家族模型支持的 71 个家族及其线索覆盖情况 |
| `family_aliases.csv` | 家族变种名称到标准家族名的离线映射 |
| `association_summary.json` | 关联库规模、覆盖数量和状态分布摘要 |
| `lookup_dga_family_actor.py` | 按 DGA 家族查询组织线索，或按组织名称反查 DGA 家族 |

## 系统使用

APTHunter 在 DGA 家族识别完成后，由 `backend/app/models/dga_threat_actor_attribution.py` 自动读取核心关联表。仅当 `family_attribution_status=usable` 且家族名称明确时，才输出组织线索。

检测结果中的主要字段：

| 字段 | 说明 |
|---|---|
| `APT组织名` | 可能关联的组织、团伙、运营者或分发方；多条结果使用顿号分隔 |
| `关联方式` | 使用、分发、运营、共享工具或基础设施关联等中文关系类型 |
| `APT组织线索数` | 当前域名通过 DGA 家族关联到的线索条数 |
| `APT组织关联详情` | 包含英文关系类型、状态、置信度、来源链接和备注的 JSON 明细 |

## 独立查询

在本目录执行：

```bash
python lookup_dga_family_actor.py qakbot emotet
python lookup_dga_family_actor.py --actor TA577
```

## 结果边界

- `relationship_type` 表示使用、分发、运营、共享工具或基础设施关联等线索类型。
- `confidence` 是线索整理置信度，不是模型预测概率。
- 同一家族可能对应多个组织，调用方应保留全部关系及各自来源。
- 查询结果只能表述为“可能关联组织”或“组织线索”，不能单独作为最终 APT 归因结论。
- 无可靠关联的家族不会伪造 `unknown_actor` 记录；调用方应保留 DGA 家族结果并将组织线索留空。
