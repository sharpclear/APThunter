# APTHunter -> APTHunter3 展示/态势感知整合说明

## 已完成的整合改造（最小侵入）

### 1) 后端按重构架构接入展示模块
- 在 `app/bootstrap/app_factory.py` 中新增了展示模块路由注册：
  - `dashboard_domain`
  - `dashboard_organization`
  - `dashboard_spatial`
  - `dashboard_stats`
  - `domain_lookup`
- 通过配置开关控制是否启用，避免影响其他模块。

### 2) 新增可回滚开关
- 在 `app/core/config.py` 新增：
  - `DISPLAY_INTEGRATION_ENABLED`（默认 `True`）
- 可通过环境变量快速关闭展示整合：
  - `DISPLAY_INTEGRATION_ENABLED=false`

### 3) 展示模块后端代码适配 APTHunter3 拆分架构
- 已将展示相关 API 中 `from main import engine` 改为 `from app.db.session import engine`，避免破坏 APTHunter3 的分层约束。
- 修复 `dashboard_stats.py` 中趋势接口的明显问题（未定义连接与起始时间），并增加了实时聚合兜底逻辑。
- `dashboard_domain.py` 的域名列表与详情返回增加了组织关联与恶意标记字段，兼容 APTHunter 前端数据结构。

### 4) 前端展示 API 契约已完整补齐
已补齐并落地以下文件（此前为空）：
- `frontend/src/api/dashboard/statistics.ts`
- `frontend/src/api/dashboard/profile.ts`
- `frontend/src/api/dashboard/attributes.ts`
- `frontend/src/api/dashboard/spatial.ts`

这一步使 APTHunter 的展示/态势感知页面调用契约在 APTHunter3 中可用。

---

## 验证建议
1. 启动后端后访问：
   - `/api/dashboard/data-display/summary`
   - `/api/dashboard/data-display/trends?days=30`
   - `/api/dashboard/org-profile/list?page=1&page_size=20`
   - `/api/dashboard/spatio-temporal/events?page=1&page_size=20`
   - `/api/domain/list`
   - `/api/domain/lookup/all`
2. 前端进入仪表盘相关页面验证请求返回与渲染。

---

## 回滚方式
- 仅设置环境变量：
  - `DISPLAY_INTEGRATION_ENABLED=false`
- 重启后端即可回退展示模块整合，不影响其他业务模块。

---

## 说明
本次改造采用“最小侵入式整合”：
- 不修改检测/训练/账户等核心模块的数据写路径；
- 仅接入展示模块路由与接口适配；
- 保留快速开关和可回退能力。
