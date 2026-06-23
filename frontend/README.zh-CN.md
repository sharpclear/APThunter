# APTHunter 前端

APTHunter 前端基于 Vue 3、Vite、TypeScript、Ant Design Vue、Pinia 和 UnoCSS 构建，提供检测任务、模型管理、订阅预警和态势展示等 Web 控制台能力。

## 本地开发

```bash
pnpm install
pnpm dev
```

开发服务默认监听 `http://localhost:6678`，并通过 `VITE_API_PROXY_TARGET` 将 `/api` 请求代理到后端。

## 验证

```bash
pnpm typecheck
pnpm lint
pnpm build
```
