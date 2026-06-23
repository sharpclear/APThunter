# APTHunter Frontend

APTHunter frontend is built with Vue 3, Vite, TypeScript, Ant Design Vue, Pinia, and UnoCSS. It provides the web console for detection tasks, model management, subscriptions, alerts, and dashboard views.

## Development

```bash
pnpm install
pnpm dev
```

The development server listens on `http://localhost:6678` and proxies `/api` requests to the backend target configured by `VITE_API_PROXY_TARGET`.

## Validation

```bash
pnpm typecheck
pnpm lint
pnpm build
```
