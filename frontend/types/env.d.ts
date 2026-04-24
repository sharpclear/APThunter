/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'

  const component: DefineComponent<object, object, any>
  export default component
}

interface ImportMetaEnv {
  readonly VITE_APP_BASE: string
  readonly VITE_APP_BASE_API: string
  readonly VITE_APP_BASE_API_DEV: string
  readonly VITE_APP_BASE_URL: string
  readonly VITE_APP_BASE_URL_DEV: string
  readonly VITE_APP_LOAD_ROUTE_WAY: 'FRONTEND' | 'BACKEND'
  /** 为 true 时启用 mock-h3（/api 前缀）；联调真实后端时应为 false */
  readonly VITE_ENABLE_H3_MOCK?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
