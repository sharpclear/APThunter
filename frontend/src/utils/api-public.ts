/**
 * 浏览器侧 API 路径前缀（生产为 /api，由 Nginx 反代至 backend）。
 * 勿使用 http://localhost 或 Docker 服务名，保证与当前页同源。
 */
export function getApiBase(): string {
  return (import.meta.env.VITE_APP_BASE_API as string) || '/api'
}
