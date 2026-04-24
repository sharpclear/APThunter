export interface UserInfo {
  id: number | string
  username: string
  nickname: string
  avatar: string
  roles?: (string | number)[]
}

export function getUserInfoApi() {
  // 须走 /api，否则 Nginx 会把 /user/info 当成前端路由返回 index.html，导致无限重试
  return useGet<UserInfo>('/api/user/info')
}
