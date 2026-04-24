export interface UserInfo {
  id: number | string
  username: string
  nickname: string
  avatar: string
  roles?: (string | number)[]
}

export function getUserInfoApi() {
  // 路径相对 VITE_APP_BASE_API（/api）；勿写 /api/user/info，否则与 baseURL 拼成 /api/api/...
  return useGet<UserInfo>('/user/info')
}
