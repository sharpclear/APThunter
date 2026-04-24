export interface LoginParams {
  username: string
  password: string
  type?: 'account'
}

export interface LoginMobileParams {
  mobile: string
  code: string
  type: 'mobile'
}

export interface LoginResultModel {
  token: string
  user?: {
    userid: string
    username: string
    email?: string
  }
}

export function loginApi(params: LoginParams | LoginMobileParams) {
  // 相对 VITE_APP_BASE_API（/api）→ /api/login；base 为 / 时单独配置 env
  return usePost<LoginResultModel, LoginParams | LoginMobileParams>('/login', params, {
    token: false,
    loading: true,
  })
}

export function logoutApi() {
  return useGet('/logout')
}
