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
  // 必须使用 /api/login，避免 baseURL 为 / 时请求落到前端路由 /login 导致 Nginx 405
  return usePost<LoginResultModel, LoginParams | LoginMobileParams>('/api/login', params, {
    token: false,
    loading: true,
  })
}

export function logoutApi() {
  return useGet('/api/logout')
}
