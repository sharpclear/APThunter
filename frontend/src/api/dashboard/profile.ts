// 组织画像相关接口

// VPS服务商使用偏好
export interface VpsProviderPreference {
  provider: string
  count: number
  percentage: number
}

// 组织画像接口
export interface OrganizationProfile {
  id: string | number
  name: string
  alias?: string[]
  description: string
  iocCount?: number
  eventCount?: number
  updateTime?: string
  region?: string
  origin?: string
  targetCountries?: string[]
  targetIndustries?: string[]
  // 曾用域名
  previousDomains?: string[]
  // VPS分布：各组织的VPS服务商使用偏好
  vpsProviders?: VpsProviderPreference[]
}

// 查询参数
export interface QueryOrganizationsParams {
  keyword?: string
  startDate?: string
  endDate?: string
  attackedCountry?: string
  attackedIndustry?: string
  origin?: string
  page?: number
  pageSize?: number
}

// 组织列表响应
export interface OrganizationListResponse {
  list: OrganizationProfile[]
  total: number
  page: number
  pageSize: number
}

// 查询组织列表
export async function queryOrganizationsApi(params?: QueryOrganizationsParams) {
  return usePost<OrganizationListResponse, QueryOrganizationsParams>('/organization/list', params, {
    loading: true,
  })
}

// 查询组织详情
export async function queryOrganizationDetailApi(id: string | number) {
  return useGet<OrganizationProfile>(`/organization/${id}`, undefined, {
    loading: true,
  })
}

