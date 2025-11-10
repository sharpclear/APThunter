// APT统计数据相关接口

// 统计数据接口
export interface StatisticsData {
  // APT域名总量
  totalDomains: number
  // 活跃组织数量
  activeOrganizations: number
  // 最新威胁发现数量
  latestThreats: number
  // 今日新增域名
  todayNewDomains: number
  // 威胁等级分布
  threatLevelDistribution: {
    high: number
    medium: number
    low: number
  }
  // 最近24小时威胁趋势
  threatTrend24h: Array<{
    time: string
    count: number
  }>
  // 组织活跃度排名
  organizationRanking: Array<{
    name: string
    domainCount: number
    threatLevel: 'high' | 'medium' | 'low'
  }>
  // 域名增长趋势
  domainGrowthTrend: Array<{
    date: string
    count: number
  }>
}

// 最新威胁发现详情
export interface LatestThreat {
  id: string
  domain: string
  organization: string
  threatLevel: 'high' | 'medium' | 'low'
  discoveryTime: string
  description?: string
  tags?: string[]
}

// 查询统计数据
export async function getStatisticsApi() {
  return usePost<StatisticsData>('/dashboard/statistics', {}, {
    loading: true,
  })
}

// 查询最新威胁发现列表
export interface QueryLatestThreatsParams {
  page?: number
  pageSize?: number
  threatLevel?: 'high' | 'medium' | 'low'
}

export interface LatestThreatsResult {
  list: LatestThreat[]
  total: number
  page: number
  pageSize: number
}

export async function getLatestThreatsApi(params?: QueryLatestThreatsParams) {
  return usePost<LatestThreatsResult, QueryLatestThreatsParams>('/dashboard/latest-threats', params || {}, {
    loading: true,
  })
}

