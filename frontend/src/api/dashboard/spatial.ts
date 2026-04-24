// 时空分布相关接口

// 事件接口
export interface SpatialEvent {
  id: number
  eventDate: string
  title: string
  description?: string
  eventType: 'major' | 'normal'
  region?: string
  latitude?: number
  longitude?: number
  organizationId?: number
  organizationName?: string
  severity: number
}

// 查询事件列表参数
export interface QueryEventsParams {
  startDate?: string
  endDate?: string
  region?: string
  eventType?: 'major' | 'normal'
  organizationId?: number
  page?: number
  pageSize?: number
}

// 事件列表响应
export interface EventListResponse {
  list: SpatialEvent[]
  total: number
  page: number
  pageSize: number
}

// 热力图数据点
export interface HeatmapPoint {
  latitude: number
  longitude: number
  intensity: number
  region?: string
  count: number
}

// 时间线数据点
export interface TimelinePoint {
  date: string
  count: number
  majorCount: number
  normalCount: number
  events?: SpatialEvent[]
}

// 地图数据点
export interface MapDataPoint {
  latitude: number
  longitude: number
  region: string
  eventCount: number
  majorCount: number
  recentEvents?: SpatialEvent[]
}

// 查询事件列表
export async function queryEventsApi(params?: QueryEventsParams) {
  return useGet<EventListResponse>('/api/dashboard/spatio-temporal/events', params, {
    loading: true,
  })
}

// 查询热力图数据
export async function queryHeatmapApi(params?: {
  startDate?: string
  endDate?: string
  region?: string
}) {
  return useGet<HeatmapPoint[]>('/api/dashboard/spatio-temporal/heatmap', params, {
    loading: true,
  })
}

// 查询时间线数据
export async function queryTimelineApi(params?: {
  startDate?: string
  endDate?: string
  interval?: 'day' | 'week' | 'month'
}) {
  return useGet<TimelinePoint[]>('/api/dashboard/spatio-temporal/timeline', params, {
    loading: true,
  })
}

// 查询地图数据
export async function queryMapDataApi(params?: {
  startDate?: string
  endDate?: string
}) {
  return useGet<MapDataPoint[]>('/api/dashboard/spatio-temporal/map-data', params, {
    loading: true,
  })
}
