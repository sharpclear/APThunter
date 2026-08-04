// 时空分布相关接口
import { normalizeTextFields } from '~/utils/text-encoding'

// 事件接口
export interface SpatialEvent {
	id: number
	eventDate: string
	title: string
	description?: string
	reportUrl?: string
	releasingProduct?: string
	eventType: 'major' | 'normal'
	threatType?: string
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

const SPATIAL_EVENT_TEXT_FIELDS = ['title', 'description', 'threatType', 'releasingProduct', 'organizationName', 'organization', 'region'] as const
const SPATIAL_REGION_TEXT_FIELDS = ['region'] as const

function normalizeSpatialEvent<T extends Record<string, any>>(event: T): T {
	return normalizeTextFields(event, SPATIAL_EVENT_TEXT_FIELDS)
}

// 查询事件列表
export async function queryEventsApi(params?: QueryEventsParams) {
	const query = params
		? {
				...params,
				start_date: params.startDate,
				end_date: params.endDate,
				event_type: params.eventType,
				organization_id: params.organizationId,
				page_size: params.pageSize,
			}
		: undefined

	if (query) {
		delete (query as any).startDate
		delete (query as any).endDate
		delete (query as any).eventType
		delete (query as any).organizationId
		delete (query as any).pageSize
	}

	const response = await useGet<EventListResponse>('/dashboard/spatio-temporal/events', query, {
		loading: true,
	})

	if (response.data?.list)
		response.data.list = response.data.list.map(normalizeSpatialEvent)

	return response
}

// 查询热力图数据
export async function queryHeatmapApi(params?: {
	startDate?: string
	endDate?: string
	region?: string
}) {
	const response = await useGet<HeatmapPoint[]>('/dashboard/spatio-temporal/heatmap', params, {
		loading: true,
	})

	if (Array.isArray(response.data))
		response.data = response.data.map(item => normalizeTextFields(item, SPATIAL_REGION_TEXT_FIELDS))

	return response
}

// 查询时间线数据
export async function queryTimelineApi(params?: {
	startDate?: string
	endDate?: string
	interval?: 'day' | 'week' | 'month'
}) {
	const response = await useGet<TimelinePoint[]>('/dashboard/spatio-temporal/timeline', params, {
		loading: true,
	})

	if (Array.isArray(response.data)) {
		response.data = response.data.map((point) => {
			const normalizedPoint = normalizeSpatialEvent(point)
			return {
				...normalizedPoint,
				events: normalizedPoint.events?.map(normalizeSpatialEvent),
			}
		})
	}

	return response
}

// 查询地图数据
export async function queryMapDataApi(params?: {
	startDate?: string
	endDate?: string
}) {
	const response = await useGet<MapDataPoint[]>('/dashboard/spatio-temporal/map-data', params, {
		loading: true,
	})

	if (Array.isArray(response.data)) {
		response.data = response.data.map((point) => {
			const normalizedPoint = normalizeSpatialEvent(point)
			return {
				...normalizedPoint,
				recentEvents: normalizedPoint.recentEvents?.map(normalizeSpatialEvent),
			}
		})
	}

	return response
}
