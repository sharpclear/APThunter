export interface DomainMonitorLatestSnapshot {
  id?: number
  status?: string
  collectedAt?: string
  changedFields?: {
    is_first_snapshot?: boolean
    sections?: string[]
  }
  errorMessage?: string
}

export interface DomainMonitorTarget {
  id: number
  domain: string
  normalizedDomain: string
  isActive: boolean
  status: string
  monitorIntervalHours: number
  nextCheckAt?: string
  lastCheckedAt?: string
  consecutiveFailures: number
  lastError?: string
  sourceCount: number
  createdAt?: string
  updatedAt?: string
  latestSnapshot?: DomainMonitorLatestSnapshot | null
}

export interface DomainMonitorDnsRecord {
  type?: string
  name?: string
  value?: string
  ttl?: number
  priority?: number
}

export interface DomainMonitorSnapshot {
  id: number
  status: string
  collectedAt: string
  whois?: Record<string, any> | null
  dns?: {
    domain?: string
    records?: DomainMonitorDnsRecord[]
  } | null
  certificate?: Record<string, any> | null
  web?: Record<string, any> | null
  changedFields?: {
    is_first_snapshot?: boolean
    sections?: string[]
  } | null
  rawLookupErrors?: string[] | null
  errorMessage?: string
  createdAt?: string
}

export interface DomainMonitorTargetListParams {
  page?: number
  pageSize?: number
  activeOnly?: boolean
  domain?: string
}

export interface DomainMonitorTargetListResult {
  items: DomainMonitorTarget[]
  total: number
}

export interface DomainMonitorSnapshotListParams {
  page?: number
  pageSize?: number
}

export interface DomainMonitorSnapshotListResult {
  target: DomainMonitorTarget
  items: DomainMonitorSnapshot[]
  total: number
}

export function getDomainMonitorTargetsApi(params: DomainMonitorTargetListParams) {
  return useGet<DomainMonitorTargetListResult>('/domain-monitor/targets', params)
}

export function getDomainMonitorSnapshotsApi(targetId: number, params: DomainMonitorSnapshotListParams) {
  return useGet<DomainMonitorSnapshotListResult>(`/domain-monitor/targets/${targetId}/snapshots`, params)
}

export function triggerDomainMonitorTargetApi(targetId: number) {
  return usePost<{ ok: boolean, targetId: number }, Record<string, never>>(`/domain-monitor/targets/${targetId}/trigger`, {})
}

export function triggerDueDomainMonitorTargetsApi(limit = 20) {
  return usePost<{ ok: boolean, summary: Record<string, any> }, Record<string, never>>('/domain-monitor/trigger-due', {}, {
    params: { limit },
  })
}
