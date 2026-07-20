<script setup lang="ts">
import { Column, Pie } from '@antv/g2plot'
import dayjs from 'dayjs'
import {
  DatabaseOutlined,
  ExclamationCircleOutlined,
  TeamOutlined,
  WarningOutlined,
} from '@ant-design/icons-vue'
import { useRouter } from 'vue-router'
import type { OrganizationProfile } from '~/api/dashboard/profile'
import { queryOrganizationsApi } from '~/api/dashboard/profile'
import { queryEventsApi } from '~/api/dashboard/spatial'
import AptTimeline, { type AptEvent } from '~/components/apt-timeline/index.vue'
import worldMapImage from '~/assets/world-map.png'

defineOptions({
  name: 'Monitor',
})

function convertNumber(number: number) {
  return number.toLocaleString()
}

function formatMaliciousDomainCount(count?: number | string | null) {
  const value = Number(count ?? 0)
  if (!Number.isFinite(value))
    return '0'
  return Math.max(0, Math.trunc(value)).toLocaleString()
}

const router = useRouter()

// APT统计数据
const stats = reactive({
  aptOrganizationTotal: 0,
  activeOrganizations: 0,
  latestThreats: 0,
  dnsAnomalyDetection: 0,
})

// 威胁类型分布数据
const DEFAULT_THREAT_TYPE_DATA: Array<{ type: string; value: number }> = [
  { type: 'DNS隧道', value: 0 },
  { type: 'DGA域名', value: 0 },
  { type: '钓鱼域名', value: 0 },
  { type: 'C2通信', value: 0 },
  { type: '其他', value: 0 },
]

const threatTypeData = ref<Array<{ type: string; value: number }>>([...DEFAULT_THREAT_TYPE_DATA])

// 攻击者地理位置TOP10
const attackSourceTop10 = ref<Array<{ country: string; count: number }>>([])

// 组织恶意域名排名TOP10
const orgMaliciousDomainTop10 = ref<Array<{ organization: string; count: number }>>([])

const pieContainer = ref()
const columnContainer = ref()
const orgIocColumnContainer = ref()
const pieChart = ref<Pie | null>(null)
const attackSourceChart = ref<Column | null>(null)
const orgIocChart = ref<Column | null>(null)

// 时空分布 - 选中状态
const selectedEvent = ref<AptEvent | null>(null)
const selectedOrganization = ref<OrganizationProfile | null>(null)
const spatialLoading = ref(false)
const selectedOrgTimelineEvents = ref<AptEvent[]>([])

// 时空分布 - 数据
const allAptEvents = ref<Array<AptEvent & { organizationId?: number }>>([])
const spatialOrganizations = ref<OrganizationProfile[]>([])

function formatThreatTypeLabel(rawType?: string) {
  const label = (rawType || '').trim().toLowerCase()
  if (!label)
    return '其他'

  if (label.includes('dns') && label.includes('隧道'))
    return 'DNS隧道'
  if (label.includes('dga'))
    return 'DGA域名'
  if (label.includes('钓鱼') || label.includes('phish'))
    return '钓鱼域名'
  if (label.includes('c2'))
    return 'C2通信'
  if (label.includes('malware') || label.includes('其他') || label.includes('未分类') || label.includes('unknown'))
    return '其他'

  return (rawType || '').trim() || '其他'
}

function toAptEvent(event: any): AptEvent & { organizationId?: number } {
  return {
    id: `event-${event.id}`,
    date: event.eventDate || event.event_date,
    title: event.title || '未命名事件',
    reportUrl: event.reportUrl || event.report_url,
    organizationId: event.organizationId || event.organization_id,
    organization: event.organizationName || event.organization_name || '未知组织',
    description: event.description || '-',
    type: event.eventType || event.event_type || 'normal',
  }
}

async function fetchAllEvents(params: { organizationId?: number } = {}) {
  const pageSize = 200
  let page = 1
  let totalPages = 1
  const all: Array<AptEvent & { organizationId?: number }> = []

  while (page <= totalPages) {
    const result = await queryEventsApi({
      ...params,
      page,
      pageSize,
    })

    const list = result.data?.list || []
    all.push(...list.map(toAptEvent))

    const total = result.data?.total || list.length
    totalPages = Math.max(1, Math.ceil(total / pageSize))
    page++
  }

  return all
}

type RegionKey =
  | '东亚'
  | '南亚'
  | '东欧'
  | '中东'
  | '北美'
  | '北美洲'
  | '南美洲'
  | '非洲'
  | '欧洲'
  | '大洋洲'
  | '东南亚'
  | '中亚'
  | '未知'

const regionAnchors: Record<
  RegionKey,
  {
    label: string
    pinX: string
    pinY: string
    labelX: string
    labelY: string
    labelAlign?: 'left' | 'right' | 'center'
    lineBendX?: string
    lineBendY?: string
  }
> = {
  东亚: { label: '东亚', pinX: '78%', pinY: '45%', labelX: '98%', labelY: '45%', labelAlign: 'right' },
  东南亚: {
    label: '东南亚',
    pinX: '78%',
    pinY: '62%',
    labelX: '98%',
    labelY: '65%',
    labelAlign: 'right',
    lineBendX: '98%',
    lineBendY: '62%',
  },
  南亚: { label: '南亚', pinX: '70%', pinY: '58%', labelX: '70%', labelY: '75%', labelAlign: 'center' },
  中亚: { label: '中亚', pinX: '68%', pinY: '38%', labelX: '68%', labelY: '30%', labelAlign: 'center' },
  中东: { label: '中东', pinX: '62%', pinY: '54%', labelX: '62%', labelY: '87%', labelAlign: 'center' },
  欧洲: { label: '欧洲', pinX: '54%', pinY: '38%', labelX: '54%', labelY: '20%', labelAlign: 'center' },
  东欧: { label: '东欧', pinX: '70%', pinY: '35%', labelX: '70%', labelY: '18%', labelAlign: 'center' },
  非洲: { label: '非洲', pinX: '50%', pinY: '62%', labelX: '30%', labelY: '62%', labelAlign: 'left' },
  北美: { label: '北美', pinX: '24%', pinY: '42%', labelX: '2%', labelY: '42%', labelAlign: 'left' },
  北美洲: { label: '北美洲', pinX: '24%', pinY: '42%', labelX: '2%', labelY: '42%', labelAlign: 'left' },
  南美洲: { label: '南美洲', pinX: '30%', pinY: '70%', labelX: '2%', labelY: '70%', labelAlign: 'left' },
  大洋洲: { label: '大洋洲', pinX: '84%', pinY: '82%', labelX: '98%', labelY: '82%', labelAlign: 'right' },
  未知: { label: '未知区域', pinX: '6%', pinY: '12%', labelX: '16%', labelY: '12%', labelAlign: 'left' },
}

function normalizeOrganizationName(name?: string | null) {
  return (name || '').trim().toLowerCase().replace(/[\s\-_]+/g, '')
}

const organizationMapByName = computed(() => {
  const map = new Map<string, OrganizationProfile>()
  spatialOrganizations.value.forEach((org) => {
    if (org.name)
      map.set(normalizeOrganizationName(org.name), org)

    if (org.alias?.length) {
      org.alias.forEach((alias) => {
        const normalizedAlias = normalizeOrganizationName(alias)
        if (normalizedAlias && !map.has(normalizedAlias)) {
          map.set(normalizedAlias, org)
        }
      })
    }
  })
  return map
})

const organizationMapById = computed(() => {
  const map = new Map<number, OrganizationProfile>()
  spatialOrganizations.value.forEach((org) => {
    const id = Number(org.id)
    if (!Number.isNaN(id)) {
      map.set(id, org)
    }
  })
  return map
})

const relatedOrganizations = computed<OrganizationProfile[]>(() => {
  if (selectedOrganization.value)
    return [selectedOrganization.value]

  const selected = selectedEvent.value as (AptEvent & { organizationId?: number }) | null
  if (!selected)
    return []

  // 1) 优先通过 organizationId 精确匹配
  const selectedOrgId = Number(selected.organizationId)
  if (!Number.isNaN(selectedOrgId)) {
    const matchedById = organizationMapById.value.get(selectedOrgId)
    if (matchedById)
      return [matchedById]
  }

  // 2) 通过组织名/别名匹配
  const normalizedEventOrg = normalizeOrganizationName(selected.organization)
  if (normalizedEventOrg) {
    const matchedByName = organizationMapByName.value.get(normalizedEventOrg)
    if (matchedByName)
      return [matchedByName]

    // 3) 模糊兜底（避免格式差异导致空）
    const fuzzy = spatialOrganizations.value.find((org) => {
      const name = normalizeOrganizationName(org.name)
      if (name && (name.includes(normalizedEventOrg) || normalizedEventOrg.includes(name)))
        return true

      return !!org.alias?.some((alias) => {
        const aliasName = normalizeOrganizationName(alias)
        return aliasName && (aliasName.includes(normalizedEventOrg) || normalizedEventOrg.includes(aliasName))
      })
    })
    if (fuzzy)
      return [fuzzy]
  }

  return []
})

const isSpatialDetailView = computed(() => !!selectedEvent.value || !!selectedOrganization.value)

const filteredEvents = computed<AptEvent[]>(() => {
  if (selectedOrganization.value) {
    return selectedOrgTimelineEvents.value
  }

  // 首页：每个组织仅展示 1 条（按日期最新）
  const sortedByDateDesc = [...allAptEvents.value].sort(
    (a, b) => dayjs(b.date).valueOf() - dayjs(a.date).valueOf(),
  )

  const picked = new Map<string, AptEvent>()
  for (const event of sortedByDateDesc) {
    const organizationId = (event as any).organizationId
    const organizationKey = typeof organizationId === 'number'
      ? `id:${organizationId}`
      : `name:${normalizeOrganizationName(event.organization) || 'unknown'}`

    if (!picked.has(organizationKey)) {
      picked.set(organizationKey, event)
    }
  }

  // 时间轴按时间升序展示
  return [...picked.values()].sort((a, b) => dayjs(a.date).valueOf() - dayjs(b.date).valueOf())
})

const groupedByRegion = computed<Record<RegionKey, OrganizationProfile[]>>(() => {
  const groups: Record<RegionKey, OrganizationProfile[]> = {
    东亚: [],
    南亚: [],
    东欧: [],
    中东: [],
    北美: [],
    北美洲: [],
    南美洲: [],
    非洲: [],
    欧洲: [],
    大洋洲: [],
    东南亚: [],
    中亚: [],
    未知: [],
  }

  spatialOrganizations.value.forEach((org) => {
    const key = (org.region as RegionKey) || '未知'
    if (groups[key])
      groups[key].push(org)
    else
      groups.未知.push(org)
  })

  return groups
})

const regionPageSize = 3
const regionPageIndex = ref<Record<string, number>>({})

function getGroupByRegionKey(key: string): OrganizationProfile[] {
  return (groupedByRegion.value as Record<string, OrganizationProfile[]>)[key] ?? []
}

function getRegionCurrentPage(key: string) {
  return Math.max(1, regionPageIndex.value[key] ?? 1)
}

function getRegionTotalPages(key: string) {
  const total = getGroupByRegionKey(key).length
  return Math.max(1, Math.ceil(total / regionPageSize))
}

function hasRegionPagination(key: string) {
  return getGroupByRegionKey(key).length > regionPageSize
}

function getPagedGroupByRegionKey(key: string): OrganizationProfile[] {
  const group = getGroupByRegionKey(key)
  const totalPages = getRegionTotalPages(key)
  const currentPage = Math.min(getRegionCurrentPage(key), totalPages)

  if (regionPageIndex.value[key] !== currentPage) {
    regionPageIndex.value[key] = currentPage
  }

  const start = (currentPage - 1) * regionPageSize
  return group.slice(start, start + regionPageSize)
}

function goPrevRegionPage(key: string) {
  const current = getRegionCurrentPage(key)
  if (current > 1) {
    regionPageIndex.value[key] = current - 1
  }
}

function goNextRegionPage(key: string) {
  const current = getRegionCurrentPage(key)
  const totalPages = getRegionTotalPages(key)
  if (current < totalPages) {
    regionPageIndex.value[key] = current + 1
  }
}

watch(
  groupedByRegion,
  () => {
    const nextPageMap: Record<string, number> = {}
    Object.keys(regionAnchors).forEach((key) => {
      const totalPages = getRegionTotalPages(key)
      const current = regionPageIndex.value[key] ?? 1
      nextPageMap[key] = Math.min(Math.max(current, 1), totalPages)
    })
    regionPageIndex.value = nextPageMap
  },
  { immediate: true, deep: true },
)

function generateRandomEvents(): AptEvent[] {
  const organizations = spatialOrganizations.value.map(org => org.name).filter(Boolean)
  const defaultOrganizations = organizations.length > 0 ? organizations : ['Lazarus', 'Gamaredon', '透明部落', '响尾蛇']
  const eventTypes = ['major', 'normal'] as const
  const titles = ['发现新的C2服务器', '大规模攻击活动', '网络钓鱼活动', '威胁检测', '新域名注册']

  const events: AptEvent[] = []
  const startDate = dayjs('2025-01-01')
  const endDate = dayjs('2025-12-31')
  const totalDays = endDate.diff(startDate, 'day')

  for (let i = 0; i < 25; i++) {
    const randomDay = Math.floor(Math.random() * totalDays)
    const eventDate = startDate.add(randomDay, 'day')
    const type = eventTypes[Math.floor(Math.random() * eventTypes.length)]
    const organization = defaultOrganizations[Math.floor(Math.random() * defaultOrganizations.length)]
    const title = titles[Math.floor(Math.random() * titles.length)]

    events.push({
      id: `event-fallback-${i + 1}`,
      date: eventDate.format('YYYY-MM-DD'),
      title,
      description: `${organization} 相关威胁活动监测`,
      type,
      organization,
    })
  }

  return events.sort((a, b) => dayjs(a.date).valueOf() - dayjs(b.date).valueOf())
}

// 加载汇总统计数据
async function loadSummaryStats() {
  try {
    const response = await fetch('/api/dashboard/data-display/summary')
    if (response.ok) {
      const result = await response.json()
      if (result.code === 200 && result.data) {
        stats.aptOrganizationTotal = result.data.totalOrganizations || 0
        stats.dnsAnomalyDetection = result.data.totalDomains || 0
        
        // 威胁分类数据
        if (result.data.threatBreakdown) {
          const breakdown = result.data.threatBreakdown

          // 新格式：[{ type, value }]
          if (Array.isArray(breakdown)) {
            const merged = new Map<string, number>()
            breakdown.forEach((item: any) => {
              const type = formatThreatTypeLabel(item?.type)
              const value = Number(item?.value || 0)
              merged.set(type, (merged.get(type) || 0) + value)
            })

            threatTypeData.value = DEFAULT_THREAT_TYPE_DATA.map(item => ({
              type: item.type,
              value: merged.get(item.type) || 0,
            }))
          }
          else {
            // 兼容旧格式对象
            threatTypeData.value = [
              { type: 'DNS隧道', value: breakdown.dnsTunnel || 0 },
              { type: 'DGA域名', value: breakdown.dgaDomain || 0 },
              { type: '钓鱼域名', value: breakdown.phishing || 0 },
              { type: 'C2通信', value: breakdown.c2Communication || 0 },
              { type: '其他', value: breakdown.malware || 0 },
            ]
          }
        }
      }
    }
  } catch (error) {
    console.error('加载统计数据失败:', error)
  }
}

// 加载更新时间在 2025-01-01 之后的组织数量
async function loadActiveOrganizationsAfter2025() {
  try {
    const threshold = new Date('2025-01-01T00:00:00')
    const pageSize = 100
    let page = 1
    let totalPages = 1
    let count = 0

    while (page <= totalPages) {
      const response = await queryOrganizationsApi({ page, pageSize })
      if (response.code !== 200 || !response.data?.list) {
        break
      }

      const list = response.data.list
      count += list.filter((org) => {
        const dateSource = org.latestEventDate || org.updateTime
        if (!dateSource)
          return false
        const updateDate = new Date(dateSource)
        return !Number.isNaN(updateDate.getTime()) && updateDate > threshold
      }).length

      const total = response.data.total || list.length
      totalPages = Math.max(1, Math.ceil(total / pageSize))
      page++
    }

    stats.activeOrganizations = count
  }
  catch (error) {
    console.error('加载活跃组织数量失败:', error)
  }
}

// 加载APT事件总量
async function loadAptEventCount() {
  try {
    const response = await queryEventsApi({ page: 1, pageSize: 1 })
    if (response.code === 200 && response.data) {
      stats.latestThreats = response.data.total || response.data.list?.length || 0
    }
  }
  catch (error) {
    console.error('加载APT事件数量失败:', error)
  }
}

// 跳转到组织画像页面
function goToOrganizationProfile() {
  router.push('/dashboard/profile')
}

function goToActiveOrganizations() {
  router.push({
    path: '/dashboard/profile',
    query: { activeOnly: '1' },
  })
}

// 跳转到时空分布页面的APT事件时间轴
function goToAptTimeline() {
  const target = document.querySelector('#apt-event-timeline')
  if (target) {
    target.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
}

// 跳转到域名属性页面
function goToDomainAttributes() {
  router.push('/dashboard/attributes')
}

// 加载攻击来源Top10
async function loadRegionDistribution() {
  try {
    const response = await fetch('/api/dashboard/data-display/region-distribution')
    if (response.ok) {
      const result = await response.json()
      if (result.code === 200 && Array.isArray(result.data) && result.data.length > 0) {
        attackSourceTop10.value = result.data.slice(0, 10).map((item: any) => ({
          country: item.region || '未知',
          count: item.count || 0,
        }))
        return
      }
    }
    attackSourceTop10.value = []
  } catch (error) {
    console.error('加载攻击来源失败:', error)
  }
}

// 加载组织恶意域名排名Top10
async function loadOrgMaliciousDomainTop10() {
  try {
    const response = await fetch('/api/dashboard/data-display/top-organizations?limit=10&order_by=malicious_domain_count')
    if (response.ok) {
      const result = await response.json()
      if (result.code === 200 && result.data) {
        orgMaliciousDomainTop10.value = result.data.map((item: any) => ({
          organization: item.name || '未知',
          count: item.count || 0
        }))
      }
    }
  } catch (error) {
    console.error('加载组织数据失败:', error)
  }
}

// 加载时空分布数据
async function loadSpatialData() {
  spatialLoading.value = true
  try {
    const [allEvents, orgsResult] = await Promise.all([
      fetchAllEvents(),
      queryOrganizationsApi({ page: 1, pageSize: 100 }),
    ])

    if (orgsResult?.code === 200 && orgsResult.data?.list) {
      spatialOrganizations.value = orgsResult.data.list
    }

    allAptEvents.value = allEvents

    if (allAptEvents.value.length === 0) {
      allAptEvents.value = generateRandomEvents()
    }
  }
  catch (error) {
    console.error('加载时空分布数据失败:', error)
    allAptEvents.value = generateRandomEvents()
  }
  finally {
    spatialLoading.value = false
  }
}

function handleEventClick(event: AptEvent) {
  selectedEvent.value = event
  selectedOrganization.value = null
  selectedOrgTimelineEvents.value = []
}

async function handleOrganizationClick(org: OrganizationProfile) {
  selectedOrganization.value = org
  selectedEvent.value = null
  selectedOrgTimelineEvents.value = []

  const orgId = Number(org.id)
  if (Number.isNaN(orgId))
    return

  spatialLoading.value = true
  try {
    selectedOrgTimelineEvents.value = await fetchAllEvents({ organizationId: orgId })
  }
  catch (error) {
    console.error('加载组织时间轴事件失败:', error)
  }
  finally {
    spatialLoading.value = false
  }
}

function resetSpatialFilter() {
  selectedEvent.value = null
  selectedOrganization.value = null
  selectedOrgTimelineEvents.value = []
}

function formatDate(dateStr?: string): string {
  if (!dateStr)
    return '-'
  return dayjs(dateStr).format('YYYY-MM-DD')
}

function initVpsChart(containerId: string, data: { provider: string; count: number; percentage: number }[]) {
  nextTick(() => {
    const container = document.getElementById(containerId)
    if (!container)
      return

    container.innerHTML = ''

    const chartData = data.map(item => ({
      type: item.provider,
      value: item.percentage,
    }))

    const pie = new Pie(container, {
      data: chartData,
      angleField: 'value',
      colorField: 'type',
      radius: 0.8,
      innerRadius: 0.5,
      label: {
        type: 'inner',
        offset: '-50%',
        content: '{value}%',
        style: {
          textAlign: 'center',
          fontSize: 12,
        },
      },
      interactions: [{ type: 'element-active' }],
      statistic: {
        title: false,
        content: {
          style: {
            whiteSpace: 'pre-wrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          },
          content: 'VPS分布',
        },
      },
    })

    pie.render()
  })
}

function renderDashboardCharts() {
  if (!pieContainer.value || !columnContainer.value || !orgIocColumnContainer.value)
    return

  try {
    pieChart.value?.destroy()
    attackSourceChart.value?.destroy()
    orgIocChart.value?.destroy()

    pieChart.value = new Pie(pieContainer.value, {
      data: threatTypeData.value,
      angleField: 'value',
      colorField: 'type',
      height: 280,
      radius: 0.8,
      innerRadius: 0.6,
      label: {
        type: 'spider',
        labelHeight: 28,
        content: '{name}\n{percentage}',
      },
      color: ['#5B8FF9', '#5AD8A6', '#5D7092', '#F6BD16', '#E86452'],
      interactions: [{ type: 'element-active' }],
      legend: {
        position: 'bottom',
      },
      statistic: {
        title: {
          content: '威胁总数',
          style: {
            fontSize: '14px',
          },
        },
        content: {
          style: {
            fontSize: '24px',
          },
          formatter: () => {
            const total = threatTypeData.value.reduce((sum, item) => sum + item.value, 0)
            return convertNumber(total)
          },
        },
      },
    })
    pieChart.value.render()

    attackSourceChart.value = new Column(columnContainer.value, {
      data: attackSourceTop10.value,
      xField: 'country',
      yField: 'count',
      height: 280,
      color: '#5B8FF9',
      label: {
        position: 'top',
        offset: 5,
        style: {
          fill: '#000000',
          opacity: 0.6,
          fontSize: 12,
        },
      },
      appendPadding: [20, 0, 0, 0],
      xAxis: {
        label: {
          autoRotate: false,
          autoHide: false,
          autoEllipsis: false,
        },
      },
      meta: {
        country: {
          alias: '地区',
        },
        count: {
          alias: '攻击事件数',
        },
      },
    })
    attackSourceChart.value.render()

    orgIocChart.value = new Column(orgIocColumnContainer.value, {
      data: orgMaliciousDomainTop10.value,
      xField: 'organization',
      yField: 'count',
      height: 280,
      color: '#5AD8A6',
      label: {
        position: 'top',
        offset: 5,
        style: {
          fill: '#000000',
          opacity: 0.6,
          fontSize: 12,
        },
      },
      appendPadding: [20, 0, 0, 0],
      xAxis: {
        label: {
          autoRotate: true,
          autoHide: false,
        },
      },
      meta: {
        organization: {
          alias: '组织',
        },
        count: {
          alias: '恶意域名数量',
        },
      },
    })
    orgIocChart.value.render()
  }
  catch (error) {
    console.error('渲染首页图表失败:', error)
  }
}

watch(
  relatedOrganizations,
  (newList) => {
    nextTick(() => {
      newList.forEach((org) => {
        if (org.vpsProviders?.length) {
          initVpsChart(`vps-chart-${org.id}`, org.vpsProviders)
        }
      })
    })
  },
  { deep: true, immediate: true },
)

watch(
  [threatTypeData, attackSourceTop10, orgMaliciousDomainTop10, isSpatialDetailView],
  async () => {
    if (!isSpatialDetailView.value) {
      await nextTick()
      renderDashboardCharts()
    }
  },
  { deep: true },
)

onMounted(async () => {
  // 加载所有统计数据
  await Promise.all([
    loadSummaryStats(),
    loadActiveOrganizationsAfter2025(),
    loadAptEventCount(),
    loadRegionDistribution(),
    loadOrgMaliciousDomainTop10(),
    loadSpatialData(),
  ])

  // 等待数据加载完成后再渲染图表
  await nextTick()
  renderDashboardCharts()

  if (window.location.hash === '#apt-event-timeline') {
    goToAptTimeline()
  }
})
</script>

<template>
  <page-container>
    <!-- 顶部统计卡片 -->
    <a-row v-if="!isSpatialDetailView" :gutter="16" style="margin-bottom: 24px">
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card clickable-stat-card" @click="goToOrganizationProfile">
          <a-statistic
            title="APT组织总量"
            :value="convertNumber(stats.aptOrganizationTotal)"
            :value-style="{ color: '#3f8600' }"
          >
            <template #prefix>
              <DatabaseOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card clickable-stat-card" @click="goToActiveOrganizations">
          <a-statistic
            title="活跃组织数量"
            :value="convertNumber(stats.activeOrganizations)"
            :value-style="{ color: '#cf1322' }"
          >
            <template #prefix>
              <TeamOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card clickable-stat-card" @click="goToAptTimeline">
          <a-statistic
            title="APT事件数量"
            :value="convertNumber(stats.latestThreats)"
            :value-style="{ color: '#ff9800' }"
          >
            <template #prefix>
              <WarningOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card clickable-stat-card" @click="goToDomainAttributes">
          <a-statistic
            title="恶意域名总数"
            :value="convertNumber(stats.dnsAnomalyDetection)"
            :value-style="{ color: '#13c2c2' }"
          >
            <template #prefix>
              <ExclamationCircleOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
    </a-row>

    <!-- 时空分布整合区域 -->
    <a-card
      v-if="!selectedEvent && !selectedOrganization"
      id="organization-profile"
      :bordered="false"
      :style="{ marginBottom: '24px' }"
    >
      <template #title>
        <a-typography-title :level="5" style="margin: 0;">
          APT组织地理分布
        </a-typography-title>
      </template>
      <div class="map-wrapper">
        <div class="map-canvas">
          <div class="map-container">
            <img :src="worldMapImage" alt="世界地图" class="map-image">
            <svg class="connection-lines" xmlns="http://www.w3.org/2000/svg">
              <template v-for="(anchor, key) in regionAnchors" :key="`line-${key}`">
                <template v-if="getGroupByRegionKey(key as string).length > 0">
                  <template v-if="(anchor as any).lineBendX && (anchor as any).lineBendY">
                    <line
                      :x1="(anchor as any).pinX"
                      :y1="(anchor as any).pinY"
                      :x2="(anchor as any).lineBendX"
                      :y2="(anchor as any).lineBendY"
                      class="anchor-line"
                    />
                    <line
                      :x1="(anchor as any).lineBendX"
                      :y1="(anchor as any).lineBendY"
                      :x2="(anchor as any).labelX"
                      :y2="(anchor as any).labelY"
                      class="anchor-line"
                    />
                  </template>
                  <line
                    v-else
                    :x1="(anchor as any).pinX"
                    :y1="(anchor as any).pinY"
                    :x2="(anchor as any).labelX"
                    :y2="(anchor as any).labelY"
                    class="anchor-line"
                  />
                </template>
              </template>
            </svg>

            <template v-for="(anchor, key) in regionAnchors" :key="`pin-${key}`">
              <div
                v-if="getGroupByRegionKey(key as string).length > 0"
                class="map-pin"
                :style="{ left: (anchor as any).pinX, top: (anchor as any).pinY }"
              >
                <div class="pin-dot" />
                <div class="pin-label">
                  {{ (anchor as any).label }}
                </div>
              </div>
            </template>

            <template v-for="(anchor, key) in regionAnchors" :key="`label-${key}`">
              <div
                v-if="getGroupByRegionKey(key as string).length > 0"
                class="org-label-box"
                :class="`align-${(anchor as any).labelAlign || 'center'}`"
                :style="{ left: (anchor as any).labelX, top: (anchor as any).labelY }"
              >
                <div class="label-orgs">
                  <a-tag
                    v-for="org in getPagedGroupByRegionKey(key as string)"
                    :key="org.id"
                    color="cyan"
                    class="clickable org-tag"
                    :title="org.name"
                    @click="handleOrganizationClick(org)"
                  >
                    {{ org.name }}
                  </a-tag>
                </div>
                <div v-if="hasRegionPagination(key as string)" class="label-pagination">
                  <a-button
                    type="link"
                    size="small"
                    class="pagination-btn"
                    :disabled="getRegionCurrentPage(key as string) <= 1"
                    @click.stop="goPrevRegionPage(key as string)"
                  >
                    上一页
                  </a-button>
                  <span class="page-indicator">
                    {{ getRegionCurrentPage(key as string) }} / {{ getRegionTotalPages(key as string) }}
                  </span>
                  <a-button
                    type="link"
                    size="small"
                    class="pagination-btn"
                    :disabled="getRegionCurrentPage(key as string) >= getRegionTotalPages(key as string)"
                    @click.stop="goNextRegionPage(key as string)"
                  >
                    下一页
                  </a-button>
                </div>
              </div>
            </template>
          </div>
        </div>
      </div>
    </a-card>

    <a-card id="apt-event-timeline" :bordered="false" :style="{ marginBottom: '24px' }">
      <template #title>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span>APT事件时间轴</span>
          <a-button
            v-if="selectedEvent || selectedOrganization"
            type="link"
            size="large"
            class="return-filter-btn"
            @click="resetSpatialFilter"
          >
            返回
          </a-button>
        </div>
      </template>

      <AptTimeline :events="filteredEvents" @event-click="handleEventClick" />

      <div v-if="selectedEvent" class="selected-panel">
        <a-space direction="vertical" style="width: 100%;" :size="8">
          <div>
            <a-typography-text strong>
              选中事件：
            </a-typography-text>
            <a-tag color="blue" style="margin-left: 8px;">
              {{ selectedEvent.title }}
            </a-tag>
          </div>
          <div>
            <a-typography-text type="secondary">
              日期：
            </a-typography-text>
            <a-typography-text style="margin-left: 8px;">
              {{ formatDate(selectedEvent.date) }}
            </a-typography-text>
          </div>
          <div v-if="selectedEvent.organization">
            <a-typography-text type="secondary">
              相关组织：
            </a-typography-text>
            <a-tag color="green" style="margin-left: 8px;">
              {{ selectedEvent.organization }}
            </a-tag>
          </div>
          <div v-if="selectedEvent.description">
            <a-typography-text type="secondary">
              描述：
            </a-typography-text>
            <a-typography-text style="margin-left: 8px;">
              {{ selectedEvent.description }}
            </a-typography-text>
          </div>
          <div v-if="selectedEvent.reportUrl">
            <a-typography-text type="secondary">
              事件报告：
            </a-typography-text>
            <a :href="selectedEvent.reportUrl" target="_blank" rel="noopener noreferrer" style="margin-left: 8px;">
              {{ selectedEvent.reportUrl }}
            </a>
          </div>
          <div>
            <a-typography-text type="secondary">
              相关组织数量：
            </a-typography-text>
            <a-typography-text strong style="margin-left: 8px;">
              {{ relatedOrganizations.length }} 个
            </a-typography-text>
          </div>
        </a-space>
      </div>

      <div v-else-if="selectedOrganization" class="selected-panel">
        <a-space direction="vertical" style="width: 100%;" :size="8">
          <div>
            <a-typography-text strong>
              选中组织：
            </a-typography-text>
            <a-tag color="green" style="margin-left: 8px;">
              {{ selectedOrganization.name }}
            </a-tag>
          </div>
          <div>
            <a-typography-text type="secondary">
              相关事件数量：
            </a-typography-text>
            <a-typography-text strong style="margin-left: 8px;">
              {{ filteredEvents.length }} 个
            </a-typography-text>
          </div>
        </a-space>
      </div>
    </a-card>

    <a-spin v-if="selectedEvent || selectedOrganization" :spinning="spatialLoading">
      <template v-if="relatedOrganizations.length > 0">
        <a-row :gutter="[16, 16]">
          <a-col
            v-for="org in relatedOrganizations"
            :key="org.id"
            :xs="24"
            :sm="24"
            :md="24"
            :lg="24"
            :xl="24"
          >
            <a-card class="organization-card" :bordered="false" :hoverable="true" :style="{ height: '100%' }">
              <template #title>
                <div class="org-header">
                  <a-tag color="green" style="margin-right: 8px;">
                    APT
                  </a-tag>
                  <a-typography-title :level="4" style="margin: 0; display: inline;">
                    {{ org.name }}
                  </a-typography-title>
                </div>
              </template>

              <div class="org-content">
                <div v-if="org.alias && org.alias.length > 0" class="org-section">
                  <a-typography-text type="secondary" strong>
                    别名：
                  </a-typography-text>
                  <a-space wrap style="margin-top: 4px;">
                    <a-tag v-for="(alias, index) in org.alias" :key="index" color="blue">
                      {{ alias }}
                    </a-tag>
                  </a-space>
                </div>

                <div class="org-section">
                  <a-typography-paragraph :ellipsis="{ rows: 3, expandable: false }" :style="{ marginBottom: 0 }">
                    {{ org.description }}
                  </a-typography-paragraph>
                </div>

                <div class="org-section">
                  <a-space :size="24">
                    <span>
                      <a-typography-text type="secondary">
                        关联恶意域名：
                      </a-typography-text>
                      <a-typography-text strong>
                        {{ formatMaliciousDomainCount(org.maliciousDomainCount ?? org.iocCount) }} 个
                      </a-typography-text>
                    </span>
                    <span>
                      <a-typography-text type="secondary">
                        关联事件：
                      </a-typography-text>
                      <a-typography-text strong>
                        {{ org.eventCount ?? 0 }} 个
                      </a-typography-text>
                    </span>
                  </a-space>
                </div>

                <div class="org-section">
                  <a-space wrap>
                    <a-tag v-if="org.region" color="cyan">
                      区域：{{ org.region }}
                    </a-tag>
                    <a-tag v-if="org.origin" color="orange">
                      来源：{{ org.origin }}
                    </a-tag>
                  </a-space>
                </div>

                <div v-if="org.previousDomains && org.previousDomains.length > 0" class="org-section">
                  <a-typography-text type="secondary" strong>
                    曾用域名：
                  </a-typography-text>
                  <div style="margin-top: 8px;">
                    <a-space wrap>
                      <a-tag
                        v-for="(domain, index) in org.previousDomains"
                        :key="index"
                        color="purple"
                        style="font-family: monospace; font-size: 11px;"
                      >
                        {{ domain }}
                      </a-tag>
                    </a-space>
                  </div>
                </div>

                <div v-if="org.vpsProviders && org.vpsProviders.length > 0" class="org-section">
                  <a-typography-text type="secondary" strong>
                    VPS分布：各组织的VPS服务商使用偏好
                  </a-typography-text>
                  <div style="margin-top: 8px;">
                    <div :id="`vps-chart-${org.id}`" style="height: 200px; margin-bottom: 8px;" />

                    <a-list :data-source="org.vpsProviders" :pagination="false" size="small" :bordered="true">
                      <template #renderItem="{ item }">
                        <a-list-item>
                          <a-row style="width: 100%;" :gutter="8">
                            <a-col :span="12">
                              <a-typography-text strong>
                                {{ item.provider }}
                              </a-typography-text>
                            </a-col>
                            <a-col :span="6" style="text-align: right;">
                              <a-typography-text type="secondary">
                                {{ item.count }} 个
                              </a-typography-text>
                            </a-col>
                            <a-col :span="6" style="text-align: right;">
                              <a-tag color="blue">
                                {{ item.percentage }}%
                              </a-tag>
                            </a-col>
                          </a-row>
                        </a-list-item>
                      </template>
                    </a-list>
                  </div>
                </div>

                <div class="org-section org-update-time">
                  <a-typography-text type="secondary" style="font-size: 12px;">
                    更新时间：{{ formatDate(org.updateTime) }}
                  </a-typography-text>
                </div>
              </div>
            </a-card>
          </a-col>
        </a-row>
      </template>

      <a-empty v-else-if="!spatialLoading" description="暂无相关组织数据" :style="{ marginTop: '50px' }" />
    </a-spin>

    <!-- 威胁类型分布和图表展示区 -->
    <a-row v-if="!isSpatialDetailView" :gutter="24">
      <a-col :xl="8" :lg="24" :md="24" :sm="24" :xs="24" :style="{ marginBottom: '24px' }">
        <a-card title="威胁类型分布" :bordered="false">
          <div ref="pieContainer" />
        </a-card>
      </a-col>
      <a-col :xl="8" :lg="12" :md="12" :sm="24" :xs="24" :style="{ marginBottom: '24px' }">
        <a-card title="攻击来源 TOP10" :bordered="false">
          <div ref="columnContainer" />
        </a-card>
      </a-col>
      <a-col :xl="8" :lg="12" :md="12" :sm="24" :xs="24" :style="{ marginBottom: '24px' }">
        <a-card title="组织恶意域名排名 TOP10" :bordered="false">
          <div ref="orgIocColumnContainer" />
        </a-card>
      </a-col>
    </a-row>
  </page-container>
</template>

<style scoped lang="less">
.stat-card {
  transition: all 0.3s ease;
  &:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    transform: translateY(-2px);
  }
}

.clickable-stat-card {
  cursor: pointer;
}

.return-filter-btn {
  font-size: 16px;
  font-weight: 600;
}

.selected-panel {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #f0f0f0;
}

.organization-card {
  transition: all 0.3s;

  &:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    transform: translateY(-2px);
  }

  :deep(.ant-card-head-title) {
    padding: 16px 0 8px 0;
  }

  :deep(.ant-card-body) {
    padding: 0 24px 24px;
  }
}

.org-header {
  display: flex;
  align-items: center;
}

.org-content {
  .org-section {
    margin-bottom: 16px;

    &:last-child {
      margin-bottom: 0;
    }
  }
}

.org-update-time {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid #f0f0f0;
}

.map-wrapper {
  background: #ffffff;
  border-radius: 4px;
  padding: 12px;
}

.map-canvas {
  position: relative;
  width: 100%;
  box-sizing: border-box;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 500px;
  overflow: visible;
  padding: 20px;
  background-color: #ffffff;
}

.map-container {
  position: relative;
  width: 100%;
  min-width: 0;
  max-width: 1400px;
  margin: 0 auto;
}

.map-image {
  width: 100%;
  height: auto;
  display: block;
}

.connection-lines {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 1;
}

.anchor-line {
  stroke: rgba(24, 144, 255, 0.4);
  stroke-width: 1.5;
  stroke-dasharray: 4, 4;
  fill: none;
}

.map-pin {
  position: absolute;
  transform: translate(-50%, -50%);
  z-index: 3;
  pointer-events: none;
}

.pin-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #1890ff;
  box-shadow: 0 0 12px rgba(24, 144, 255, 0.8), 0 0 0 3px rgba(24, 144, 255, 0.2);
  animation: pulse 2s ease-in-out infinite;
}

@keyframes pulse {
  0%,
  100% {
    box-shadow: 0 0 12px rgba(24, 144, 255, 0.8), 0 0 0 3px rgba(24, 144, 255, 0.2);
  }
  50% {
    box-shadow: 0 0 18px rgba(24, 144, 255, 1), 0 0 0 6px rgba(24, 144, 255, 0.3);
  }
}

.pin-label {
  position: absolute;
  top: 18px;
  left: 50%;
  transform: translateX(-50%);
  font-size: 11px;
  font-weight: 600;
  color: #1890ff;
  white-space: nowrap;
  background: rgba(255, 255, 255, 0.95);
  padding: 2px 6px;
  border-radius: 3px;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.15);
}

.org-label-box {
  position: absolute;
  z-index: 5;
  pointer-events: auto;
  background: rgba(255, 255, 255, 0.98);
  border: 2px solid #40a9ff;
  border-radius: 8px;
  padding: 10px 12px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  width: fit-content;
  min-width: 0;
  max-width: min(440px, calc(60% - 16px));
  box-sizing: border-box;
}

.org-label-box.align-left {
  transform: translateY(-50%);
}

.org-label-box.align-right {
  transform: translate(-100%, -50%);
}

.org-label-box.align-center {
  transform: translate(-50%, -50%);
}

.label-orgs {
  display: flex;
  flex-wrap: nowrap;
  gap: 6px;
  align-items: center;
  max-width: 100%;
}

.org-tag {
  margin: 0 !important;
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 4px;
  min-width: 0;
  max-width: 18ch;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: block;
  line-height: 1.4;
  text-align: center;
}

.label-pagination {
  margin-top: 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.pagination-btn {
  padding: 0;
  height: 20px;
}

.page-indicator {
  font-size: 12px;
  color: rgba(0, 0, 0, 0.65);
}

.clickable {
  cursor: pointer;
  transition: all 0.2s;

  &:hover {
    transform: scale(1.05);
    box-shadow: 0 2px 8px rgba(24, 144, 255, 0.4);
  }
}

:deep(.ant-list-item) {
  padding: 8px 12px;
}

:deep(.ant-typography-paragraph) {
  margin-bottom: 0;
  color: rgba(0, 0, 0, 0.85);
  line-height: 1.8;
}
</style>
