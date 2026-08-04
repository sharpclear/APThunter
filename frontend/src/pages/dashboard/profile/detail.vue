<script setup lang="ts">
import type { DomainListItem } from '~/api/dashboard/attributes'
import type { OrganizationProfile } from '~/api/dashboard/profile'
import type { SpatialEvent } from '~/api/dashboard/spatial'
import type { AptEvent } from '~/components/apt-timeline/index.vue'
import {
  ArrowLeftOutlined,
  CalendarOutlined,
  DatabaseOutlined,
  DownloadOutlined,
  EnvironmentOutlined,
  GlobalOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, nextTick, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getDomainListApi } from '~/api/dashboard/attributes'
import { exportOrganizationCsvApi, queryOrganizationDetailApi } from '~/api/dashboard/profile'
import { queryEventsApi } from '~/api/dashboard/spatial'
import AptTimeline from '~/components/apt-timeline/index.vue'

defineOptions({ name: 'DashboardOrganizationDetail' })

const route = useRoute()
const router = useRouter()
const activeTab = ref('overview')
const organization = ref<OrganizationProfile | null>(null)
const domains = ref<DomainListItem[]>([])
const events = ref<SpatialEvent[]>([])
const organizationLoading = ref(false)
const domainsLoading = ref(false)
const eventsLoading = ref(false)
const exportLoading = ref(false)
const eventPage = ref(1)
const eventPageSize = 5
const selectedEventId = ref<number | null>(null)
const eventTableAnchor = ref<HTMLElement | null>(null)

const organizationId = computed(() => Number(route.params.id))
const maliciousDomainCount = computed(() => {
  if (!domainsLoading.value)
    return domains.value.length
  return Number(organization.value?.maliciousDomainCount ?? organization.value?.iocCount ?? 0)
})
const eventCount = computed(() => {
  if (!eventsLoading.value)
    return events.value.length
  return Number(organization.value?.eventCount ?? 0)
})
const firstEventDate = computed(() => {
  const dates = events.value
    .map(item => dayjs(item.eventDate))
    .filter(item => item.isValid())
    .sort((a, b) => a.valueOf() - b.valueOf())
  return dates[0]?.format('YYYY-MM-DD') || '-'
})
const latestEventDate = computed(() => {
  const dates = events.value
    .map(item => dayjs(item.eventDate))
    .filter(item => item.isValid())
    .sort((a, b) => b.valueOf() - a.valueOf())
  return dates[0]?.format('YYYY-MM-DD') || organization.value?.latestEventDate || '-'
})

const timelineEvents = computed<AptEvent[]>(() => events.value.map(event => ({
  id: `event-${event.id}`,
  date: event.eventDate,
  title: event.title || '未命名事件',
  description: event.description || '-',
  reportUrl: event.reportUrl,
  releasingProduct: event.releasingProduct,
  type: event.eventType || 'normal',
  organization: event.organizationName || organization.value?.name || '',
})))

const domainColumns = [
  { title: '恶意域名', dataIndex: 'domain', key: 'domain', width: 320 },
  { title: '恶意标记', dataIndex: 'isMalicious', key: 'isMalicious', width: 110 },
  { title: '属性数据', key: 'attributes', width: 240 },
  { title: '入库时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
]

const eventColumns = [
  { title: '事件时间', dataIndex: 'eventDate', key: 'eventDate', width: 130 },
  { title: '事件名称', dataIndex: 'title', key: 'title', width: 300 },
  { title: '类型', dataIndex: 'threatType', key: 'threatType', width: 140 },
  { title: '披露厂商', dataIndex: 'releasingProduct', key: 'releasingProduct', width: 180 },
  { title: '事件描述', dataIndex: 'description', key: 'description', width: 520 },
  { title: '原报告', dataIndex: 'reportUrl', key: 'reportUrl', width: 110 },
]

function formatDate(value?: string) {
  if (!value)
    return '-'
  const date = dayjs(value)
  return date.isValid() ? date.format('YYYY-MM-DD HH:mm:ss') : value
}

function hasValue(value?: string | null) {
  return Boolean(value && value.trim())
}

async function loadOrganization(id: number) {
  organizationLoading.value = true
  try {
    const response = await queryOrganizationDetailApi(id)
    organization.value = response.data || null
  }
  catch (error) {
    console.error('加载组织详情失败:', error)
    organization.value = null
    message.error('加载组织详情失败，请稍后重试')
  }
  finally {
    organizationLoading.value = false
  }
}

async function loadDomains(id: number) {
  domainsLoading.value = true
  try {
    const response = await getDomainListApi({ organizationId: id, maliciousOnly: true })
    domains.value = response.code === 200 && response.data ? response.data : []
  }
  catch (error) {
    console.error('加载组织恶意域名失败:', error)
    domains.value = []
    message.error('加载组织恶意域名失败，请稍后重试')
  }
  finally {
    domainsLoading.value = false
  }
}

async function loadEvents(id: number) {
  eventsLoading.value = true
  try {
    const allEvents: SpatialEvent[] = []
    const pageSize = 500
    let page = 1
    let total = 0

    do {
      const response = await queryEventsApi({ organizationId: id, page, pageSize })
      const list = response.data?.list || []
      total = Number(response.data?.total || list.length)
      allEvents.push(...list)
      if (list.length === 0)
        break
      page += 1
    } while (allEvents.length < total && page <= 100)

    events.value = allEvents
  }
  catch (error) {
    console.error('加载组织APT事件失败:', error)
    events.value = []
    message.error('加载组织APT事件失败，请稍后重试')
  }
  finally {
    eventsLoading.value = false
  }
}

async function loadDetailPage() {
  const id = organizationId.value
  if (!Number.isInteger(id) || id <= 0) {
    message.error('组织编号无效')
    router.replace('/dashboard/profile')
    return
  }

  organization.value = null
  domains.value = []
  events.value = []
  activeTab.value = 'overview'
  eventPage.value = 1
  selectedEventId.value = null
  await Promise.all([loadOrganization(id), loadDomains(id), loadEvents(id)])
}

function goBack() {
  router.push('/dashboard/profile')
}

function goToDomainAttributes() {
  if (!organization.value)
    return
  router.push({
    path: '/dashboard/attributes',
    query: {
      orgId: String(organization.value.id),
      orgName: organization.value.name,
    },
  })
}

function openDomainAttributes(domain: string) {
  if (!organization.value)
    return

  router.push({
    path: '/dashboard/attributes',
    query: {
      domain,
      orgId: String(organization.value.id),
      orgName: organization.value.name,
    },
  })
}

function handleTimelineEventClick(event: AptEvent) {
  const id = Number(String(event.id).replace(/^event-/, ''))
  const eventIndex = events.value.findIndex(item => Number(item.id) === id)
  if (eventIndex < 0)
    return

  selectedEventId.value = id
  eventPage.value = Math.floor(eventIndex / eventPageSize) + 1
  nextTick(() => eventTableAnchor.value?.scrollIntoView({ behavior: 'smooth', block: 'start' }))
}

function handleEventTableChange(pagination: { current?: number }) {
  eventPage.value = pagination.current || 1
}

function getEventRowClass(record: SpatialEvent) {
  return Number(record.id) === selectedEventId.value ? 'selected-event-row' : ''
}

function formatEventType(record: Record<string, any>) {
  if (record.threatType?.trim())
    return record.threatType
  return record.eventType === 'major' ? '重要事件' : '普通事件'
}

async function exportOrganizationInfo() {
  if (!organization.value)
    return

  exportLoading.value = true
  try {
    const blob = await exportOrganizationCsvApi(organization.value.id)
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    const safeName = organization.value.name.replace(/[\\/:*?"<>|]/g, '_').replace(/[. ]+$/g, '') || '组织信息'
    link.href = url
    link.download = `${safeName}.csv`
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
    message.success('组织信息已开始下载')
  }
  catch (error) {
    console.error('导出组织信息失败:', error)
    message.error('导出组织信息失败，请稍后重试')
  }
  finally {
    exportLoading.value = false
  }
}

watch(() => route.params.id, loadDetailPage, { immediate: true })
</script>

<template>
  <page-container>
    <a-space class="page-actions" wrap>
      <a-button @click="goBack">
        <template #icon>
          <ArrowLeftOutlined />
        </template>
        返回组织列表
      </a-button>
      <a-button :loading="exportLoading" @click="exportOrganizationInfo">
        <template #icon>
          <DownloadOutlined />
        </template>
        导出信息
      </a-button>
    </a-space>

    <a-spin :spinning="organizationLoading">
      <template v-if="organization">
        <section class="organization-hero">
          <div class="hero-mark">
            APT
          </div>
          <div class="hero-main">
            <div class="hero-title-row">
              <div>
                <div class="hero-kicker">
                  APT ORGANIZATION PROFILE
                </div>
                <div class="hero-name-line">
                  <h1>{{ organization.name }}</h1>
                  <a-tag color="red">
                    威胁组织
                  </a-tag>
                </div>
              </div>
            </div>

            <div class="hero-meta">
              <span><EnvironmentOutlined /> 来源：{{ organization.origin || '未知' }}</span>
              <span><GlobalOutlined /> 区域：{{ organization.region || '未知' }}</span>
              <span><CalendarOutlined /> 最近活动：{{ latestEventDate }}</span>
            </div>

            <div v-if="organization.alias?.length" class="hero-aliases">
              <span class="meta-label">组织别名</span>
              <a-tag v-for="alias in organization.alias" :key="alias" color="blue">
                {{ alias }}
              </a-tag>
            </div>
          </div>

          <div class="hero-stats">
            <div class="hero-stat">
              <strong>{{ maliciousDomainCount.toLocaleString() }}</strong>
              <span>相关恶意域名</span>
            </div>
            <div class="hero-stat">
              <strong>{{ eventCount.toLocaleString() }}</strong>
              <span>相关APT事件</span>
            </div>
          </div>
        </section>

        <a-card class="detail-card" :bordered="false">
          <a-tabs v-model:active-key="activeTab" class="detail-tabs">
            <a-tab-pane key="overview" tab="组织描述">
              <div class="overview-grid">
                <section class="content-panel description-panel">
                  <div class="section-heading">
                    <SafetyCertificateOutlined />
                    <span>组织描述</span>
                  </div>
                  <p class="description-text">
                    {{ organization.description || '暂无组织描述' }}
                  </p>
                </section>

                <section class="content-panel">
                  <div class="section-heading">
                    <GlobalOutlined />
                    <span>基本信息</span>
                  </div>
                  <a-descriptions :column="{ xs: 1, sm: 1, md: 2, lg: 2, xl: 2, xxl: 2 }" bordered size="small">
                    <a-descriptions-item label="组织名称">
                      {{ organization.name }}
                    </a-descriptions-item>
                    <a-descriptions-item label="来源国家/地区">
                      {{ organization.origin || '-' }}
                    </a-descriptions-item>
                    <a-descriptions-item label="所属区域">
                      {{ organization.region || '-' }}
                    </a-descriptions-item>
                    <a-descriptions-item label="最早事件时间">
                      {{ firstEventDate }}
                    </a-descriptions-item>
                    <a-descriptions-item label="最近事件时间">
                      {{ latestEventDate }}
                    </a-descriptions-item>
                    <a-descriptions-item label="资料更新时间">
                      {{ formatDate(organization.updateTime) }}
                    </a-descriptions-item>
                    <a-descriptions-item label="相关恶意域名">
                      {{ maliciousDomainCount.toLocaleString() }} 个
                    </a-descriptions-item>
                    <a-descriptions-item label="相关APT事件">
                      {{ eventCount.toLocaleString() }} 个
                    </a-descriptions-item>
                  </a-descriptions>
                </section>

                <section class="content-panel">
                  <div class="section-heading">
                    目标国家/地区
                  </div>
                  <a-space v-if="organization.targetCountries?.length" wrap>
                    <a-tag v-for="country in organization.targetCountries" :key="country" color="cyan">
                      {{ country }}
                    </a-tag>
                  </a-space>
                  <a-empty v-else :image="undefined" description="暂无目标国家/地区信息" />
                </section>

                <section class="content-panel">
                  <div class="section-heading">
                    目标行业
                  </div>
                  <a-space v-if="organization.targetIndustries?.length" wrap>
                    <a-tag v-for="industry in organization.targetIndustries" :key="industry" color="orange">
                      {{ industry }}
                    </a-tag>
                  </a-space>
                  <a-empty v-else :image="undefined" description="暂无目标行业信息" />
                </section>
              </div>
            </a-tab-pane>

            <a-tab-pane key="domains">
              <template #tab>
                <span><DatabaseOutlined /> 相关恶意域名（{{ maliciousDomainCount }}）</span>
              </template>
              <div class="tab-toolbar">
                <div>
                  <h3>相关恶意域名</h3>
                  <p>展示数据库中与该组织关联且标记为恶意的域名。</p>
                </div>
                <a-button type="primary" @click="goToDomainAttributes">
                  进入域名属性分析
                </a-button>
              </div>
              <a-table
                :columns="domainColumns"
                :data-source="domains"
                :loading="domainsLoading"
                row-key="domain"
                :scroll="{ x: 900 }"
                :pagination="{ pageSize: 15, showSizeChanger: true, showQuickJumper: true, showTotal: (total: number) => `共 ${total} 条` }"
              >
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'domain'">
                    <a class="domain-name" @click="openDomainAttributes(record.domain)">
                      <GlobalOutlined /> {{ record.domain }}
                    </a>
                  </template>
                  <template v-else-if="column.key === 'isMalicious'">
                    <a-tag :color="record.isMalicious ? 'red' : 'default'">
                      {{ record.isMalicious ? '恶意' : '未标记' }}
                    </a-tag>
                  </template>
                  <template v-else-if="column.key === 'attributes'">
                    <a-space :size="4" wrap>
                      <a-tag :color="record.hasWhois ? 'blue' : 'default'">
                        WHOIS
                      </a-tag>
                      <a-tag :color="record.hasDns ? 'green' : 'default'">
                        DNS
                      </a-tag>
                      <a-tag :color="record.hasSsl ? 'orange' : 'default'">
                        SSL
                      </a-tag>
                    </a-space>
                  </template>
                  <template v-else-if="column.key === 'createdAt'">
                    {{ formatDate(record.createdAt) }}
                  </template>
                </template>
                <template #emptyText>
                  <a-empty description="暂无相关恶意域名" />
                </template>
              </a-table>
            </a-tab-pane>

            <a-tab-pane key="events">
              <template #tab>
                <span><CalendarOutlined /> APT事件时间轴（{{ eventCount }}）</span>
              </template>
              <div class="tab-toolbar">
                <div>
                  <h3>APT事件时间轴</h3>
                  <p>按时间展示该组织关联的APT活动，点击原报告可查看事件来源。</p>
                </div>
              </div>
              <a-spin :spinning="eventsLoading">
                <div v-if="timelineEvents.length" class="timeline-panel">
                  <AptTimeline :events="timelineEvents" @event-click="handleTimelineEventClick" />
                </div>
                <a-empty v-else-if="!eventsLoading" description="暂无相关APT事件" />
              </a-spin>

              <div ref="eventTableAnchor" class="event-table-anchor">
                <a-table
                  class="event-table"
                  :columns="eventColumns"
                  :data-source="events"
                  :loading="eventsLoading"
                  row-key="id"
                  :row-class-name="getEventRowClass"
                  :scroll="{ x: 1200 }"
                  :pagination="{ current: eventPage, pageSize: eventPageSize, showSizeChanger: false, showQuickJumper: true, showTotal: (total: number) => `共 ${total} 条` }"
                  @change="handleEventTableChange"
                >
                  <template #bodyCell="{ column, record }">
                    <template v-if="column.key === 'threatType'">
                      <a-tag color="blue">
                        {{ formatEventType(record) }}
                      </a-tag>
                    </template>
                    <template v-else-if="column.key === 'description'">
                      <div class="event-description-cell">
                        {{ record.description || '暂无描述' }}
                      </div>
                    </template>
                    <template v-else-if="column.key === 'releasingProduct'">
                      {{ record.releasingProduct || '-' }}
                    </template>
                    <template v-else-if="column.key === 'reportUrl'">
                      <a v-if="hasValue(record.reportUrl)" :href="record.reportUrl" target="_blank" rel="noopener noreferrer">查看报告</a>
                      <span v-else>-</span>
                    </template>
                  </template>
                  <template #emptyText>
                    <a-empty description="暂无相关APT事件" />
                  </template>
                </a-table>
              </div>
            </a-tab-pane>
          </a-tabs>
        </a-card>
      </template>

      <a-result v-else-if="!organizationLoading" status="404" title="未找到组织" sub-title="该组织可能不存在或已被删除">
        <template #extra>
          <a-button type="primary" @click="goBack">
            返回组织列表
          </a-button>
        </template>
      </a-result>
    </a-spin>
  </page-container>
</template>

<style scoped lang="less">
.page-actions {
  display: flex;
  justify-content: space-between;
  width: 100%;
  margin-bottom: 16px;
}

.organization-hero {
  position: relative;
  display: grid;
  grid-template-columns: 112px minmax(0, 1fr) auto;
  gap: 24px;
  align-items: center;
  min-height: 190px;
  margin-bottom: 16px;
  padding: 28px 32px;
  overflow: hidden;
  color: rgba(0, 0, 0, 0.88);
  background:
    radial-gradient(circle at 92% 12%, rgba(22, 119, 255, 0.09), transparent 30%),
    linear-gradient(135deg, #ffffff 0%, #f8fbff 56%, #eef5ff 100%);
  border: 1px solid #dbeafe;
  border-top: 3px solid #1677ff;
  border-radius: 10px;
  box-shadow: 0 4px 16px rgba(31, 73, 125, 0.08);
}

.hero-mark {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 104px;
  height: 104px;
  font-size: 28px;
  font-weight: 800;
  letter-spacing: 2px;
  color: #1677ff;
  background: linear-gradient(145deg, #f0f7ff, #e6f4ff);
  border: 1px solid #91caff;
  border-radius: 50%;
  box-shadow:
    inset 0 0 24px rgba(22, 119, 255, 0.08),
    0 6px 18px rgba(22, 119, 255, 0.12);
}

.hero-main {
  min-width: 0;
}

.hero-title-row {
  display: flex;
  gap: 16px;
  align-items: center;
}

.hero-kicker {
  margin-bottom: 4px;
  font-size: 11px;
  letter-spacing: 2px;
  color: #1677ff;
}

.hero-name-line {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
}

.hero-title-row h1 {
  margin: 0;
  font-size: 30px;
  color: rgba(0, 0, 0, 0.88);
}

.hero-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 28px;
  margin-top: 18px;
  color: rgba(0, 0, 0, 0.65);
}

.hero-meta span {
  display: inline-flex;
  gap: 7px;
  align-items: center;
}

.hero-aliases {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  margin-top: 16px;
}

.meta-label {
  margin-right: 4px;
  color: rgba(0, 0, 0, 0.45);
}

.hero-stats {
  display: flex;
  gap: 12px;
}

.hero-stat {
  min-width: 130px;
  padding: 18px;
  text-align: center;
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid #d6e4ff;
  border-radius: 8px;
  box-shadow: 0 3px 10px rgba(22, 119, 255, 0.07);
}

.hero-stat strong {
  display: block;
  font-size: 26px;
  color: #1677ff;
}

.hero-stat span {
  display: block;
  margin-top: 3px;
  font-size: 12px;
  color: rgba(0, 0, 0, 0.45);
}

.detail-card {
  min-height: 460px;
}
.detail-tabs :deep(.ant-tabs-nav) {
  margin-bottom: 24px;
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.content-panel {
  min-width: 0;
  padding: 20px;
  background: #fafafa;
  border: 1px solid #f0f0f0;
  border-radius: 8px;
}

.description-panel {
  grid-column: 1 / -1;
}

.section-heading {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 14px;
  font-size: 16px;
  font-weight: 600;
  color: rgba(0, 0, 0, 0.88);
}

.description-text {
  margin: 0;
  line-height: 1.9;
  white-space: pre-wrap;
}

.tab-toolbar {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 18px;
}

.tab-toolbar h3 {
  margin: 0 0 4px;
}
.tab-toolbar p {
  margin: 0;
  color: rgba(0, 0, 0, 0.45);
}
.domain-name {
  font-family: Consolas, Monaco, monospace;
  color: #cf1322;
}
.timeline-panel {
  margin-bottom: 20px;
  overflow-x: auto;
  border: 1px solid #f0f0f0;
  border-radius: 8px;
}
.event-table {
  margin-top: 20px;
}

.event-table-anchor {
  scroll-margin-top: 16px;
}

.event-description-cell {
  max-height: 108px;
  overflow-y: auto;
  line-height: 1.8;
  white-space: pre-wrap;
}

:deep(.selected-event-row > td) {
  background: #e6f4ff !important;
  box-shadow:
    inset 0 1px 0 #91caff,
    inset 0 -1px 0 #91caff;
}

@media (max-width: 1100px) {
  .organization-hero {
    grid-template-columns: 88px minmax(0, 1fr);
  }
  .hero-mark {
    width: 80px;
    height: 80px;
    font-size: 22px;
  }
  .hero-stats {
    grid-column: 1 / -1;
  }
  .hero-stat {
    flex: 1;
  }
}

@media (max-width: 768px) {
  .organization-hero {
    grid-template-columns: 1fr;
    padding: 22px;
  }
  .hero-mark {
    display: none;
  }
  .hero-title-row {
    align-items: flex-start;
  }
  .hero-title-row h1 {
    font-size: 24px;
  }
  .hero-stats {
    flex-direction: column;
  }
  .overview-grid {
    grid-template-columns: 1fr;
  }
  .description-panel {
    grid-column: auto;
  }
  .tab-toolbar {
    flex-direction: column;
    gap: 12px;
  }
}
</style>
