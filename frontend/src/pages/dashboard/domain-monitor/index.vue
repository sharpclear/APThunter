<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import { ReloadOutlined, SearchOutlined, ThunderboltOutlined } from '@ant-design/icons-vue'
import type { DomainMonitorSnapshot, DomainMonitorTarget } from '~/api/domain-monitor'
import {
  getDomainMonitorSnapshotsApi,
  getDomainMonitorTargetsApi,
  triggerDomainMonitorTargetApi,
  triggerDueDomainMonitorTargetsApi,
} from '~/api/domain-monitor'

defineOptions({ name: 'DashboardDomainMonitor' })

const loading = ref(false)
const snapshotLoading = ref(false)
const triggerLoading = ref(false)
const targets = ref<DomainMonitorTarget[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const selectedTarget = ref<DomainMonitorTarget | null>(null)
const snapshots = ref<DomainMonitorSnapshot[]>([])
const snapshotTotal = ref(0)
const snapshotPage = ref(1)
const drawerOpen = ref(false)

const filters = reactive({
  domain: '',
  activeOnly: true,
})

const statusLabels: Record<string, string> = {
  pending: '待查询',
  checking: '查询中',
  active: '正常追踪',
  failed: '查询失败',
  paused: '已暂停',
}

const sectionLabels: Record<string, string> = {
  whois: 'WHOIS',
  dns: 'DNS',
  certificate: '证书',
  web: '网页',
}

const statusColors: Record<string, string> = {
  pending: 'blue',
  checking: 'processing',
  active: 'success',
  failed: 'error',
  paused: 'default',
}

const targetColumns = [
  { title: '域名', dataIndex: 'domain', key: 'domain', width: 260 },
  { title: '状态', dataIndex: 'status', key: 'status', width: 110 },
  { title: '来源数', dataIndex: 'sourceCount', key: 'sourceCount', width: 90 },
  { title: '最近查询', dataIndex: 'lastCheckedAt', key: 'lastCheckedAt', width: 170 },
  { title: '下次查询', dataIndex: 'nextCheckAt', key: 'nextCheckAt', width: 170 },
  { title: '变化', key: 'changed', width: 180 },
  { title: '操作', key: 'action', width: 150, fixed: 'right' as const },
]

const dnsColumns = [
  { title: '类型', dataIndex: 'type', key: 'type', width: 90 },
  { title: '名称', dataIndex: 'name', key: 'name', width: 180 },
  { title: '值', dataIndex: 'value', key: 'value' },
  { title: 'TTL', dataIndex: 'ttl', key: 'ttl', width: 90 },
  { title: '优先级', dataIndex: 'priority', key: 'priority', width: 90 },
]

const currentSnapshot = computed(() => snapshots.value[0] || null)
const activeCount = computed(() => targets.value.filter(item => item.isActive).length)
const checkingCount = computed(() => targets.value.filter(item => item.status === 'checking').length)
const changedCount = computed(() => {
  return targets.value.filter((item) => {
    const sections = item.latestSnapshot?.changedFields?.sections || []
    return sections.length > 0
  }).length
})

function unwrap<T>(response: any, fallback: T): T {
  return response?.data ?? response ?? fallback
}

function formatTime(value?: string) {
  if (!value)
    return '-'
  return value.replace('T', ' ').slice(0, 19)
}

function statusText(value?: string) {
  return statusLabels[value || ''] || value || '未知'
}

function changedSections(snapshot?: { changedFields?: { sections?: string[] } | null } | null) {
  return snapshot?.changedFields?.sections || []
}

function changedSectionText(section: string) {
  return sectionLabels[section] || section
}

function objectSummary(value: any) {
  if (!value)
    return '-'
  if (typeof value === 'string')
    return value
  if (Array.isArray(value))
    return value.join('、') || '-'
  if (typeof value === 'object') {
    return Object.entries(value)
      .filter(([, item]) => item !== undefined && item !== null && item !== '')
      .map(([key, item]) => `${key}: ${item}`)
      .join('；') || '-'
  }
  return String(value)
}

async function loadTargets(page = currentPage.value) {
  loading.value = true
  try {
    const response = await getDomainMonitorTargetsApi({
      page,
      pageSize: pageSize.value,
      activeOnly: filters.activeOnly,
      domain: filters.domain.trim() || undefined,
    })
    const payload = unwrap(response, { items: [], total: 0 })
    targets.value = payload.items || []
    total.value = Number(payload.total || 0)
    currentPage.value = page
  }
  catch (error: any) {
    message.error(error?.response?.data?.detail || error?.message || '加载域名追踪列表失败')
  }
  finally {
    loading.value = false
  }
}

async function loadSnapshots(target: DomainMonitorTarget, page = 1) {
  snapshotLoading.value = true
  try {
    const response = await getDomainMonitorSnapshotsApi(target.id, {
      page,
      pageSize: 10,
    })
    const payload = unwrap(response, { target, items: [], total: 0 })
    selectedTarget.value = payload.target || target
    snapshots.value = payload.items || []
    snapshotTotal.value = Number(payload.total || 0)
    snapshotPage.value = page
  }
  catch (error: any) {
    message.error(error?.response?.data?.detail || error?.message || '加载域名追踪快照失败')
  }
  finally {
    snapshotLoading.value = false
  }
}

async function openDetail(target: any) {
  const monitorTarget = target as DomainMonitorTarget
  selectedTarget.value = monitorTarget
  drawerOpen.value = true
  await loadSnapshots(monitorTarget, 1)
}

async function triggerTarget(target: any) {
  const monitorTarget = target as DomainMonitorTarget
  triggerLoading.value = true
  try {
    await triggerDomainMonitorTargetApi(monitorTarget.id)
    message.success('已提交立即查询任务')
    await loadTargets()
    if (selectedTarget.value?.id === monitorTarget.id)
      await loadSnapshots(monitorTarget, 1)
  }
  catch (error: any) {
    message.error(error?.response?.data?.detail || error?.message || '触发查询失败')
  }
  finally {
    triggerLoading.value = false
  }
}

async function triggerDueTargets() {
  triggerLoading.value = true
  try {
    await triggerDueDomainMonitorTargetsApi(50)
    message.success('已触发到期域名追踪任务')
    await loadTargets()
  }
  catch (error: any) {
    message.error(error?.response?.data?.detail || error?.message || '触发到期追踪失败')
  }
  finally {
    triggerLoading.value = false
  }
}

function handleSearch() {
  loadTargets(1)
}

onMounted(() => loadTargets())
</script>

<template>
  <page-container class="domain-monitor-page">
    <div class="toolbar">
      <div>
        <div class="page-title">域名追踪</div>
        <div class="page-subtitle">持续追踪系统检测命中的恶意域名，定期采集 DNS、WHOIS、证书和网页变化。</div>
      </div>
      <a-space wrap>
        <a-input
          v-model:value="filters.domain"
          allow-clear
          class="search-input"
          placeholder="搜索域名"
          @press-enter="handleSearch"
        >
          <template #prefix><SearchOutlined /></template>
        </a-input>
        <a-checkbox v-model:checked="filters.activeOnly" @change="handleSearch">仅活跃</a-checkbox>
        <a-button :loading="loading" @click="loadTargets()">
          <template #icon><ReloadOutlined /></template>
          刷新
        </a-button>
        <a-button type="primary" :loading="triggerLoading" @click="triggerDueTargets">
          <template #icon><ThunderboltOutlined /></template>
          触发到期追踪
        </a-button>
      </a-space>
    </div>

    <a-row :gutter="[12, 12]" class="summary-row">
      <a-col :xs="12" :md="6">
        <a-card :bordered="false" class="summary-card">
          <a-statistic title="追踪域名" :value="total" />
        </a-card>
      </a-col>
      <a-col :xs="12" :md="6">
        <a-card :bordered="false" class="summary-card">
          <a-statistic title="当前页活跃" :value="activeCount" />
        </a-card>
      </a-col>
      <a-col :xs="12" :md="6">
        <a-card :bordered="false" class="summary-card">
          <a-statistic title="查询中" :value="checkingCount" />
        </a-card>
      </a-col>
      <a-col :xs="12" :md="6">
        <a-card :bordered="false" class="summary-card">
          <a-statistic title="当前页有变化" :value="changedCount" />
        </a-card>
      </a-col>
    </a-row>

    <a-card :bordered="false" class="table-card">
      <a-table
        :columns="targetColumns"
        :data-source="targets"
        :loading="loading"
        :row-key="record => record.id"
        :scroll="{ x: 1160 }"
        :pagination="{
          current: currentPage,
          pageSize,
          total,
          showSizeChanger: true,
          showTotal: value => `共 ${value} 个追踪域名`,
          onChange: (page, size) => {
            pageSize = size
            loadTargets(page)
          },
        }"
        size="middle"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'domain'">
            <div class="domain-cell">
              <span class="domain-name">{{ record.domain }}</span>
              <span class="domain-sub">{{ record.normalizedDomain }}</span>
            </div>
          </template>
          <template v-else-if="column.key === 'status'">
            <a-tag :color="statusColors[record.status] || 'default'">
              {{ statusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'lastCheckedAt'">
            {{ formatTime(record.lastCheckedAt) }}
          </template>
          <template v-else-if="column.key === 'nextCheckAt'">
            {{ formatTime(record.nextCheckAt) }}
          </template>
          <template v-else-if="column.key === 'changed'">
            <template v-if="changedSections(record.latestSnapshot).length">
              <a-tag v-for="section in changedSections(record.latestSnapshot)" :key="section" color="orange">
                {{ changedSectionText(section) }}
              </a-tag>
            </template>
            <span v-else>-</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space>
              <a-button type="link" size="small" @click="openDetail(record)">详情</a-button>
              <a-button type="link" size="small" :loading="triggerLoading" @click="triggerTarget(record)">立即查询</a-button>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-drawer
      v-model:open="drawerOpen"
      width="820"
      :title="selectedTarget ? `追踪详情：${selectedTarget.domain}` : '追踪详情'"
    >
      <a-spin :spinning="snapshotLoading">
        <template v-if="selectedTarget">
          <div class="detail-meta">
            <a-tag :color="statusColors[selectedTarget.status] || 'default'">{{ statusText(selectedTarget.status) }}</a-tag>
            <span>最近查询：{{ formatTime(selectedTarget.lastCheckedAt) }}</span>
            <span>下次查询：{{ formatTime(selectedTarget.nextCheckAt) }}</span>
          </div>

          <a-alert
            v-if="selectedTarget.lastError"
            type="error"
            show-icon
            class="detail-alert"
            :message="selectedTarget.lastError"
          />

          <template v-if="currentSnapshot">
            <div class="detail-section">
              <div class="section-title">变化字段</div>
              <template v-if="changedSections(currentSnapshot).length">
                <a-tag v-for="section in changedSections(currentSnapshot)" :key="section" color="orange">
                  {{ changedSectionText(section) }}
                </a-tag>
              </template>
              <span v-else>本次快照未发现稳定字段变化</span>
            </div>

            <div class="detail-section">
              <div class="section-title">WHOIS 信息</div>
              <a-descriptions bordered size="small" :column="1">
                <a-descriptions-item label="注册商">{{ currentSnapshot.whois?.registrar || '-' }}</a-descriptions-item>
                <a-descriptions-item label="注册时间">{{ currentSnapshot.whois?.registration_date || '-' }}</a-descriptions-item>
                <a-descriptions-item label="过期时间">{{ currentSnapshot.whois?.expiration_date || '-' }}</a-descriptions-item>
                <a-descriptions-item label="更新时间">{{ currentSnapshot.whois?.updated_date || '-' }}</a-descriptions-item>
                <a-descriptions-item label="NameServer">{{ objectSummary(currentSnapshot.whois?.name_servers) }}</a-descriptions-item>
                <a-descriptions-item label="状态">{{ objectSummary(currentSnapshot.whois?.status) }}</a-descriptions-item>
                <a-descriptions-item label="注册人">{{ objectSummary(currentSnapshot.whois?.registrant) }}</a-descriptions-item>
              </a-descriptions>
            </div>

            <div class="detail-section">
              <div class="section-title">DNS 记录</div>
              <a-table
                :columns="dnsColumns"
                :data-source="currentSnapshot.dns?.records || []"
                :pagination="{ pageSize: 8 }"
                :row-key="record => `${record.type}-${record.name}-${record.value}`"
                size="small"
                bordered
              />
            </div>

            <div class="detail-section">
              <div class="section-title">证书信息</div>
              <a-descriptions bordered size="small" :column="1">
                <a-descriptions-item label="颁发者">{{ objectSummary(currentSnapshot.certificate?.issuer) }}</a-descriptions-item>
                <a-descriptions-item label="主体">{{ objectSummary(currentSnapshot.certificate?.subject) }}</a-descriptions-item>
                <a-descriptions-item label="生效时间">{{ currentSnapshot.certificate?.not_before || '-' }}</a-descriptions-item>
                <a-descriptions-item label="过期时间">{{ currentSnapshot.certificate?.not_after || '-' }}</a-descriptions-item>
                <a-descriptions-item label="算法">{{ currentSnapshot.certificate?.algorithm || '-' }}</a-descriptions-item>
                <a-descriptions-item label="密钥长度">{{ currentSnapshot.certificate?.key_size || '-' }}</a-descriptions-item>
                <a-descriptions-item label="序列号">{{ currentSnapshot.certificate?.serial_number || '-' }}</a-descriptions-item>
                <a-descriptions-item label="SAN">{{ objectSummary(currentSnapshot.certificate?.san_names) }}</a-descriptions-item>
                <a-descriptions-item label="指纹">{{ currentSnapshot.certificate?.fingerprint || '-' }}</a-descriptions-item>
              </a-descriptions>
            </div>
          </template>
          <a-empty v-else description="暂无追踪快照" />

          <div class="detail-section">
            <div class="section-title">历史快照</div>
            <a-list
              :data-source="snapshots"
              :pagination="{
                current: snapshotPage,
                pageSize: 10,
                total: snapshotTotal,
                onChange: page => selectedTarget && loadSnapshots(selectedTarget, page),
              }"
              size="small"
              bordered
            >
              <template #renderItem="{ item }">
                <a-list-item>
                  <a-list-item-meta>
                    <template #title>
                      <a-space>
                        <span>{{ formatTime(item.collectedAt) }}</span>
                        <a-tag :color="statusColors[item.status] || 'default'">{{ statusText(item.status) }}</a-tag>
                      </a-space>
                    </template>
                    <template #description>
                      <span v-if="changedSections(item).length">
                        变化：{{ changedSections(item).map(changedSectionText).join('、') }}
                      </span>
                      <span v-else>无变化</span>
                      <span v-if="item.errorMessage">；错误：{{ item.errorMessage }}</span>
                    </template>
                  </a-list-item-meta>
                </a-list-item>
              </template>
            </a-list>
          </div>
        </template>
      </a-spin>
    </a-drawer>
  </page-container>
</template>

<style scoped>
:deep(.ant-pro-page-container-children-content) {
  background: #f5f7fb;
}

.domain-monitor-page {
  padding-bottom: 8px;
}

.toolbar {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
}

.page-title {
  color: #1f2937;
  font-size: 22px;
  font-weight: 700;
  line-height: 1.4;
}

.page-subtitle {
  margin-top: 4px;
  color: #667085;
}

.search-input {
  width: 260px;
}

.summary-row {
  margin-bottom: 16px;
}

.summary-card,
.table-card {
  border: 1px solid rgba(220, 226, 235, 0.9);
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(15, 35, 80, 0.05);
}

.domain-cell {
  display: flex;
  min-width: 0;
  flex-direction: column;
}

.domain-name {
  color: #1f2937;
  font-weight: 700;
}

.domain-sub {
  overflow: hidden;
  color: #667085;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.detail-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 12px;
  color: #667085;
}

.detail-alert {
  margin-bottom: 12px;
}

.detail-section {
  margin-top: 18px;
}

.section-title {
  margin-bottom: 10px;
  color: #1f2937;
  font-weight: 700;
}

@media (max-width: 768px) {
  .toolbar {
    flex-direction: column;
  }

  .search-input {
    width: 100%;
  }
}
</style>
