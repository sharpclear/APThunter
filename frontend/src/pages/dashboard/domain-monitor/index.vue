<script setup lang="ts">
import type { DomainMonitorSnapshot, DomainMonitorTarget } from '~/api/domain-monitor'
import { DownloadOutlined, ReloadOutlined, SearchOutlined, ThunderboltOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, reactive, ref } from 'vue'
import {
  exportDomainMonitorCsvApi,
  getDomainMonitorSnapshotsApi,
  getDomainMonitorTargetsApi,
  triggerDomainMonitorTargetApi,
  triggerDueDomainMonitorTargetsApi,
} from '~/api/domain-monitor'

defineOptions({ name: 'DashboardDomainMonitor' })

const loading = ref(false)
const snapshotLoading = ref(false)
const triggerLoading = ref(false)
const exportLoading = ref(false)
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
  fingerprint: '指纹',
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
  if (Array.isArray(value)) {
    return value
      .map(item => typeof item === 'object' && item !== null ? JSON.stringify(item) : String(item))
      .join('、') || '-'
  }
  if (typeof value === 'object') {
    return Object.entries(value)
      .filter(([, item]) => item !== undefined && item !== null && item !== '')
      .map(([key, item]) => `${key}: ${typeof item === 'object' ? JSON.stringify(item) : item}`)
      .join('；') || '-'
  }
  return String(value)
}

function booleanText(value: any) {
  if (value === true)
    return '是'
  if (value === false)
    return '否'
  return '-'
}

function dayText(value: any) {
  return value === undefined || value === null ? '-' : `${value} 天`
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

function exportFilename() {
  const now = new Date()
  const parts = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, '0'),
    String(now.getDate()).padStart(2, '0'),
    String(now.getHours()).padStart(2, '0'),
    String(now.getMinutes()).padStart(2, '0'),
    String(now.getSeconds()).padStart(2, '0'),
  ]
  return `域名追踪_${parts.join('')}.csv`
}

async function exportCsv() {
  exportLoading.value = true
  try {
    const blob = await exportDomainMonitorCsvApi({
      activeOnly: filters.activeOnly,
      domain: filters.domain.trim() || undefined,
    })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = exportFilename()
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
    message.success('域名追踪数据已开始下载')
  }
  catch (error: any) {
    message.error(error?.response?.data?.detail || error?.message || '导出域名追踪数据失败')
  }
  finally {
    exportLoading.value = false
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
        <div class="page-subtitle">持续追踪系统检测命中的恶意域名，定期采集 DNS、WHOIS、证书、TLS 和网页应用指纹变化。</div>
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
        <a-button :loading="exportLoading" :disabled="total === 0" @click="exportCsv">
          <template #icon><DownloadOutlined /></template>
          导出 CSV
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
                <a-descriptions-item label="联系邮箱域">{{ objectSummary(currentSnapshot.whois?.email_domains) }}</a-descriptions-item>
                <a-descriptions-item label="隐私代理">{{ booleanText(currentSnapshot.whois?.privacy_proxy_detected) }}</a-descriptions-item>
                <a-descriptions-item label="NameServer 集合指纹">{{ currentSnapshot.whois?.name_server_set_sha256 || '-' }}</a-descriptions-item>
                <a-descriptions-item label="注册身份指纹">{{ currentSnapshot.whois?.registrant_identity_sha256 || '-' }}</a-descriptions-item>
              </a-descriptions>
            </div>

            <div class="detail-section">
              <div class="section-title">DNS 与网络指纹</div>
              <a-descriptions bordered size="small" :column="1" class="fingerprint-summary">
                <a-descriptions-item label="解析 IP">{{ objectSummary(currentSnapshot.dns?.resolved_ips) }}</a-descriptions-item>
                <a-descriptions-item label="网络前缀">{{ objectSummary(currentSnapshot.dns?.network_prefixes) }}</a-descriptions-item>
                <a-descriptions-item label="CNAME">{{ objectSummary(currentSnapshot.dns?.cnames) }}</a-descriptions-item>
                <a-descriptions-item label="NameServer">{{ objectSummary(currentSnapshot.dns?.name_servers) }}</a-descriptions-item>
                <a-descriptions-item label="邮件服务器">{{ objectSummary(currentSnapshot.dns?.mail_servers) }}</a-descriptions-item>
                <a-descriptions-item label="记录类型统计">{{ objectSummary(currentSnapshot.dns?.record_counts) }}</a-descriptions-item>
                <a-descriptions-item label="TTL 分布">{{ objectSummary(currentSnapshot.dns?.ttl_profile) }}</a-descriptions-item>
                <a-descriptions-item label="DNS 记录集合指纹">{{ currentSnapshot.dns?.record_set_sha256 || '-' }}</a-descriptions-item>
                <a-descriptions-item label="解析 IP 集合指纹">{{ currentSnapshot.dns?.resolved_ip_set_sha256 || '-' }}</a-descriptions-item>
              </a-descriptions>
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
                <a-descriptions-item label="公钥类型">{{ currentSnapshot.certificate?.public_key_type || '-' }}</a-descriptions-item>
                <a-descriptions-item label="密钥长度">{{ currentSnapshot.certificate?.key_size || '-' }}</a-descriptions-item>
                <a-descriptions-item label="序列号">{{ currentSnapshot.certificate?.serial_number || '-' }}</a-descriptions-item>
                <a-descriptions-item label="SAN">{{ objectSummary(currentSnapshot.certificate?.san_names) }}</a-descriptions-item>
                <a-descriptions-item label="证书 SHA-256">{{ currentSnapshot.certificate?.fingerprint || '-' }}</a-descriptions-item>
                <a-descriptions-item label="SPKI SHA-256">{{ currentSnapshot.certificate?.spki_fingerprint || '-' }}</a-descriptions-item>
                <a-descriptions-item label="连接 IP">{{ currentSnapshot.certificate?.connected_ip || '-' }}</a-descriptions-item>
                <a-descriptions-item label="TLS 版本">{{ currentSnapshot.certificate?.tls_version || '-' }}</a-descriptions-item>
                <a-descriptions-item label="密码套件">{{ objectSummary(currentSnapshot.certificate?.cipher) }}</a-descriptions-item>
                <a-descriptions-item label="ALPN">{{ currentSnapshot.certificate?.alpn_protocol || '-' }}</a-descriptions-item>
              </a-descriptions>
            </div>

            <div class="detail-section">
              <div class="section-title">网页与应用指纹</div>
              <a-descriptions bordered size="small" :column="1">
                <a-descriptions-item label="采集状态">{{ currentSnapshot.web?.status || '-' }}</a-descriptions-item>
                <a-descriptions-item label="最终地址">{{ currentSnapshot.web?.final_url || '-' }}</a-descriptions-item>
                <a-descriptions-item label="页面标题">{{ currentSnapshot.web?.title || '-' }}</a-descriptions-item>
                <a-descriptions-item label="生成器">{{ currentSnapshot.web?.generator || '-' }}</a-descriptions-item>
                <a-descriptions-item label="响应头">{{ objectSummary(currentSnapshot.web?.response_headers) }}</a-descriptions-item>
                <a-descriptions-item label="Cookie 名称与属性">{{ objectSummary(currentSnapshot.web?.cookies) }}</a-descriptions-item>
                <a-descriptions-item label="重定向链">{{ objectSummary(currentSnapshot.web?.redirect_chain) }}</a-descriptions-item>
                <a-descriptions-item label="外部资源主机">{{ objectSummary(currentSnapshot.web?.external_resource_hosts) }}</a-descriptions-item>
                <a-descriptions-item label="统计标识">{{ objectSummary(currentSnapshot.web?.analytics_identifiers) }}</a-descriptions-item>
                <a-descriptions-item label="表单目标">{{ objectSummary(currentSnapshot.web?.form_targets) }}</a-descriptions-item>
                <a-descriptions-item label="HTML SHA-256">{{ currentSnapshot.web?.html_hash || '-' }}</a-descriptions-item>
                <a-descriptions-item label="正文 SHA-256">{{ currentSnapshot.web?.text_hash || '-' }}</a-descriptions-item>
                <a-descriptions-item label="DOM 结构 SHA-256">{{ currentSnapshot.web?.dom_structure_sha256 || '-' }}</a-descriptions-item>
                <a-descriptions-item label="响应头 SHA-256">{{ currentSnapshot.web?.response_header_sha256 || '-' }}</a-descriptions-item>
                <a-descriptions-item label="资源 URL 集合 SHA-256">{{ currentSnapshot.web?.resource_url_set_sha256 || '-' }}</a-descriptions-item>
                <a-descriptions-item label="站点图标 SHA-256">{{ objectSummary(currentSnapshot.fingerprint?.application?.favicon_sha256) }}</a-descriptions-item>
              </a-descriptions>
            </div>

            <div class="detail-section">
              <div class="section-title">时间关系指纹</div>
              <a-descriptions bordered size="small" :column="1">
                <a-descriptions-item label="注册至更新间隔">{{ dayText(currentSnapshot.fingerprint?.temporal?.registration_to_update_days) }}</a-descriptions-item>
                <a-descriptions-item label="注册至证书签发间隔">{{ dayText(currentSnapshot.fingerprint?.temporal?.registration_to_certificate_days) }}</a-descriptions-item>
                <a-descriptions-item label="域名注册周期">{{ dayText(currentSnapshot.fingerprint?.temporal?.domain_registration_period_days) }}</a-descriptions-item>
                <a-descriptions-item label="证书有效周期">{{ dayText(currentSnapshot.fingerprint?.temporal?.certificate_validity_days) }}</a-descriptions-item>
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

.fingerprint-summary {
  margin-bottom: 12px;
}

:deep(.ant-descriptions-item-content) {
  overflow-wrap: anywhere;
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
