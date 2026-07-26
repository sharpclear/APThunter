<script setup lang="ts">
import { LoadingOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'FocusImpersonationDetection',
})

interface OfficialDomainItem {
  单位名称?: string
  官方域名: string
  置信度?: string | number
  说明?: string
}

interface PhishingResultItem {
  仿冒域名?: string
  钓鱼域名?: string
  官方域名?: string
  目标域名?: string
  官方域名单位名称?: string
  公司名称?: string
  单位类型?: string
  匹配类型?: string
  风险等级?: string
  研判原因?: string
  关键特征?: string
  归因组织?: string
  归因级别?: string
  APT置信度?: number
  强证据数?: number
  归因说明?: string
}

interface FocusResultData {
  ok?: boolean
  task_id?: string
  task_type?: string
  status?: string
  rawStatus?: string
  message?: string
  error?: string
  progress?: number
  progress_stage?: string
  focus_impersonation_detection?: boolean
  focus_query_name?: string
  statistics?: Record<string, string | number>
  official_domains?: OfficialDomainItem[]
  phishing_domains?: PhishingResultItem[]
  total_count?: number
  phishing_count?: number
  focus_report_filename?: string
  attribution_enabled?: boolean
  attribution_results?: Array<Record<string, any>>
}

interface PersistedFocusTask {
  taskId: string
  queryName: string
  dateRange: [string, string] | null
  withAttribution?: boolean
}

const API_BASE = getApiBase()
const userId = useUserId()
const token = useAuthorization()
const FOCUS_TASK_STORAGE_PREFIX = 'apthunter:focus-impersonation-task'

const queryName = ref('')
const dateRange = ref<[string, string] | null>(null)
const withAttribution = ref(false)
const submitLoading = ref(false)
const resultLoading = ref(false)
const currentTaskId = ref('')
const taskStatus = ref('')
const taskProgress = ref(0)
const taskStage = ref('')
const officialDomains = ref<OfficialDomainItem[]>([])
const resultData = ref<FocusResultData | null>(null)
const lastError = ref('')

const MIN_START_DATE = dayjs('2024-09-01')
const pickedAnchorDate = ref<dayjs.Dayjs | null>(null)
const pickedAnchorType = ref<'start' | 'end' | null>(null)
let pollingTimer: number | null = null
let componentUnmounted = false

const phishingRows = computed(() => resultData.value?.phishing_domains || [])
const statistics = computed(() => resultData.value?.statistics || {})
const hasCompleted = computed(() => taskStatus.value === 'completed' || !!resultData.value?.ok)
const focusTaskStorageKey = computed(() =>
  `${FOCUS_TASK_STORAGE_PREFIX}:${userId.value || 'anonymous'}`,
)
const isTaskRunning = computed(() =>
  ['submitting', 'pending', 'processing'].includes(taskStatus.value),
)
const taskStatusText = computed(() => {
  if (taskStage.value)
    return taskStage.value
  if (taskStatus.value === 'submitting')
    return '正在提交检测任务'
  if (taskStatus.value === 'pending')
    return '任务等待执行中'
  return '正在执行重点单位仿冒检测'
})
const taskStatusLabel = computed(() => {
  if (hasCompleted.value)
    return '已完成'
  if (taskStatus.value === 'failed')
    return '失败'
  if (taskStatus.value === 'submitting')
    return '提交中'
  if (taskStatus.value === 'processing')
    return '执行中'
  return '待执行'
})

const officialDomainColumns = [
  { title: '单位/对象', dataIndex: '单位名称', key: 'name', width: '28%', ellipsis: true },
  { title: '官方域名或子域名', dataIndex: '官方域名', key: 'domain', width: '34%', ellipsis: true },
  { title: '置信度', dataIndex: '置信度', key: 'confidence', width: '14%', align: 'center' as const },
  { title: '说明', dataIndex: '说明', key: 'reason', width: '24%', ellipsis: true },
]

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers.Authorization = `Bearer ${token.value}`
  return headers
}

function persistFocusTask(taskId: string, query: string, range: [string, string] | null) {
  try {
    const state: PersistedFocusTask = {
      taskId,
      queryName: query,
      dateRange: range,
      withAttribution: withAttribution.value,
    }
    localStorage.setItem(focusTaskStorageKey.value, JSON.stringify(state))
  }
  catch {}
}

function removePersistedFocusTask() {
  try {
    localStorage.removeItem(focusTaskStorageKey.value)
  }
  catch {}
}

function restoreFocusTask() {
  try {
    const raw = localStorage.getItem(focusTaskStorageKey.value)
    if (!raw)
      return
    const state = JSON.parse(raw) as PersistedFocusTask
    if (!state.taskId)
      return
    currentTaskId.value = state.taskId
    queryName.value = state.queryName || ''
    dateRange.value = state.dateRange || null
    withAttribution.value = !!state.withAttribution
    taskStatus.value = 'pending'
    taskStage.value = '正在恢复检测进度'
    lastError.value = ''
    void fetchResult(state.taskId)
  }
  catch {
    removePersistedFocusTask()
  }
}

function disabledNewDomainDate(current: dayjs.Dayjs) {
  const today = dayjs().endOf('day')
  const cur = dayjs(current).startOf('day')
  if (cur.isBefore(MIN_START_DATE, 'day') || cur.isAfter(today, 'day'))
    return true
  if (!pickedAnchorDate.value)
    return false
  const anchor = pickedAnchorDate.value.startOf('day')
  if (pickedAnchorType.value === 'start')
    return cur.isBefore(anchor, 'day') || cur.isAfter(anchor.add(30, 'day'), 'day')
  if (pickedAnchorType.value === 'end')
    return cur.isBefore(anchor.subtract(30, 'day'), 'day') || cur.isAfter(anchor, 'day')
  return false
}

function onCalendarChange(dates: any, _dateStrings: any, info: any) {
  if (!dates) {
    pickedAnchorDate.value = null
    pickedAnchorType.value = null
    return
  }
  const range = info?.range as 'start' | 'end' | undefined
  if (range === 'end' && dates[1]) {
    pickedAnchorDate.value = dayjs(dates[1])
    pickedAnchorType.value = 'end'
  }
  else if (dates[0]) {
    pickedAnchorDate.value = dayjs(dates[0])
    pickedAnchorType.value = 'start'
  }
}

function onOpenChange(open: boolean) {
  if (open) {
    pickedAnchorDate.value = null
    pickedAnchorType.value = null
  }
}

function formatDateList(dates: string[]) {
  const visible = dates.slice(0, 5).join('、')
  return dates.length > 5 ? `${visible} 等 ${dates.length} 天` : visible
}

async function ensureNewDomainDataAvailable(range: [string, string]) {
  const params = new URLSearchParams({ startDate: range[0], endDate: range[1] })
  const resp = await fetch(`${API_BASE}/new-domain-data/availability?${params.toString()}`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  const json = await resp.json().catch(() => null)
  if (!resp.ok) {
    const detail = json?.detail
    const detailMessage = typeof detail === 'object' ? detail?.message : detail
    throw new Error(detailMessage || json?.message || '检查新注册域名数据失败')
  }
  if (!json.available) {
    message.warning(json.message || '所选日期范围内暂无可用的新注册域名数据，请重新选择日期')
    return false
  }
  const unavailableDates = [...(json.missingDates || []), ...(json.invalidDates || [])]
  if (unavailableDates.length > 0)
    message.warning(`部分日期暂无可用数据：${formatDateList(unavailableDates)}，将仅检测可用日期。`)
  return true
}

function stopPolling() {
  if (pollingTimer) {
    window.clearTimeout(pollingTimer)
    pollingTimer = null
  }
}

function schedulePolling(taskId: string, delay = 2000) {
  stopPolling()
  if (componentUnmounted)
    return
  pollingTimer = window.setTimeout(() => {
    void fetchResult(taskId, true)
  }, delay)
}

async function submitTask() {
  if (isTaskRunning.value)
    return message.info('当前重点单位仿冒检测任务尚未完成')
  const query = queryName.value.trim()
  if (!query)
    return message.warning('请输入单位名或热点事件名')
  if (!dateRange.value)
    return message.warning('请选择新注册域名日期范围')
  const days = dayjs(dateRange.value[1]).startOf('day').diff(dayjs(dateRange.value[0]).startOf('day'), 'day')
  if (days > 30)
    return message.warning('日期范围最多为一个月')

  const submittedRange: [string, string] = [dateRange.value[0], dateRange.value[1]]
  submitLoading.value = true
  lastError.value = ''
  try {
    const available = await ensureNewDomainDataAvailable(submittedRange)
    if (!available)
      return

    const fd = new FormData()
    fd.append('queryName', query)
    fd.append('detectionDateRange', JSON.stringify(submittedRange))
    fd.append('withAttribution', String(withAttribution.value))
    const resp = await fetch(`${API_BASE}/focus-impersonation-tasks`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok) {
      const detail = json?.detail
      const detailMessage = typeof detail === 'object' ? detail?.message : detail
      throw new Error(detailMessage || json?.message || '提交失败')
    }
    stopPolling()
    removePersistedFocusTask()
    resultData.value = null
    officialDomains.value = []
    currentTaskId.value = json.task_id
    officialDomains.value = json.officialDomains || []
    taskStatus.value = json.status || 'pending'
    taskProgress.value = 0
    taskStage.value = '任务已提交，等待执行'
    persistFocusTask(currentTaskId.value, query, submittedRange)
    message.success('重点单位仿冒检测任务已提交')
    if (!componentUnmounted)
      void fetchResult(json.task_id)
  }
  catch (e: any) {
    lastError.value = e?.message || '未知错误'
    message.error(`提交失败：${lastError.value}`)
  }
  finally {
    submitLoading.value = false
  }
}

async function fetchResult(taskId = currentTaskId.value, silent = false) {
  if (!taskId || currentTaskId.value !== taskId)
    return
  if (!silent)
    resultLoading.value = true
  let retryable = true
  try {
    const resp = await fetch(`${API_BASE}/tasks/${taskId}/result`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok) {
      retryable = resp.status >= 500
      throw new Error(json?.detail || json?.message || '获取任务结果失败')
    }
    if (currentTaskId.value !== taskId)
      return

    if (Array.isArray(json?.official_domains))
      officialDomains.value = json.official_domains

    if (json?.ok && json?.statistics) {
      resultData.value = json
      officialDomains.value = json.official_domains || officialDomains.value
      taskStatus.value = 'completed'
      taskProgress.value = 100
      taskStage.value = '检测完成'
      lastError.value = ''
      stopPolling()
      return
    }

    taskStatus.value = json?.status || json?.rawStatus || 'processing'
    const progress = Number(json?.progress)
    taskProgress.value = Number.isFinite(progress) ? Math.max(0, Math.min(100, progress)) : 0
    taskStage.value = json?.progress_stage || json?.message || ''
    lastError.value = ''
    if (taskStatus.value === 'failed' || taskStatus.value === 'completed') {
      lastError.value = json?.error || json?.message || '任务结果不可用'
      stopPolling()
      return
    }
    schedulePolling(taskId)
  }
  catch (e: any) {
    if (currentTaskId.value !== taskId)
      return
    lastError.value = e?.message || '未知错误'
    if (!silent)
      message.error(`获取结果失败：${lastError.value}`)
    if (retryable && isTaskRunning.value) {
      schedulePolling(taskId, 3000)
    }
    else {
      taskStatus.value = 'failed'
      taskStage.value = ''
      stopPolling()
    }
  }
  finally {
    if (!silent)
      resultLoading.value = false
  }
}

async function downloadReport() {
  if (!currentTaskId.value)
    return message.warning('暂无可下载报告')
  try {
    const resp = await fetch(`${API_BASE}/tasks/${currentTaskId.value}/download`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    if (!resp.ok)
      throw new Error(await resp.text())
    const blob = await resp.blob()
    const disposition = resp.headers.get('content-disposition') || ''
    const match = disposition.match(/filename\*=utf-8''(.+)/i)
    const filename = decodeURIComponent(match?.[1] || resultData.value?.focus_report_filename || `${currentTaskId.value}_focus_impersonation_report.pdf`)
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  }
  catch (e: any) {
    message.error(`下载失败：${e?.message || '未知错误'}`)
  }
}

function getImpersonationDomain(item: PhishingResultItem) {
  return item.仿冒域名 || item.钓鱼域名 || '未知域名'
}

function getTargetName(item: PhishingResultItem) {
  return item.官方域名单位名称 || item.公司名称 || item.官方域名 || item.目标域名 || '未知对象'
}

function riskLevelColor(level?: string) {
  if (level === '高')
    return 'red'
  if (level === '中')
    return 'orange'
  if (level === '低')
    return 'blue'
  return 'default'
}

onMounted(() => {
  componentUnmounted = false
  restoreFocusTask()
})

onBeforeUnmount(() => {
  componentUnmounted = true
  stopPolling()
})
</script>

<template>
  <page-container class="focus-page">
    <a-row :gutter="[24, 24]">
      <a-col :xs="24" :xl="9">
        <a-card class="panel-card" :bordered="false">
          <div class="card-title">重点单位仿冒检测</div>
          <div class="card-subtitle">
            输入重点单位或热点事件名称，系统检索相关官方域名及子域名，并基于新注册域名执行仿冒检测。
          </div>
          <a-form layout="vertical" class="task-form">
            <a-form-item label="单位名或热点事件名">
              <a-input-search
                v-model:value="queryName"
                allow-clear
                placeholder="例如：中国人民银行、杭州亚运会、某某大学"
                :maxlength="120"
                :loading="submitLoading || isTaskRunning"
                @search="submitTask"
              />
            </a-form-item>
            <a-form-item label="新注册域名日期范围">
              <a-range-picker
                v-model:value="dateRange"
                :disabled-date="disabledNewDomainDate"
                format="YYYY-MM-DD"
                value-format="YYYY-MM-DD"
                style="width:100%"
                @calendar-change="onCalendarChange"
                @open-change="onOpenChange"
              />
            </a-form-item>
            <a-form-item>
              <a-checkbox v-model:checked="withAttribution">
                归因到组织
              </a-checkbox>
              <div class="attribution-help">
                勾选后，对检测结果中标记为恶意的域名实时补全 DNS、RDAP、TLS、IP/ASN 和 Web 应用指纹，并基于历史图谱归因。
              </div>
            </a-form-item>
            <div class="action-row">
              <a-button type="primary" :loading="submitLoading || isTaskRunning" @click="submitTask">
                创建检测任务
              </a-button>
              <a-button :disabled="!currentTaskId" @click="fetchResult()">
                刷新结果
              </a-button>
            </div>
          </a-form>

          <div v-if="currentTaskId" class="task-state">
            <div class="state-line">任务编号：{{ currentTaskId }}</div>
            <div class="state-line">
              当前状态：
              <a-tag :color="hasCompleted ? 'success' : taskStatus === 'failed' ? 'error' : 'processing'">
                {{ taskStatusLabel }}
              </a-tag>
            </div>
            <a-progress
              v-if="isTaskRunning"
              :percent="taskProgress"
              :show-info="taskProgress > 0"
              size="small"
            />
            <div v-if="lastError" class="error-text">{{ lastError }}</div>
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :xl="15">
        <a-card class="panel-card" :bordered="false">
          <div class="result-header">
            <div>
              <div class="card-title">检测结果概要</div>
              <div class="card-subtitle">
                展示检索到的官方域名基线，以及仿冒检测命中的重点对象。
              </div>
            </div>
            <div class="result-actions">
              <div v-if="isTaskRunning" class="detecting-status">
                <LoadingOutlined spin />
                <span>检测中</span>
              </div>
              <a-tag v-else-if="hasCompleted" color="green">检测完成</a-tag>
              <a-tag v-else-if="taskStatus === 'failed'" color="red">检测失败</a-tag>
              <a-button type="primary" :disabled="!hasCompleted" @click="downloadReport">
                下载PDF报告
              </a-button>
            </div>
          </div>

          <a-spin :spinning="resultLoading">
            <a-row :gutter="[12, 12]" class="stat-row">
              <a-col :xs="12" :md="6">
                <a-statistic title="官方域名" :value="officialDomains.length" />
              </a-col>
              <a-col :xs="12" :md="6">
                <a-statistic title="检测域名" :value="statistics['总域名数'] || resultData?.total_count || 0" />
              </a-col>
              <a-col :xs="12" :md="6">
                <a-statistic title="仿冒域名" :value="statistics['仿冒域名数'] || statistics['钓鱼域名数'] || resultData?.phishing_count || 0" :value-style="{ color: '#cf1322' }" />
              </a-col>
              <a-col :xs="12" :md="6">
                <a-statistic title="仿冒占比" :value="statistics['仿冒域名占比'] || statistics['钓鱼域名占比'] || '0.00%'" />
              </a-col>
            </a-row>

            <div v-if="isTaskRunning" class="detecting-placeholder">
              <LoadingOutlined class="detecting-icon" spin />
              <div class="detecting-title">{{ taskStatusText }}</div>
              <a-progress
                class="detecting-progress"
                :percent="taskProgress"
                :show-info="taskProgress > 0"
              />
            </div>
            <a-alert
              v-else-if="lastError"
              class="result-error"
              type="error"
              show-icon
              :message="lastError"
            />

            <div class="inner-section">
              <div class="section-title">相关官方域名及子域名</div>
              <a-table
                :data-source="officialDomains"
                :columns="officialDomainColumns"
                :pagination="{ pageSize: 8, showSizeChanger: true }"
                row-key="官方域名"
                size="small"
                bordered
              />
            </div>

            <div class="inner-section">
              <div class="section-title">仿冒域名概要</div>
              <template v-if="phishingRows.length > 0">
                <div v-for="item in phishingRows.slice(0, 30)" :key="getImpersonationDomain(item)" class="result-item">
                  <div class="domain-line">{{ getImpersonationDomain(item) }}</div>
                  <div class="meta-line">
                    <a-tag color="red">仿冒域名</a-tag>
                    <a-tag :color="riskLevelColor(item.风险等级)">风险等级：{{ item.风险等级 || '未知' }}</a-tag>
                    <span>仿冒对象：{{ getTargetName(item) }}</span>
                  </div>
                  <div class="detail-line">
                    官方域名：{{ item.官方域名 || item.目标域名 || '未知' }}；匹配类型：{{ item.匹配类型 || '未知' }}
                  </div>
                  <div v-if="resultData?.attribution_enabled" class="detail-line">
                    归因组织：{{ item.归因组织 || 'unknown' }}；
                    归因级别：{{ item.归因级别 || '未归因' }}；
                    APT置信度：{{ item.APT置信度 ?? 0 }}
                  </div>
                </div>
              </template>
              <a-empty v-else description="暂无仿冒域名命中结果" />
            </div>
          </a-spin>
        </a-card>
      </a-col>
    </a-row>
  </page-container>
</template>

<style scoped>
:deep(.ant-pro-page-container-children-content) {
  background: #f5f7fb;
}

.focus-page {
  padding-bottom: 8px;
}

.panel-card {
  border: 1px solid rgba(220, 226, 235, 0.9);
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(15, 35, 80, 0.06);
}

.inner-section {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #e5e7eb;
}

.section-title {
  margin-bottom: 12px;
  color: #1f2937;
  font-weight: 700;
}

.card-title {
  color: #1f2937;
  font-size: 20px;
  font-weight: 700;
  line-height: 1.4;
}

.card-subtitle {
  margin-top: 6px;
  color: #667085;
  line-height: 1.65;
}

.task-form {
  margin-top: 18px;
}

.attribution-help {
  margin-top: 6px;
  color: #667085;
  font-size: 13px;
  line-height: 1.6;
}

.action-row,
.result-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.result-actions,
.detecting-status {
  display: flex;
  align-items: center;
  gap: 8px;
}

.detecting-status {
  color: #1677ff;
  white-space: nowrap;
}

.task-state {
  margin-top: 18px;
  padding: 12px;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  background: #f8fafc;
}

.state-line {
  color: #344054;
  line-height: 1.8;
}

.error-text {
  margin-top: 6px;
  color: #cf1322;
}

.stat-row {
  margin-top: 16px;
}

.detecting-placeholder {
  min-height: 180px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  color: #667085;
}

.detecting-icon {
  margin-bottom: 12px;
  color: #1677ff;
  font-size: 32px;
}

.detecting-title {
  color: #1f2937;
  font-size: 16px;
  font-weight: 600;
}

.detecting-progress {
  width: min(320px, 100%);
  margin-top: 16px;
}

.result-error {
  margin-top: 16px;
}

.result-item {
  padding: 12px 0;
  border-bottom: 1px solid #eaecf0;
}

.result-item:last-child {
  border-bottom: none;
}

.domain-line {
  color: #101828;
  font-size: 15px;
  font-weight: 700;
}

.meta-line,
.detail-line {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
  color: #475467;
  line-height: 1.7;
}

@media (max-width: 768px) {
  .action-row,
  .result-header {
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
