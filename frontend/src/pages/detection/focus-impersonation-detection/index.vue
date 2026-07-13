<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, onBeforeUnmount, ref } from 'vue'
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
  来源?: string
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
}

interface FocusResultData {
  ok?: boolean
  task_id?: string
  task_type?: string
  status?: string
  message?: string
  focus_impersonation_detection?: boolean
  focus_query_name?: string
  statistics?: Record<string, string | number>
  official_domains?: OfficialDomainItem[]
  phishing_domains?: PhishingResultItem[]
  total_count?: number
  phishing_count?: number
  focus_report_filename?: string
}

const API_BASE = getApiBase()
const userId = useUserId()
const token = useAuthorization()

const queryName = ref('')
const dateRange = ref<[string, string] | null>(null)
const submitLoading = ref(false)
const resultLoading = ref(false)
const currentTaskId = ref('')
const taskStatus = ref('')
const officialDomains = ref<OfficialDomainItem[]>([])
const resultData = ref<FocusResultData | null>(null)
const lastError = ref('')

const MIN_START_DATE = dayjs('2024-09-01')
const pickedAnchorDate = ref<dayjs.Dayjs | null>(null)
const pickedAnchorType = ref<'start' | 'end' | null>(null)
let pollingTimer: number | null = null

const phishingRows = computed(() => resultData.value?.phishing_domains || [])
const statistics = computed(() => resultData.value?.statistics || {})
const hasCompleted = computed(() => taskStatus.value === 'completed' || !!resultData.value?.ok)

const officialDomainColumns = [
  { title: '单位/对象', dataIndex: '单位名称', key: 'name', width: '24%', ellipsis: true },
  { title: '官方域名或子域名', dataIndex: '官方域名', key: 'domain', width: '28%', ellipsis: true },
  { title: '置信度', dataIndex: '置信度', key: 'confidence', width: '12%', align: 'center' as const },
  { title: '来源', dataIndex: '来源', key: 'source', width: '12%', align: 'center' as const },
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
    window.clearInterval(pollingTimer)
    pollingTimer = null
  }
}

function startPolling(taskId: string) {
  stopPolling()
  fetchResult(taskId)
  pollingTimer = window.setInterval(() => fetchResult(taskId, true), 3000)
}

async function submitTask() {
  const query = queryName.value.trim()
  if (!query)
    return message.warning('请输入单位名或热点事件名')
  if (!dateRange.value)
    return message.warning('请选择新注册域名日期范围')
  const days = dayjs(dateRange.value[1]).startOf('day').diff(dayjs(dateRange.value[0]).startOf('day'), 'day')
  if (days > 30)
    return message.warning('日期范围最多为一个月')

  submitLoading.value = true
  resultData.value = null
  officialDomains.value = []
  currentTaskId.value = ''
  taskStatus.value = ''
  lastError.value = ''
  try {
    const available = await ensureNewDomainDataAvailable(dateRange.value)
    if (!available)
      return

    const fd = new FormData()
    fd.append('queryName', query)
    fd.append('detectionDateRange', JSON.stringify(dateRange.value))
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
    currentTaskId.value = json.task_id
    officialDomains.value = json.officialDomains || []
    taskStatus.value = 'pending'
    message.success('重点单位仿冒检测任务已提交')
    startPolling(json.task_id)
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
  if (!taskId)
    return
  if (!silent)
    resultLoading.value = true
  try {
    const resp = await fetch(`${API_BASE}/tasks/${taskId}/result`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '获取任务结果失败')
    taskStatus.value = json?.status || (json?.ok ? 'completed' : taskStatus.value)
    if (json?.ok && json?.statistics) {
      resultData.value = json
      officialDomains.value = json.official_domains || officialDomains.value
      taskStatus.value = 'completed'
      stopPolling()
    }
    else if (json?.status === 'failed') {
      lastError.value = json?.message || '任务执行失败'
      stopPolling()
    }
  }
  catch (e: any) {
    lastError.value = e?.message || '未知错误'
    if (!silent)
      message.error(`获取结果失败：${lastError.value}`)
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

onBeforeUnmount(stopPolling)
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
                :loading="submitLoading"
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
            <div class="action-row">
              <a-button type="primary" :loading="submitLoading" @click="submitTask">
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
                {{ hasCompleted ? '已完成' : taskStatus || '待执行' }}
              </a-tag>
            </div>
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
            <a-button type="primary" :disabled="!hasCompleted" @click="downloadReport">
              下载PDF报告
            </a-button>
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

.action-row,
.result-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
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
