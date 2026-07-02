<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'AptTemplateNrdDetection',
})

const API_BASE = getApiBase()
const userId = useUserId()
const token = useAuthorization()

const modelList = ref<{ id: string | number, name: string }[]>([])
const selectedModel = ref<string | number | null>('')
const modelListLoading = ref(false)
const dataSource = ref<'upload' | 'newDomain' | 'manualInput'>('upload')
const uploadFile = ref<File | null>(null)
const submitLoading = ref(false)
const manualDomains = ref('')
const scoreThreshold = ref(90)

interface AptTemplateNrdResultItem {
  域名: string
  规范化域名?: string
  注册域名?: string
  score?: number
  risk_level?: string
  风险等级?: string
  匹配模板?: string
  命中原因?: string
  reason?: string
  预测标签?: number
  预测结果?: string
}

interface AptTemplateNrdStatistics {
  总域名数?: string | number
  模板化APT域名数?: string | number
  高风险域名数?: string | number
  正常域名数?: string | number
  模板化APT域名占比?: string
  高风险域名占比?: string
  预警阈值?: string | number
}

interface AptTemplateNrdResultData {
  task_id: string
  task_type: string
  status?: string
  message?: string
  statistics: AptTemplateNrdStatistics
  results: AptTemplateNrdResultItem[]
  apt_template_nrd_domains?: AptTemplateNrdResultItem[]
  result_filename: string
  total_count: number
  apt_template_nrd_count?: number
}

const manualResultTaskId = ref('')
const manualResultLoading = ref(false)
const manualResultStatusMessage = ref('')
const manualResultError = ref('')
const manualResultData = ref<AptTemplateNrdResultData | null>(null)
const manualResultPollAttempts = ref(0)
let manualResultPollTimer: number | null = null

const MIN_START_DATE = dayjs('2024-09-01')
const dateRange = ref<[string, string] | null>(null)
const pickedAnchorDate = ref<dayjs.Dayjs | null>(null)
const pickedAnchorType = ref<'start' | 'end' | null>(null)

const fileRules = {
  maxSize: 5 * 1024 * 1024,
  accept: '.csv,.txt,.xlsx',
}

const manualDomainItems = computed(() => {
  return manualDomains.value
    .split(/[\s,，;；]+/)
    .map(item => item.trim())
    .filter(Boolean)
})

const manualRiskDomains = computed(() => manualResultData.value?.apt_template_nrd_domains || [])

function displayAptScore(item: Partial<AptTemplateNrdResultItem>) {
  const score = Number(item.score)
  if (Number.isNaN(score))
    return '未知'
  return score.toFixed(4)
}

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

async function fetchAvailableModels() {
  modelListLoading.value = true
  try {
    const resp = await fetch(`${API_BASE}/models/available?category=apt_template_nrd`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || await resp.text())
    if (json.code === 0 && Array.isArray(json.data)) {
      modelList.value = json.data.map((item: any) => ({ id: item.id, name: item.name }))
      if (!selectedModel.value && modelList.value.length > 0)
        selectedModel.value = modelList.value[0].id
    }
    else {
      throw new Error(json?.message || '获取模型列表失败')
    }
  }
  catch (e: any) {
    message.error(`模型列表加载失败：${e?.message || '未知错误'}`)
    modelList.value = []
  }
  finally {
    modelListLoading.value = false
  }
}

onMounted(fetchAvailableModels)

function beforeUpload(file: File) {
  const fileExt = `.${file.name.split('.').pop()!.toLowerCase()}`
  const acceptedExts = fileRules.accept.split(',').map(ext => ext.trim().toLowerCase())
  const isValid = file.size <= fileRules.maxSize && acceptedExts.includes(fileExt)
  if (!isValid) {
    message.error('文件不符合要求，仅支持CSV/TXT/XLSX格式且不超过5MB')
    return false
  }
  return false
}

function handleUpload(info: any) {
  const file = info.file
  if (file.status === 'removed') {
    uploadFile.value = null
    return
  }
  const originalFile = file.originFileObj || file.raw || file
  uploadFile.value = originalFile instanceof File ? originalFile : null
  if (!uploadFile.value)
    message.error('无法读取上传文件，请重新选择')
}

function clearManualResultPoll() {
  if (manualResultPollTimer) {
    window.clearTimeout(manualResultPollTimer)
    manualResultPollTimer = null
  }
}

function resetManualResultState() {
  clearManualResultPoll()
  manualResultTaskId.value = ''
  manualResultLoading.value = false
  manualResultStatusMessage.value = ''
  manualResultError.value = ''
  manualResultData.value = null
  manualResultPollAttempts.value = 0
}

function scheduleManualResultPoll(taskId: string) {
  clearManualResultPoll()
  manualResultPollTimer = window.setTimeout(() => {
    fetchManualResult(taskId)
  }, 2000)
}

async function fetchManualResult(taskId: string) {
  if (!taskId)
    return
  if (manualResultTaskId.value && manualResultTaskId.value !== taskId)
    return
  manualResultLoading.value = true
  manualResultError.value = ''
  try {
    const resp = await fetch(`${API_BASE}/tasks/${taskId}/result`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || `HTTP ${resp.status}`)
    if (manualResultTaskId.value !== taskId)
      return

    if (json?.ok && json?.task_id) {
      clearManualResultPoll()
      manualResultData.value = json as AptTemplateNrdResultData
      manualResultStatusMessage.value = '检测完成'
      manualResultLoading.value = false
      return
    }

    if (json?.status === 'failed' || json?.status === 'completed') {
      clearManualResultPoll()
      manualResultStatusMessage.value = ''
      manualResultError.value = json?.message || json?.error || '任务结果不可用'
      manualResultLoading.value = false
      return
    }

    manualResultStatusMessage.value = json?.message || '任务正在执行中，请稍候'
    manualResultPollAttempts.value += 1
    if (manualResultPollAttempts.value >= 120) {
      clearManualResultPoll()
      manualResultError.value = '结果获取超时，请稍后到“我的任务”查看'
      manualResultLoading.value = false
      return
    }
    scheduleManualResultPoll(taskId)
  }
  catch (e: any) {
    clearManualResultPoll()
    manualResultError.value = e?.message || '获取结果失败'
    manualResultLoading.value = false
  }
}

async function downloadManualResult() {
  if (!manualResultTaskId.value)
    return message.warning('暂无可下载的结果')
  try {
    const resp = await fetch(`${API_BASE}/tasks/${manualResultTaskId.value}/download`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    if (!resp.ok)
      throw new Error(await resp.text())
    const blob = await resp.blob()
    const disposition = resp.headers.get('content-disposition') || ''
    const match = disposition.match(/filename\*=utf-8''(.+)/i)
    const filename = decodeURIComponent(match?.[1] || manualResultData.value?.result_filename || `${manualResultTaskId.value}.pdf`)
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
    message.success('结果开始下载')
  }
  catch (e: any) {
    message.error(`下载失败：${e?.message || '未知错误'}`)
  }
}

async function handleSubmit() {
  if (!selectedModel.value)
    return message.warning('请选择模板化APT域名检测模型')
  if (dataSource.value === 'upload' && !uploadFile.value)
    return message.warning('请上传待检测文件')
  if (dataSource.value === 'newDomain' && !dateRange.value)
    return message.warning('请选择日期范围')
  if (dataSource.value === 'manualInput' && manualDomainItems.value.length === 0)
    return message.warning('请输入待检测域名或URL')
  if (dataSource.value === 'newDomain' && dateRange.value) {
    const days = dayjs(dateRange.value[1]).startOf('day').diff(dayjs(dateRange.value[0]).startOf('day'), 'day')
    if (days > 30)
      return message.warning('日期范围最多为一个月')
  }

  submitLoading.value = true
  try {
    if (dataSource.value === 'manualInput')
      resetManualResultState()

    if (dataSource.value === 'newDomain' && dateRange.value) {
      const available = await ensureNewDomainDataAvailable(dateRange.value)
      if (!available)
        return
    }

    const fd = new FormData()
    fd.append('model', String(selectedModel.value))
    fd.append('dataSource', dataSource.value)
    fd.append('scoreThreshold', String(scoreThreshold.value))
    if (dataSource.value === 'upload' && uploadFile.value)
      fd.append('file', uploadFile.value, uploadFile.value.name)
    if (dataSource.value === 'newDomain' && dateRange.value)
      fd.append('dateRange', JSON.stringify(dateRange.value))
    if (dataSource.value === 'manualInput')
      fd.append('manualDomains', manualDomains.value)

    const resp = await fetch(`${API_BASE}/apt-template-nrd-tasks`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '提交失败')

    if (dataSource.value === 'manualInput') {
      manualResultTaskId.value = json.task_id || ''
      manualResultStatusMessage.value = '任务已提交，正在获取检测结果'
      message.success(`模板化APT域名检测任务已提交！task: ${json.task_id || ''}`)
      void fetchManualResult(manualResultTaskId.value)
    }
    else {
      message.success(`模板化APT域名检测任务已提交！task: ${json.task_id || ''}`)
      resetForm()
    }
  }
  catch (e: any) {
    message.error(`提交失败：${e?.message || '未知错误'}`)
  }
  finally {
    submitLoading.value = false
  }
}

function resetForm() {
  selectedModel.value = modelList.value[0]?.id || ''
  dataSource.value = 'upload'
  uploadFile.value = null
  dateRange.value = null
  manualDomains.value = ''
  scoreThreshold.value = 90
  resetManualResultState()
}

onBeforeUnmount(clearManualResultPoll)
</script>

<template>
  <div class="task-layout">
    <a-row :gutter="[24, 24]">
      <a-col :xs="24" :xl="16">
        <a-card class="form-card" :bordered="false">
          <div class="card-header">
            <div class="card-title">创建模板化APT域名检测任务</div>
            <div class="card-subtitle">
              基于模板化APT域名模板库匹配待检测域名，输出风险分、风险等级和命中原因。
            </div>
            <div class="header-tags">
              <span class="mini-tag">模板化APT域名</span>
              <span class="mini-tag">新注册域名</span>
              <span class="mini-tag">订阅预警</span>
            </div>
          </div>

          <a-form layout="vertical" class="task-form">
            <div class="form-section">
              <div class="section-title">步骤 1：选择检测模型</div>
              <a-form-item label="检测模型">
                <a-select
                  v-model:value="selectedModel"
                  placeholder="请选择模板化APT域名检测模型"
                  :options="modelList.map(m => ({ label: m.name, value: m.id }))"
                  :loading="modelListLoading"
                  allow-clear
                />
              </a-form-item>
            </div>

            <div class="form-section">
              <div class="section-title">步骤 2：选择数据来源</div>
              <a-form-item label="数据来源">
                <a-radio-group v-model:value="dataSource" button-style="solid">
                  <a-radio-button value="upload">上传文件</a-radio-button>
                  <a-radio-button value="newDomain">选择新注册域名</a-radio-button>
                  <a-radio-button value="manualInput">手动输入域名</a-radio-button>
                </a-radio-group>
              </a-form-item>

              <a-form-item v-if="dataSource === 'upload'" label="待检测数据文件">
                <a-upload-dragger
                  :before-upload="beforeUpload"
                  :show-upload-list="false"
                  :accept="fileRules.accept"
                  :custom-request="() => {}"
                  class="upload-card"
                  @change="handleUpload"
                >
                  <p class="ant-upload-drag-icon">
                    <i class="iconfont icon-upload-cloud upload-icon" />
                  </p>
                  <p class="upload-title">
                    {{ uploadFile ? uploadFile.name : '点击或拖拽上传待检测域名文件' }}
                  </p>
                  <p class="upload-subtitle">支持 CSV / TXT / XLSX，单文件不超过 5MB</p>
                </a-upload-dragger>
              </a-form-item>

              <a-form-item v-if="dataSource === 'newDomain'" label="新注册域名数据日期范围">
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

              <a-form-item v-if="dataSource === 'manualInput'" label="待检测域名或URL">
                <a-textarea
                  v-model:value="manualDomains"
                  class="manual-input"
                  :rows="8"
                  :maxlength="20000"
                  placeholder="每行输入一个域名或URL，例如：&#10;mofa-services-server.top&#10;https://login.example.org/path"
                  show-count
                />
                <div class="manual-input-meta">
                  当前输入 {{ manualDomainItems.length }} 项，提交后后端会自动提取域名、去重并过滤无效内容。
                </div>
              </a-form-item>
            </div>

            <div class="form-section">
              <div class="section-title">步骤 3：配置预警阈值</div>
              <a-form-item label="风险分阈值（0-100）">
                <div class="threshold-row">
                  <a-slider v-model:value="scoreThreshold" class="threshold-slider" :min="0" :max="100" />
                  <span class="threshold-value">{{ scoreThreshold }}</span>
                </div>
              </a-form-item>
            </div>

            <div class="action-footer">
              <a-button type="primary" :loading="submitLoading" class="submit-btn" @click="handleSubmit">
                提交任务
              </a-button>
              <a-button @click="resetForm">重置</a-button>
            </div>
          </a-form>
        </a-card>

        <a-card
          v-if="dataSource === 'manualInput' && (manualResultTaskId || manualResultData || manualResultError)"
          class="manual-result-card"
          :bordered="false"
        >
          <div class="result-header">
            <div>
              <div class="card-title">手动输入检测结果</div>
              <div class="card-subtitle">
                仅展示本次手动输入任务的在线结果，完整结果仍可在“我的任务”中查看。
              </div>
            </div>
            <a-button v-if="manualResultData" type="primary" @click="downloadManualResult">
              下载PDF报告
            </a-button>
          </div>

          <a-spin :spinning="manualResultLoading">
            <a-alert
              v-if="manualResultStatusMessage && !manualResultData && !manualResultError"
              class="result-alert"
              type="info"
              show-icon
              :message="manualResultStatusMessage"
            />
            <a-alert
              v-if="manualResultError"
              class="result-alert"
              type="error"
              show-icon
              :message="manualResultError"
            />

            <template v-if="manualResultData">
              <div class="result-stat-grid">
                <div class="result-stat-item">
                  <span>总域名数</span>
                  <strong>{{ manualResultData.statistics['总域名数'] || manualResultData.total_count || 0 }}</strong>
                </div>
                <div class="result-stat-item danger">
                  <span>模板化APT域名</span>
                  <strong>{{ manualResultData.statistics['模板化APT域名数'] || manualResultData.apt_template_nrd_count || 0 }}</strong>
                </div>
                <div class="result-stat-item danger">
                  <span>高风险域名</span>
                  <strong>{{ manualResultData.statistics['高风险域名数'] || manualResultData.apt_template_nrd_count || 0 }}</strong>
                </div>
                <div class="result-stat-item">
                  <span>高风险占比</span>
                  <strong>{{ manualResultData.statistics['高风险域名占比'] || '0%' }}</strong>
                </div>
              </div>

              <a-list
                v-if="manualRiskDomains.length"
                class="result-list"
                :data-source="manualRiskDomains"
                :pagination="{ pageSize: 10, showSizeChanger: true }"
                size="large"
                bordered
              >
                <template #renderItem="{ item }">
                  <a-list-item>
                    <a-list-item-meta>
                      <template #title>
                        <span class="risk-domain">{{ item.域名 }}</span>
                      </template>
                      <template #description>
                        <div class="risk-summary">
                          <a-tag color="red">模板化APT命中</a-tag>
                          <span class="summary-item">风险分: {{ displayAptScore(item) }}</span>
                          <span class="summary-item">风险等级: {{ item.风险等级 || item.risk_level || '未知' }}</span>
                          <span class="summary-item">匹配模板: {{ item.匹配模板 || '未知' }}</span>
                          <div v-if="item.命中原因 || item.reason" class="risk-reason">
                            命中原因: {{ item.命中原因 || item.reason }}
                          </div>
                        </div>
                      </template>
                    </a-list-item-meta>
                  </a-list-item>
                </template>
              </a-list>
              <a-empty v-else description="本次手动输入未命中模板化APT域名" />
            </template>
          </a-spin>
        </a-card>
      </a-col>

      <a-col :xs="24" :xl="8">
        <a-card title="处理流程" class="guide-card" :bordered="false">
          <ul class="guide-list">
            <li><span class="dot">1</span><span>加载模板化APT域名模板库并编译模板匹配规则。</span></li>
            <li><span class="dot">2</span><span>对待检测域名逐条匹配模板，生成风险分、风险等级和命中原因。</span></li>
            <li><span class="dot">3</span><span>风险分达到阈值的域名进入结果文件和订阅预警流程。</span></li>
          </ul>
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<style scoped>
.task-layout {
  padding: 8px;
}

.form-card,
.manual-result-card,
.guide-card {
  border-radius: 8px;
}

.manual-result-card {
  margin-top: 16px;
}

.card-header {
  margin-bottom: 24px;
}

.card-title {
  font-size: 20px;
  font-weight: 600;
  color: #1f2937;
}

.card-subtitle {
  margin-top: 8px;
  color: #667085;
}

.header-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 12px;
}

.mini-tag {
  padding: 2px 8px;
  font-size: 12px;
  color: #0958d9;
  background: #e6f4ff;
  border: 1px solid #91caff;
  border-radius: 4px;
}

.form-section {
  padding: 16px 0;
  border-top: 1px solid #eef0f3;
}

.section-title {
  margin-bottom: 12px;
  font-weight: 600;
  color: #344054;
}

.upload-card {
  background: #fbfdff;
}

.upload-icon {
  font-size: 36px;
  color: #1677ff;
}

.upload-title {
  margin-bottom: 4px;
  font-weight: 600;
}

.upload-subtitle,
.manual-input-meta {
  color: #667085;
}

.manual-input {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}

.threshold-row {
  display: flex;
  align-items: center;
  gap: 16px;
}

.threshold-slider {
  flex: 1;
}

.threshold-value {
  min-width: 44px;
  padding: 2px 8px;
  color: #0958d9;
  text-align: center;
  background: #e6f4ff;
  border-radius: 4px;
}

.action-footer {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  padding-top: 20px;
  border-top: 1px solid #eef0f3;
}

.submit-btn {
  min-width: 120px;
}

.result-header {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 20px;
}

.result-alert {
  margin-bottom: 16px;
}

.result-stat-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.result-stat-item {
  min-height: 74px;
  padding: 12px;
  background: #f8fafc;
  border: 1px solid #eaecf0;
  border-radius: 8px;
}

.result-stat-item span {
  display: block;
  margin-bottom: 6px;
  color: #667085;
}

.result-stat-item strong {
  color: #101828;
  font-size: 24px;
  line-height: 1.2;
}

.result-stat-item.danger strong {
  color: #cf1322;
}

.result-list {
  margin-top: 8px;
}

.risk-domain {
  color: #cf1322;
  font-weight: 600;
}

.risk-summary {
  color: #475467;
}

.summary-item {
  margin-left: 8px;
}

.risk-reason {
  margin-top: 4px;
  color: #667085;
}

.guide-list {
  padding: 0;
  margin: 0;
  list-style: none;
}

.guide-list li {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  margin-bottom: 14px;
  color: #475467;
}

.dot {
  display: inline-flex;
  flex: 0 0 22px;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  color: #0958d9;
  background: #e6f4ff;
  border-radius: 50%;
}

@media (max-width: 768px) {
  .result-header {
    flex-direction: column;
  }

  .result-stat-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 520px) {
  .result-stat-grid {
    grid-template-columns: 1fr;
  }

  .summary-item {
    display: block;
    margin: 6px 0 0;
  }
}
</style>
