<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'UnifiedMaliciousDomainDetectionForm',
})

type DataSource = 'manualInput' | 'upload' | 'newDomain'

interface UnifiedResultItem {
  域名: string
  判定结果: '恶意' | '正常' | string
  恶意类别?: string
  恶意类别标签?: string[]
  命中模块数?: number
  命中详情?: string
}

interface UnifiedPreviewResult {
  task_id: string
  task_type: string
  statistics: Record<string, string | number>
  malicious_count?: number
  normal_count?: number
  total_count?: number
  unified_malicious_domains?: UnifiedResultItem[]
  malicious_domains?: UnifiedResultItem[]
  normal_domains?: UnifiedResultItem[]
  label_counts?: Record<string, number>
  model_names?: Record<string, string>
  manual_domain_stats?: {
    valid_count?: number
    invalid_count?: number
    duplicate_count?: number
  }
}

const API_BASE = getApiBase()
const userId = useUserId()
const token = useAuthorization()

const dataSource = ref<DataSource>('manualInput')
const submitLoading = ref(false)
const manualDomains = ref('')
const uploadFile = ref<File | null>(null)
const previewResult = ref<UnifiedPreviewResult | null>(null)

const MIN_START_DATE = dayjs('2024-09-01')
const dateRange = ref<[string, string] | null>(null)
const pickedAnchorDate = ref<dayjs.Dayjs | null>(null)
const pickedAnchorType = ref<'start' | 'end' | null>(null)

const fileRules = {
  maxSize: 5 * 1024 * 1024,
  accept: '.csv,.txt,.xlsx',
}

const moduleNames = [
  '仿冒域名检测',
  'DGA域名检测',
  '历史APT域名相似性检测',
  '模板化APT域名检测',
]

const manualDomainItems = computed(() => {
  return manualDomains.value
    .split(/[\s,，;；]+/)
    .map(item => item.trim())
    .filter(Boolean)
})

const maliciousRows = computed(() => {
  return previewResult.value?.unified_malicious_domains
    || previewResult.value?.malicious_domains
    || []
})

const labelCountEntries = computed(() => {
  const counts = previewResult.value?.label_counts || {}
  return Object.entries(counts).filter(([, count]) => Number(count) > 0)
})

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

function setDataSource(source: DataSource) {
  dataSource.value = source
  previewResult.value = null
}

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

async function handleManualPreview() {
  if (manualDomainItems.value.length === 0)
    return message.warning('请输入待检测域名或URL')

  submitLoading.value = true
  previewResult.value = null
  try {
    const fd = new FormData()
    fd.append('manualDomains', manualDomains.value)
    const resp = await fetch(`${API_BASE}/unified-malicious-domain-detection/preview`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '检测失败')
    previewResult.value = json
    dataSource.value = 'manualInput'
    message.success('恶意域名检测完成')
  }
  catch (e: any) {
    message.error(`检测失败：${e?.message || '未知错误'}`)
  }
  finally {
    submitLoading.value = false
  }
}

async function handleAsyncSubmit() {
  if (dataSource.value === 'manualInput' && manualDomainItems.value.length === 0)
    return message.warning('请输入待检测域名或URL')
  if (dataSource.value === 'upload' && !uploadFile.value)
    return message.warning('请上传待检测文件')
  if (dataSource.value === 'newDomain' && !dateRange.value)
    return message.warning('请选择日期范围')
  if (dataSource.value === 'newDomain' && dateRange.value) {
    const days = dayjs(dateRange.value[1]).startOf('day').diff(dayjs(dateRange.value[0]).startOf('day'), 'day')
    if (days > 30)
      return message.warning('日期范围最多为一个月')
  }

  submitLoading.value = true
  try {
    if (dataSource.value === 'newDomain' && dateRange.value) {
      const available = await ensureNewDomainDataAvailable(dateRange.value)
      if (!available)
        return
    }

    const fd = new FormData()
    fd.append('dataSource', dataSource.value)
    if (dataSource.value === 'upload' && uploadFile.value)
      fd.append('file', uploadFile.value, uploadFile.value.name)
    if (dataSource.value === 'newDomain' && dateRange.value)
      fd.append('dateRange', JSON.stringify(dateRange.value))
    if (dataSource.value === 'manualInput')
      fd.append('manualDomains', manualDomains.value)

    const resp = await fetch(`${API_BASE}/unified-malicious-domain-tasks`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '提交失败')

    message.success(`恶意域名检测任务已提交，可在“我的任务”查看结果。task: ${json.task_id || ''}`)
    resetForm(false)
  }
  catch (e: any) {
    message.error(`提交失败：${e?.message || '未知错误'}`)
  }
  finally {
    submitLoading.value = false
  }
}

function handleSubmit() {
  if (dataSource.value === 'manualInput')
    return handleManualPreview()
  return handleAsyncSubmit()
}

function resetForm(clearPreview = true) {
  dataSource.value = 'manualInput'
  uploadFile.value = null
  dateRange.value = null
  manualDomains.value = ''
  if (clearPreview)
    previewResult.value = null
}
</script>

<template>
  <div class="task-layout">
    <a-row :gutter="[16, 16]" class="task-row">
      <a-col :xs="24" :xl="9">
        <a-card class="form-card" :bordered="false">
          <div class="card-header">
            <div class="card-title">创建恶意域名检测任务</div>
            <div class="card-subtitle">
              对同一批域名依次执行仿冒、DGA、历史APT相似和模板化APT四个检测模块，并汇总多标签结果。
            </div>
            <div class="header-tags">
              <span v-for="name in moduleNames" :key="name" class="mini-tag">{{ name }}</span>
            </div>
          </div>

          <a-form layout="vertical" class="task-form">
            <div class="form-section">
              <div class="section-title">步骤 1：确认检测模块</div>
              <div class="module-grid">
                <div v-for="name in moduleNames" :key="name" class="module-item">
                  {{ name }}
                </div>
              </div>
            </div>

            <div class="form-section">
              <div class="section-title">步骤 2：选择数据来源</div>
              <div class="source-toolbar">
                <a-input-search
                  v-model:value="manualDomains"
                  class="manual-search"
                  placeholder="手动输入域名，多个域名可用空格、逗号或换行分隔"
                  enter-button="直接检测"
                  :loading="submitLoading && dataSource === 'manualInput'"
                  @focus="setDataSource('manualInput')"
                  @search="handleManualPreview"
                />
                <a-button class="source-action-btn" :type="dataSource === 'upload' ? 'primary' : 'default'" @click="setDataSource('upload')">
                  上传文件
                </a-button>
                <a-button class="source-action-btn" :type="dataSource === 'newDomain' ? 'primary' : 'default'" @click="setDataSource('newDomain')">
                  选择新注册域名
                </a-button>
              </div>
              <div v-if="dataSource === 'manualInput'" class="manual-input-meta">
                当前输入 {{ manualDomainItems.length }} 项
              </div>

              <a-form-item v-if="dataSource === 'upload'" label="待检测数据文件" class="source-panel">
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

              <a-form-item v-if="dataSource === 'newDomain'" label="新注册域名数据日期范围" class="source-panel">
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
            </div>

            <div class="action-footer">
              <a-button type="primary" :loading="submitLoading" class="submit-btn" @click="handleSubmit">
                {{ dataSource === 'manualInput' ? '直接检测并查看结果' : '提交任务' }}
              </a-button>
              <a-button
                v-if="dataSource === 'manualInput'"
                :loading="submitLoading"
                @click="handleAsyncSubmit"
              >
                提交为任务
              </a-button>
              <a-button @click="resetForm()">重置</a-button>
            </div>
          </a-form>
        </a-card>
      </a-col>

      <a-col :xs="24" :xl="15">
        <a-card class="result-card" :bordered="false">
          <div class="result-header">
            <div>
              <div class="card-title">检测结果概要</div>
              <div class="card-subtitle">
                手动输入域名检测结果，仅展示统一判定和多标签命中信息。
              </div>
            </div>
            <a-button v-if="previewResult" @click="previewResult = null">清空结果</a-button>
          </div>

          <a-row :gutter="[12, 12]" class="stat-row">
            <a-col :xs="12" :md="6">
              <a-statistic title="总域名数" :value="previewResult?.statistics?.['总域名数'] || previewResult?.total_count || 0" />
            </a-col>
            <a-col :xs="12" :md="6">
              <a-statistic title="恶意域名" :value="previewResult?.statistics?.['恶意域名数'] || previewResult?.malicious_count || 0" :value-style="{ color: '#cf1322' }" />
            </a-col>
            <a-col :xs="12" :md="6">
              <a-statistic title="正常域名" :value="previewResult?.statistics?.['正常域名数'] || previewResult?.normal_count || 0" :value-style="{ color: '#3f8600' }" />
            </a-col>
            <a-col :xs="12" :md="6">
              <a-statistic title="恶意占比" :value="previewResult?.statistics?.['恶意域名占比'] || '0.00%'" />
            </a-col>
          </a-row>

          <div v-if="labelCountEntries.length" class="label-summary">
            <a-tag v-for="[label, count] in labelCountEntries" :key="label" color="red">
              {{ label }}：{{ count }}
            </a-tag>
          </div>

          <div class="report-block">
            <template v-if="previewResult && maliciousRows.length > 0">
              <div v-for="(item, index) in maliciousRows.slice(0, 50)" :key="item.域名" class="report-item">
                <div class="domain-line">{{ index + 1 }}. {{ item.域名 }}</div>
                <div class="tag-line">
                  <a-tag v-for="label in item.恶意类别标签 || []" :key="label" color="red">
                    {{ label }}
                  </a-tag>
                </div>
                <div class="detail-line">{{ item.命中详情 || '命中详情待查看完整报告' }}</div>
              </div>
            </template>
            <a-empty v-else-if="previewResult" description="未发现被四个模块判定为恶意的域名" />
            <a-empty v-else description="手动输入域名并直接检测后展示结果概要" />
          </div>
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<style scoped>
.iconfont.icon-upload-cloud::before {
  content: '\e68c';
  font-family: 'iconfont';
}

.task-layout {
  width: 100%;
}

.task-row {
  margin-right: 0 !important;
  margin-left: 0 !important;
}

.form-card,
.result-card {
  border-radius: 12px;
  border: 1px solid rgba(220, 226, 235, 0.9);
  box-shadow: 0 8px 24px rgba(15, 35, 80, 0.06);
  min-height: 620px;
}

.card-header,
.result-header {
  margin-bottom: 16px;
}

.result-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
}

.card-title {
  font-size: 20px;
  line-height: 1.4;
  font-weight: 700;
  color: #1f2937;
}

.card-subtitle,
.manual-input-meta {
  margin-top: 6px;
  color: #667085;
  line-height: 1.65;
}

.header-tags,
.label-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

.mini-tag {
  display: inline-flex;
  align-items: center;
  padding: 2px 10px;
  border-radius: 999px;
  border: 1px solid #dbeafe;
  color: #2563eb;
  background: #eff6ff;
  font-size: 12px;
}

.task-form {
  display: flex;
  flex-direction: column;
}

.form-section {
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  padding: 14px 14px 4px;
  margin-bottom: 14px;
  background: #fff;
}

.section-title {
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 10px;
}

.module-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 10px;
}

.module-item {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 10px 12px;
  background: #f8fafc;
  color: #344054;
}

.source-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: stretch;
}

.manual-search {
  flex: 1 1 100%;
  min-width: 0;
}

.source-action-btn {
  flex: 1 1 0;
  min-width: 120px;
}

.source-panel {
  margin-top: 14px;
}

.upload-card {
  border-radius: 12px;
}

:deep(.upload-card.ant-upload-wrapper .ant-upload-drag) {
  min-height: 152px;
  border-color: #d7e6ff;
  background: #f8fbff;
}

.upload-icon {
  font-size: 30px;
  color: #7a89d9;
}

.upload-title {
  color: #1f2937;
  font-weight: 600;
  margin-bottom: 4px;
}

.upload-subtitle {
  color: #667085;
  margin-bottom: 0;
}

.action-footer {
  border-top: 1px solid #e5e7eb;
  padding-top: 16px;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.submit-btn {
  min-width: 160px;
}

.stat-row {
  margin-bottom: 16px;
}

.report-block {
  border-radius: 12px;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
  padding: 16px;
  margin-top: 16px;
}

.report-item {
  padding: 12px 0;
  border-bottom: 1px solid #e5e7eb;
}

.report-item:last-child {
  border-bottom: none;
}

.domain-line {
  font-weight: 700;
  color: #1f2937;
}

.tag-line {
  margin-top: 8px;
}

.detail-line {
  margin-top: 6px;
  color: #667085;
  line-height: 1.7;
}

@media (max-width: 768px) {
  .source-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .module-grid {
    grid-template-columns: 1fr;
  }
}
</style>
