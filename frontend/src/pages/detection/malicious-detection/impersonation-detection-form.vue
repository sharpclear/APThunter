<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, onMounted, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'ImpersonationDetectionForm',
})

type DataSource = 'manualInput' | 'upload' | 'newDomain'

interface ModelOption {
  id: string | number
  name: string
}

const API_BASE = getApiBase()
const userId = useUserId()
const token = useAuthorization()

const modelList = ref<ModelOption[]>([])
const selectedModel = ref<string | number | null>('')
const modelListLoading = ref(false)
const dataSource = ref<DataSource>('manualInput')
const submitLoading = ref(false)
const manualDomains = ref('')
const uploadFile = ref<File | null>(null)
const previewResult = ref<any | null>(null)

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

const currentModel = computed(() => {
  return modelList.value.find(item => String(item.id) === String(selectedModel.value)) || null
})

const previewMainCount = computed(() => {
  const data = previewResult.value
  if (!data)
    return 0
  return data.phishing_count || data.phishing_domains?.length || 0
})

const impersonationGroups = computed(() => {
  const rows = previewResult.value?.phishing_domains || []
  const grouped = new Map<string, any[]>()
  rows.forEach((item: any) => {
    const label = unitGroupLabel(item)
    if (!grouped.has(label))
      grouped.set(label, [])
    grouped.get(label)!.push(item)
  })
  return Array.from(grouped.entries()).map(([label, items]) => ({ label, items }))
})

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers.Authorization = `Bearer ${token.value}`
  return headers
}

function normalizeText(value: any, fallback = '未知') {
  const text = String(value ?? '').trim()
  return text || fallback
}

const MATCH_TYPE_LABELS: Record<string, string> = {
  typo: '拼写变体',
  confusable: '视觉混淆',
  brand_combo: '品牌组合',
  prefix_suffix: '前后缀诱导',
  pinyin_abbr: '拼音缩写',
  service_entry: '服务入口仿冒',
  hyphenation: '连字符变体',
  tld_replace: '顶级域替换',
}

const RISK_LEVEL_LABELS: Record<string, string> = {
  high: '高',
  medium: '中',
  low: '低',
}

function translateMultiValue(value: any, labels: Record<string, string>) {
  const text = String(value ?? '').trim()
  if (!text)
    return '未知'
  const parts = text.split(/[|\\/,，、]+/).map(item => item.trim()).filter(Boolean)
  return Array.from(new Set(parts.map(item => labels[item] || labels[item.toLowerCase()] || item))).join('\\')
}

function riskLevel(value: any) {
  const text = String(value ?? '').trim()
  return RISK_LEVEL_LABELS[text] || RISK_LEVEL_LABELS[text.toLowerCase()] || text || '未知'
}

function getImpersonationDomain(item: any) {
  return normalizeText(item.impersonation_domain || item.phishing_domain || item.仿冒域名 || item.钓鱼域名, '未知仿冒域名')
}

function getOfficialDomain(item: any) {
  return normalizeText(item.official_domain || item.官方域名 || item.目标域名, '未知官方域名')
}

function getOfficialUnitName(item: any) {
  return normalizeText(item.official_unit_name || item.官方域名单位名称 || item.官方单位名称 || item.公司名称, '未知单位')
}

function unitGroupLabel(item: any) {
  const rawType = normalizeText(item.official_unit_type || item.单位类型 || item.target_type, '未知')
  const subtype = normalizeText(item.official_unit_subtype || item.matched_target_subtype || item.target_subtype, '')
  if (['政府', '金融', '教育'].includes(rawType))
    return rawType
  if (rawType === '品牌' && subtype && !['未知', '其他'].includes(subtype))
    return `品牌-${subtype}`
  return rawType
}

function chineseOrdinal(index: number) {
  const numerals = ['零', '一', '二', '三', '四', '五', '六', '七', '八', '九', '十']
  if (index <= 10)
    return numerals[index]
  return String(index)
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
    const resp = await fetch(`${API_BASE}/models/available?category=impersonation`, {
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

function validateModel() {
  if (!selectedModel.value) {
    message.warning('请选择仿冒域名检测模型')
    return false
  }
  return true
}

async function handleManualPreview() {
  if (!validateModel())
    return
  if (manualDomainItems.value.length === 0)
    return message.warning('请输入待检测域名或URL')

  submitLoading.value = true
  previewResult.value = null
  try {
    const fd = new FormData()
    fd.append('model', String(selectedModel.value))
    fd.append('modelCategory', 'impersonation')
    fd.append('manualDomains', manualDomains.value)
    const resp = await fetch(`${API_BASE}/manual-domain-detection/preview`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '检测失败')
    previewResult.value = json
    dataSource.value = 'manualInput'
    message.success('手动输入域名检测完成')
  }
  catch (e: any) {
    message.error(`检测失败：${e?.message || '未知错误'}`)
  }
  finally {
    submitLoading.value = false
  }
}

async function handleAsyncSubmit() {
  if (!validateModel())
    return
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
    fd.append('model', String(selectedModel.value))
    fd.append('dataSource', dataSource.value)
    if (dataSource.value === 'upload' && uploadFile.value)
      fd.append('file', uploadFile.value, uploadFile.value.name)
    if (dataSource.value === 'newDomain' && dateRange.value)
      fd.append('dateRange', JSON.stringify(dateRange.value))

    const resp = await fetch(`${API_BASE}/impersonation-unified-tasks`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '提交失败')

    message.success(`仿冒域名检测任务已提交，可在“我的任务”查看结果。task: ${json.task_id || ''}`)
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

function resetForm(clearModel = true) {
  if (clearModel)
    selectedModel.value = modelList.value[0]?.id || ''
  dataSource.value = 'manualInput'
  uploadFile.value = null
  dateRange.value = null
  manualDomains.value = ''
  previewResult.value = null
}
</script>

<template>
  <div class="task-layout">
    <a-row :gutter="[24, 24]">
      <a-col :xs="24" :xl="16">
        <a-card v-if="!previewResult" class="form-card" :bordered="false">
          <div class="card-header">
            <div class="card-title">创建仿冒域名检测任务</div>
            <div class="card-subtitle">
              默认使用系统全量官方白名单，支持少量域名直接预览，也支持上传文件或选择新注册域名创建异步任务。
            </div>
            <div class="header-tags">
              <span class="mini-tag">全量白名单</span>
              <span class="mini-tag">手动预览</span>
              <span class="mini-tag">Word报告</span>
            </div>
          </div>

          <a-form layout="vertical" class="task-form">
            <div class="form-section">
              <div class="section-title">步骤 1：选择检测模型</div>
              <a-form-item label="检测模型">
                <a-select
                  v-model:value="selectedModel"
                  placeholder="请选择仿冒域名检测模型"
                  :options="modelList.map(item => ({ label: item.name, value: item.id }))"
                  :loading="modelListLoading"
                  allow-clear
                />
                <div class="form-tip">
                  当前模型：{{ currentModel?.name || '未选择' }}
                </div>
              </a-form-item>
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
                <a-button :type="dataSource === 'upload' ? 'primary' : 'default'" @click="setDataSource('upload')">
                  上传文件
                </a-button>
                <a-button :type="dataSource === 'newDomain' ? 'primary' : 'default'" @click="setDataSource('newDomain')">
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
              <a-button @click="resetForm()">重置</a-button>
            </div>
          </a-form>
        </a-card>

        <a-card v-else class="result-card" :bordered="false">
          <div class="result-header">
            <div>
              <div class="card-title">仿冒域名检测结果预览</div>
              <div class="card-subtitle">
                手动输入域名检测结果，仅展示核心命中信息；上传文件和新注册域名任务请到“我的任务”查看完整结果。
              </div>
            </div>
            <a-button @click="previewResult = null">返回创建任务</a-button>
          </div>

          <div class="result-table">
            <div class="result-row result-title-row">
              <div class="result-cell label">检测类型</div>
              <div class="result-cell">仿冒域名检测</div>
            </div>
            <div class="result-row">
              <div class="result-cell label">检测模型</div>
              <div class="result-cell">{{ previewResult.model?.name || currentModel?.name || '-' }}</div>
            </div>
            <div class="result-row">
              <div class="result-cell label">输入域名数</div>
              <div class="result-cell">{{ previewResult.manual_domain_stats?.valid_count || manualDomainItems.length }}</div>
            </div>
            <div class="result-row">
              <div class="result-cell label">命中数量</div>
              <div class="result-cell">
                <a-tag :color="previewMainCount > 0 ? 'red' : 'green'">{{ previewMainCount }}</a-tag>
              </div>
            </div>
          </div>

          <div class="report-block">
            <div class="report-line">检测类型：仿冒域名检测</div>
            <div class="report-line">仿冒域名数量：{{ previewMainCount }}</div>
            <template v-if="previewMainCount > 0">
              <div v-for="(group, groupIndex) in impersonationGroups" :key="group.label" class="report-group">
                <div class="report-group-title">{{ chineseOrdinal(groupIndex + 1) }}、单位类型：{{ group.label }}</div>
                <div v-for="(item, itemIndex) in group.items.slice(0, 20)" :key="`${group.label}-${itemIndex}`" class="report-item">
                  <div>{{ itemIndex + 1 }}. 仿冒域名：{{ getImpersonationDomain(item) }}</div>
                  <div>官方域名：{{ getOfficialDomain(item) }}</div>
                  <div>官方单位名称：{{ getOfficialUnitName(item) }}</div>
                  <div>匹配类型：{{ translateMultiValue(item.match_type || item.匹配类型, MATCH_TYPE_LABELS) }}</div>
                  <div>风险等级：{{ riskLevel(item.risk_level || item.风险等级) }}</div>
                </div>
              </div>
            </template>
            <a-empty v-else description="未发现中高风险仿冒域名" />
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :xl="8">
        <div class="side-panel">
          <a-card title="填写说明" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>手动输入会立即返回预览结果，适合少量域名快速核查。</span></li>
              <li><span class="dot">2</span><span>上传文件和新注册域名会创建任务，结果在“我的任务”中展示。</span></li>
              <li><span class="dot">3</span><span>异步任务完成后可下载仿冒检测 Word 报告。</span></li>
            </ul>
          </a-card>
          <a-card title="默认策略" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>仿冒域名检测默认加载系统全量官方白名单。</span></li>
              <li><span class="dot">2</span><span>日期范围最多 30 天，避免任务过大。</span></li>
              <li><span class="dot">3</span><span>输出会按单位类型、匹配类型和风险等级组织结果。</span></li>
            </ul>
          </a-card>
        </div>
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
  max-width: 1160px;
  margin: 0 auto;
}

.form-card,
.result-card {
  border-radius: 16px;
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
.form-tip,
.manual-input-meta {
  margin-top: 6px;
  color: #667085;
  line-height: 1.65;
}

.header-tags {
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
  border: 1px solid #d8d9ff;
  color: #4f46e5;
  background: #eef2ff;
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

.source-toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
}

.manual-search {
  flex: 1;
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

:deep(.upload-card.ant-upload-wrapper .ant-upload-drag:hover) {
  border-color: #6366f1;
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
  gap: 12px;
}

.submit-btn {
  min-width: 160px;
}

.side-panel {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.guide-card {
  border-radius: 12px;
  border: 1px solid rgba(220, 226, 235, 0.9);
  box-shadow: 0 8px 24px rgba(15, 35, 80, 0.06);
}

.guide-list {
  list-style: none;
  margin: 0;
  padding: 0;
  color: #667085;
  line-height: 1.8;
}

.guide-list li {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-bottom: 8px;
}

.dot {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #eef2ff;
  color: #4f46e5;
  font-size: 12px;
  font-weight: 600;
  line-height: 18px;
  text-align: center;
  flex-shrink: 0;
  margin-top: 4px;
}

.result-table {
  border: 1px solid #d9dfe7;
  border-bottom: none;
  margin-bottom: 18px;
}

.result-row {
  display: grid;
  grid-template-columns: 220px 1fr;
  border-bottom: 1px solid #d9dfe7;
}

.result-title-row {
  background: #eef2ff;
}

.result-cell {
  padding: 10px 12px;
  min-height: 42px;
}

.result-cell.label {
  font-weight: 700;
  background: rgba(0, 0, 0, 0.03);
  border-right: 1px solid #d9dfe7;
}

.report-block {
  border-radius: 12px;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
  padding: 16px;
  white-space: pre-wrap;
}

.report-line {
  font-weight: 600;
  margin-bottom: 8px;
}

.report-group {
  margin-top: 14px;
}

.report-group-title {
  font-weight: 700;
  color: #1f2937;
  margin-bottom: 8px;
}

.report-item {
  padding: 10px 12px;
  border-radius: 10px;
  background: #fff;
  border: 1px solid #e5e7eb;
  margin-bottom: 10px;
  color: #344054;
  line-height: 1.7;
}

@media (max-width: 768px) {
  .source-toolbar,
  .result-header {
    flex-direction: column;
    align-items: stretch;
  }

  .result-row {
    grid-template-columns: 1fr;
  }

  .result-cell.label {
    border-right: none;
    border-bottom: 1px solid #d9dfe7;
  }
}
</style>
