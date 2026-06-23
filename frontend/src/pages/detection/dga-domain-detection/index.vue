<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { computed, onMounted, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'DgaDomainDetection',
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
    const resp = await fetch(`${API_BASE}/models/available?category=dga`, {
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

async function handleSubmit() {
  if (!selectedModel.value)
    return message.warning('请选择DGA检测模型')
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
    if (dataSource.value === 'manualInput')
      fd.append('manualDomains', manualDomains.value)

    const resp = await fetch(`${API_BASE}/dga-tasks`, {
      method: 'POST',
      body: fd,
      headers: buildHeaders(),
    })
    const json = await resp.json().catch(() => null)
    if (!resp.ok)
      throw new Error(json?.detail || json?.message || '提交失败')

    message.success(`DGA检测任务已提交！task: ${json.task_id || ''}`)
    resetForm()
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
}
</script>

<template>
  <div class="task-layout">
    <a-row :gutter="[24, 24]">
      <a-col :xs="24" :xl="16">
        <a-card class="form-card" :bordered="false">
          <div class="card-header">
            <div class="card-title">创建DGA域名检测任务</div>
            <div class="card-subtitle">
              使用DGA二分类模型计算域名的DGA-like分数并输出检测结果。
            </div>
            <div class="header-tags">
              <span class="mini-tag">二分类模型</span>
              <span class="mini-tag">DGA-like</span>
              <span class="mini-tag">离线检测</span>
            </div>
          </div>

          <a-form layout="vertical" class="task-form">
            <div class="form-section">
              <div class="section-title">步骤 1：选择DGA检测模型</div>
              <a-form-item label="检测模型">
                <a-select
                  v-model:value="selectedModel"
                  placeholder="请选择用于本次检测的DGA模型"
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
                  placeholder="每行输入一个域名或URL，例如：&#10;example.com&#10;https://login.example.org/path"
                  show-count
                />
                <div class="manual-input-meta">
                  当前输入 {{ manualDomainItems.length }} 项，提交后后端会自动提取域名、去重并过滤无效内容。
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
      </a-col>

      <a-col :xs="24" :xl="8">
        <a-card title="处理流程" class="guide-card" :bordered="false">
          <ul class="guide-list">
            <li><span class="dot">1</span><span>先用DGA二分类模型计算每个域名的DGA_score。</span></li>
            <li><span class="dot">2</span><span>将DGA_score不低于0.90的域名判定为DGA-like。</span></li>
            <li><span class="dot">3</span><span>生成预测结果、统计信息和DGA域名列表。</span></li>
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
.guide-card {
  border-radius: 8px;
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
</style>
