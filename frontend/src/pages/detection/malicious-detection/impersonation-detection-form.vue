<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { ref } from 'vue'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'ImpersonationDetectionForm',
})

const userId = useUserId()

// 新注册域名日期范围：开始日期 >= 2024-09-01，窗口最多 30 天
const MIN_START_DATE = dayjs('2024-09-01')
const detectionDomainDateRange = ref<[string, string] | null>(null)
const detPickedAnchorDate = ref<dayjs.Dayjs | null>(null)
const detPickedAnchorType = ref<'start' | 'end' | null>(null)

function disabledNewDomainDate(current: dayjs.Dayjs) {
  const today = dayjs().endOf('day')
  const cur = dayjs(current).startOf('day')
  if (cur.isBefore(MIN_START_DATE, 'day') || cur.isAfter(today, 'day'))
    return true
  if (detPickedAnchorDate.value) {
    const anchor = detPickedAnchorDate.value.startOf('day')
    if (detPickedAnchorType.value === 'start') {
      if (cur.isBefore(anchor, 'day') || cur.isAfter(anchor.add(30, 'day'), 'day'))
        return true
    }
    else if (detPickedAnchorType.value === 'end') {
      if (cur.isBefore(anchor.subtract(30, 'day'), 'day') || cur.isAfter(anchor, 'day'))
        return true
    }
  }
  return false
}

function onDetCalendarChange(dates: any, _dateStrings: any, info: any) {
  if (!dates) {
    detPickedAnchorDate.value = null
    detPickedAnchorType.value = null
    return
  }
  const range = info?.range as 'start' | 'end' | undefined
  if (range === 'end' && dates[1]) {
    detPickedAnchorDate.value = dayjs(dates[1])
    detPickedAnchorType.value = 'end'
  }
  else if (dates[0]) {
    detPickedAnchorDate.value = dayjs(dates[0])
    detPickedAnchorType.value = 'start'
  }
}

function onDetOpenChange(open: boolean) {
  if (open) {
    detPickedAnchorDate.value = null
    detPickedAnchorType.value = null
  }
}

// 仿冒域名检测表单
const queryName = ref('')
const officialFile = ref<File | null>(null)
const impersonationSubmitLoading = ref(false)
const useCustomThreshold = ref(false)
const threshold = ref(60)

const API_BASE = getApiBase()

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  return headers
}

function formatDateList(dates: string[]) {
  if (!dates.length)
    return ''
  const visible = dates.slice(0, 5).join('、')
  return dates.length > 5 ? `${visible} 等 ${dates.length} 天` : visible
}

async function ensureNewDomainDataAvailable(range: [string, string]) {
  const params = new URLSearchParams({
    startDate: range[0],
    endDate: range[1],
  })
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
  if (unavailableDates.length > 0) {
    message.warning(`部分日期暂无可用数据：${formatDateList(unavailableDates)}，将仅检测可用日期。`)
  }
  return true
}

function resetImpersonationForm() {
  queryName.value = ''
  officialFile.value = null
  detectionDomainDateRange.value = null
  useCustomThreshold.value = false
  threshold.value = 60
}

function beforeOfficialFileUpload(file: File) {
  const ext = file.name.split('.').pop()?.toLowerCase()
  const ok = file.size <= 5 * 1024 * 1024 && !!ext && ['csv', 'txt', 'xlsx'].includes(ext)
  if (!ok) {
    message.error('仅支持 csv/txt/xlsx 且不超过5MB')
    return false
  }
  officialFile.value = file
  return false
}

function onOfficialFileChange({ file }: { file: any }) {
  const rawFile = file?.originFileObj
  if (rawFile instanceof File)
    officialFile.value = rawFile
}

async function handleImpersonationSubmit() {
  if (!queryName.value.trim() && !officialFile.value) {
    return message.warning('请输入事件名或单位名，或上传官方域名文件')
  }
  if (!detectionDomainDateRange.value) {
    return message.warning('请选择日期范围')
  }
  if (detectionDomainDateRange.value) {
    const [start, end] = detectionDomainDateRange.value
    const days = dayjs(end).startOf('day').diff(dayjs(start).startOf('day'), 'day')
    if (days > 30) {
      return message.warning('日期范围最多为一个月')
    }
  }
  impersonationSubmitLoading.value = true
  try {
    const available = await ensureNewDomainDataAvailable(detectionDomainDateRange.value)
    if (!available)
      return

    const fd = new FormData()
    if (queryName.value.trim())
      fd.append('queryName', queryName.value.trim())
    if (officialFile.value)
      fd.append('officialFile', officialFile.value)
    fd.append('detectionDateRange', JSON.stringify(detectionDomainDateRange.value || []))
    fd.append('useCustomThreshold', String(useCustomThreshold.value))
    if (useCustomThreshold.value)
      fd.append('threshold', String(threshold.value))
    
    // 注意：不要设置 Content-Type，让浏览器自动设置 multipart/form-data 边界
    const resp = await fetch(`${API_BASE}/impersonation-tasks`, { 
      method: 'POST', 
      body: fd,
      headers: buildHeaders(),
    })
    if (!resp.ok) {
      let errorText = ''
      try {
        const errorJson = await resp.json()
        errorText = JSON.stringify(errorJson)
        console.error('提交失败详情:', errorJson)
      } catch {
        errorText = await resp.text()
        console.error('提交失败:', errorText)
      }
      throw new Error(`提交失败: ${resp.status} ${errorText}`)
    }
    const json = await resp.json()
    if (json.officialDomainStatus === 'resolved')
      message.success(`仿冒域名检测任务已提交，DeepSeek 已解析 ${json.officialDomainCount || 0} 个官方域名。task: ${json.task_id || ''}`)
    else if (json.officialDomainStatus === 'file_uploaded')
      message.success(`仿冒域名检测任务已提交，已使用上传的官方域名文件。task: ${json.task_id || ''}`)
    else
      message.success(`仿冒域名检测任务已提交！ task: ${json.task_id || ''}`)
    resetImpersonationForm()
  }
  catch (e: any) {
    console.error('提交错误:', e)
    message.error(`提交失败: ${e.message || '未知错误'}`)
  }
  finally {
    impersonationSubmitLoading.value = false
  }
}
</script>

<template>
  <div class="task-layout">
    <a-row :gutter="[24, 24]">
      <a-col :xs="24" :xl="16">
        <a-card class="form-card" :bordered="false">
          <div class="card-header">
            <div class="card-title">
              创建仿冒域名检测任务
            </div>
            <div class="card-subtitle">
              优先输入事件名或单位名；也可以上传官方域名文件，并选择新注册域名时间窗进行相似域名分析。
            </div>
            <div class="header-tags">
              <span class="mini-tag">相似域名</span>
              <span class="mini-tag">品牌保护</span>
              <span class="mini-tag">新注册域名</span>
            </div>
          </div>

          <a-form layout="vertical" class="task-form">
            <div class="form-section">
              <div class="section-title">
                步骤 1：提供官方域名来源
              </div>
              <a-form-item label="事件名或单位名（首选）">
                <a-input
                  v-model:value="queryName"
                  allow-clear
                  placeholder="请输入事件名或单位名"
                  size="large"
                />
              </a-form-item>
              <a-form-item label="官方域名文件（可选）">
                <a-upload-dragger
                  class="upload-card"
                  :before-upload="beforeOfficialFileUpload"
                  :show-upload-list="false"
                  accept=".csv,.txt,.xlsx"
                  @change="onOfficialFileChange"
                >
                  <p class="ant-upload-drag-icon">
                    <i class="iconfont icon-upload-cloud upload-icon" />
                  </p>
                  <p v-if="officialFile" class="upload-title">
                    {{ officialFile.name }}
                  </p>
                  <template v-else>
                    <p class="upload-title">
                      点击或拖拽上传官方域名文件
                    </p>
                    <p class="upload-subtitle">
                      支持 csv / txt / xlsx，文件不超过 5MB
                    </p>
                  </template>
                </a-upload-dragger>
              </a-form-item>
            </div>

            <div class="form-section">
              <div class="section-title">
                步骤 2：选择新注册域名日期范围
              </div>
              <a-form-item label="新注册域名数据日期范围" required>
                <a-range-picker
                  v-model:value="detectionDomainDateRange"
                  :disabled-date="disabledNewDomainDate"
                  format="YYYY-MM-DD"
                  value-format="YYYY-MM-DD"
                  style="width:100%"
                  @calendar-change="onDetCalendarChange"
                  @open-change="onDetOpenChange"
                />
              </a-form-item>
            </div>

            <div class="form-section">
              <div class="section-title">
                步骤 3：设置相似度阈值
              </div>
              <a-form-item label="阈值策略">
                <a-checkbox v-model:checked="useCustomThreshold">
                  自定义相似度阈值
                </a-checkbox>
                <div v-if="!useCustomThreshold" class="threshold-tip">
                  默认使用自适应阈值，系统会根据官方域名关键部分长度自动调整判定标准。
                </div>
              </a-form-item>
              <a-form-item v-if="useCustomThreshold" label="相似度阈值（0-100）">
                <div class="threshold-row">
                  <a-slider v-model:value="threshold" class="threshold-slider" :min="0" :max="100" />
                  <span class="threshold-value">{{ threshold }}</span>
                </div>
              </a-form-item>
            </div>

            <div class="action-footer">
              <a-button
                type="primary"
                :loading="impersonationSubmitLoading"
                class="submit-btn"
                @click="handleImpersonationSubmit"
              >
                提交任务
              </a-button>
              <a-button @click="resetImpersonationForm">
                重置
              </a-button>
            </div>
          </a-form>
        </a-card>
      </a-col>

      <a-col :xs="24" :xl="8">
        <div class="side-panel">
          <a-card title="填写说明" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>事件名或单位名将通过 DeepSeek 解析相关官方域名；也可上传文件作为备用来源。</span></li>
              <li><span class="dot">2</span><span>待检测域名来自所选时间窗内的新注册域名。</span></li>
              <li><span class="dot">3</span><span>日期范围最多 30 天，避免任务过大。</span></li>
            </ul>
          </a-card>
          <a-card title="分析逻辑" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>字符串相似度分析。</span></li>
              <li><span class="dot">2</span><span>品牌关键词变体识别。</span></li>
              <li><span class="dot">3</span><span>结构模式与 TLD 特征比对。</span></li>
            </ul>
          </a-card>
          <a-card title="结果建议" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>优先关注高相似度且近期活跃的可疑域名。</span></li>
              <li><span class="dot">2</span><span>结合证书、WHOIS 和解析记录复核。</span></li>
              <li><span class="dot">3</span><span>在预警与订阅页面持续跟踪高风险对象。</span></li>
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

.form-card {
  border-radius: 16px;
  border: 1px solid rgba(220, 226, 235, 0.9);
  box-shadow: 0 8px 24px rgba(15, 35, 80, 0.06);
  min-height: 700px;
  display: flex;
  flex-direction: column;
}

.card-header {
  margin-bottom: 12px;
}

.card-title {
  font-size: 20px;
  line-height: 1.4;
  font-weight: 700;
  color: #1f2937;
}

.card-subtitle {
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
  flex: 1;
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

.threshold-tip {
  margin-top: 8px;
  color: #667085;
  font-size: 13px;
  line-height: 1.6;
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
  height: 28px;
  line-height: 28px;
  text-align: center;
  border-radius: 6px;
  color: #1f2937;
  background: #f3f4f6;
  border: 1px solid #e5e7eb;
  font-weight: 600;
}

.action-footer {
  margin-top: auto;
  border-top: 1px solid #e5e7eb;
  padding-top: 16px;
  display: flex;
  gap: 12px;
}

.submit-btn {
  min-width: 150px;
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
</style>
