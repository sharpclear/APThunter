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

// 文件上传控制
const fileRules = {
  maxSize: 5 * 1024 * 1024, // 5MB
  accept: '.csv,.txt,.xlsx',
}

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
const officialDomainFile = ref<File | null>(null)
const officialDomainUploadLoading = ref(false)
const detectionDomainSource = ref<'upload' | 'newDomain'>('upload')
const detectionDomainFile = ref<File | null>(null)
const detectionDomainUploadLoading = ref(false)
const impersonationSubmitLoading = ref(false)

const API_BASE = getApiBase()

function beforeOfficialDomainUpload(file: File) {
  const isValid = file.size <= fileRules.maxSize && fileRules.accept.split(',').includes(`.${file.name.split('.').pop()!}`)
  if (!isValid) {
    message.error('文件不符合要求，仅支持csv/txt/xlsx格式且不超过5MB')
  }
  return false // 阻止自动上传，手动处理
}
function handleOfficialDomainUpload(info: any) {
  const { file } = info
  if (file.status === 'removed') {
    officialDomainFile.value = null
    return
  }
  let originalFile: File | null = null
  if (file.originFileObj && file.originFileObj instanceof File) {
    originalFile = file.originFileObj
  } else if (file.raw && file.raw instanceof File) {
    originalFile = file.raw
  } else if (file instanceof File) {
    originalFile = file
  }
  if (originalFile) {
    officialDomainFile.value = originalFile
  } else {
    officialDomainFile.value = null
    message.error('无法获取有效的文件对象')
  }
}

function beforeDetectionDomainUpload(file: File) {
  const isValid = file.size <= fileRules.maxSize && fileRules.accept.split(',').includes(`.${file.name.split('.').pop()!}`)
  if (!isValid) {
    message.error('文件不符合要求，仅支持csv/txt/xlsx格式且不超过5MB')
  }
  return false // 阻止自动上传，手动处理
}
function handleDetectionDomainUpload(info: any) {
  const { file } = info
  if (file.status === 'removed') {
    detectionDomainFile.value = null
    return
  }
  let originalFile: File | null = null
  if (file.originFileObj && file.originFileObj instanceof File) {
    originalFile = file.originFileObj
  } else if (file.raw && file.raw instanceof File) {
    originalFile = file.raw
  } else if (file instanceof File) {
    originalFile = file
  }
  if (originalFile) {
    detectionDomainFile.value = originalFile
  } else {
    detectionDomainFile.value = null
    message.error('无法获取有效的文件对象')
  }
}
function resetImpersonationForm() {
  officialDomainFile.value = null
  detectionDomainSource.value = 'upload'
  detectionDomainFile.value = null
  detectionDomainDateRange.value = null
}
async function handleImpersonationSubmit() {
  if (!officialDomainFile.value) {
    return message.warning('请上传被仿冒官方域名文件')
  }
  if (detectionDomainSource.value === 'upload' && !detectionDomainFile.value) {
    return message.warning('请上传待检测域名文件')
  }
  if (detectionDomainSource.value === 'newDomain' && !detectionDomainDateRange.value) {
    return message.warning('请选择日期范围')
  }
  if (detectionDomainSource.value === 'newDomain' && detectionDomainDateRange.value) {
    const [start, end] = detectionDomainDateRange.value
    const days = dayjs(end).startOf('day').diff(dayjs(start).startOf('day'), 'day')
    if (days > 30) {
      return message.warning('日期范围最多为一个月')
    }
  }
  impersonationSubmitLoading.value = true
  try {
    // 验证文件对象
    if (!(officialDomainFile.value instanceof File)) {
      message.error('官方域名文件对象无效，请重新选择文件')
      throw new Error('官方域名文件对象无效')
    }
    
    const fd = new FormData()
    fd.append('officialFile', officialDomainFile.value, officialDomainFile.value.name)
    fd.append('detectionSource', detectionDomainSource.value)
    
    if (detectionDomainSource.value === 'upload') {
      if (!detectionDomainFile.value) {
        return message.warning('请上传待检测域名文件')
      }
      if (!(detectionDomainFile.value instanceof File)) {
        message.error('待检测域名文件对象无效，请重新选择文件')
        throw new Error('待检测域名文件对象无效')
      }
      fd.append('detectionFile', detectionDomainFile.value, detectionDomainFile.value.name)
    } else {
      if (!detectionDomainDateRange.value) {
        return message.warning('请选择日期范围')
      }
      fd.append('detectionDateRange', JSON.stringify(detectionDomainDateRange.value || []))
    }
    
    const headers: HeadersInit = {}
    if (userId.value) {
      headers['X-User-Id'] = userId.value
    }
    // 注意：不要设置 Content-Type，让浏览器自动设置 multipart/form-data 边界
    const resp = await fetch(`${API_BASE}/impersonation-tasks`, { 
      method: 'POST', 
      body: fd,
      headers,
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
              上传官方域名清单与待检测域名，系统将进行相似域名分析。
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
                步骤 1：上传官方域名清单
              </div>
              <a-form-item label="官方域名" required>
                <a-upload-dragger
                  :before-upload="beforeOfficialDomainUpload"
                  :show-upload-list="false"
                  accept=".csv,.txt,.xlsx"
                  :disabled="officialDomainUploadLoading"
                  :custom-request="() => {}"
                  class="upload-card"
                  @change="handleOfficialDomainUpload"
                >
                  <p class="ant-upload-drag-icon">
                    <i class="iconfont icon-upload-cloud upload-icon" />
                  </p>
                  <p class="upload-title">
                    {{ officialDomainFile ? officialDomainFile.name : '上传官方域名清单' }}
                  </p>
                  <p class="upload-subtitle">
                    用于建立基准特征，建议包含权威域名
                  </p>
                </a-upload-dragger>
              </a-form-item>
            </div>

            <div class="form-section">
              <div class="section-title">
                步骤 2：选择待检测域名来源
              </div>
              <a-form-item label="待检测域名来源" required>
                <a-radio-group v-model:value="detectionDomainSource" button-style="solid">
                  <a-radio-button value="upload">
                    上传文件
                  </a-radio-button>
                  <a-radio-button value="newDomain">
                    选择新注册域名
                  </a-radio-button>
                </a-radio-group>
              </a-form-item>
              <a-form-item
                v-if="detectionDomainSource === 'upload'"
                label="待检测域名文件"
                required
              >
                <a-upload-dragger
                  :before-upload="beforeDetectionDomainUpload"
                  :show-upload-list="false"
                  accept=".csv,.txt,.xlsx"
                  :disabled="detectionDomainUploadLoading"
                  :custom-request="() => {}"
                  class="upload-card"
                  @change="handleDetectionDomainUpload"
                >
                  <p class="ant-upload-drag-icon">
                    <i class="iconfont icon-upload-cloud upload-icon" />
                  </p>
                  <p class="upload-title">
                    {{ detectionDomainFile ? detectionDomainFile.name : '上传待检测域名文件' }}
                  </p>
                  <p class="upload-subtitle">
                    系统将与官方域名进行相似性分析
                  </p>
                </a-upload-dragger>
              </a-form-item>
              <a-form-item v-if="detectionDomainSource === 'newDomain'" label="新注册域名数据日期范围" required>
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
              <li><span class="dot">1</span><span>官方域名用于建立基准特征。</span></li>
              <li><span class="dot">2</span><span>待检测域名可来自上传文件或新注册域名时间窗。</span></li>
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


