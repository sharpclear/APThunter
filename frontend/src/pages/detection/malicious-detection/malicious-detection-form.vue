<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { onMounted, ref } from 'vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'
import { getApiBase } from '~/utils/api-public'

defineOptions({
  name: 'MaliciousDetectionForm',
})

const userId = useUserId()
const token = useAuthorization()

// 模型列表
const modelList = ref<{ id: string | number, name: string }[]>([])
const selectedModel = ref<string | number | null>('')
const modelListLoading = ref(false)

// 数据来源选择
const dataSource = ref<'upload' | 'newDomain'>('upload')

// 文件上传控制
const uploadFile = ref<any>(null)
const uploadLoading = ref(false)
const fileRules = {
  maxSize: 5 * 1024 * 1024, // 5MB
  accept: '.csv,.txt,.xlsx',
}

// 新注册域名日期范围：开始日期 >= 2024-09-01，窗口最多 30 天
const MIN_START_DATE = dayjs('2024-09-01')
const dateRange = ref<[string, string] | null>(null)
const pickedAnchorDate = ref<dayjs.Dayjs | null>(null)
const pickedAnchorType = ref<'start' | 'end' | null>(null)

function disabledNewDomainDate(current: dayjs.Dayjs) {
  const today = dayjs().endOf('day')
  const cur = dayjs(current).startOf('day')
  if (cur.isBefore(MIN_START_DATE, 'day') || cur.isAfter(today, 'day'))
    return true
  if (pickedAnchorDate.value) {
    const anchor = pickedAnchorDate.value.startOf('day')
    if (pickedAnchorType.value === 'start') {
      if (cur.isBefore(anchor, 'day') || cur.isAfter(anchor.add(30, 'day'), 'day'))
        return true
    }
    else if (pickedAnchorType.value === 'end') {
      if (cur.isBefore(anchor.subtract(30, 'day'), 'day') || cur.isAfter(anchor, 'day'))
        return true
    }
  }
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

// 归因分析
const withAttribution = ref(false)

const submitLoading = ref(false)

const API_BASE = getApiBase()

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

// 动态获取模型列表
async function fetchAvailableModels() {
  modelListLoading.value = true
  try {
    const resp = await fetch(`${API_BASE}/models/available`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      const errorText = await resp.text()
      throw new Error(errorText)
    }
    
    const json = await resp.json()
    if (json.code === 0 && json.data) {
      modelList.value = json.data.map((item: any) => ({
        id: item.id,
        name: item.name,
      }))
    }
    else {
      throw new Error(json.message || '获取模型列表失败')
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

onMounted(() => {
  fetchAvailableModels()
})

function beforeUpload(file: File) {
  console.log('beforeUpload called, file:', file)
  // 验证文件
  const fileExt = `.${file.name.split('.').pop()!.toLowerCase()}`
  const acceptedExts = fileRules.accept.split(',').map(ext => ext.trim().toLowerCase())
  const isValid = file.size <= fileRules.maxSize && acceptedExts.includes(fileExt)
  
  if (!isValid) {
    message.error('文件不符合要求，仅支持csv/txt/xlsx格式且不超过5MB')
    return false // 阻止文件上传
  }
  
  // 验证通过，文件会通过 change 事件的 originFileObj 传递
  console.log('✅ 文件验证通过:', file.name)
  return false // 阻止自动上传，手动处理
}
function handleUpload(info: any) {
  // Ant Design Vue Upload 组件的 change 事件
  const { file } = info
  
  console.log('handleUpload called, file:', file)
  console.log('file.originFileObj:', file.originFileObj)
  console.log('file.raw:', file.raw)
  console.log('file.status:', file.status)
  
  // 如果文件被移除，清空
  if (file.status === 'removed') {
    uploadFile.value = null
    return
  }
  
  // 尝试获取原生 File 对象
  // Ant Design Vue 中，当 beforeUpload 返回 false 时，原始文件在 originFileObj 中
  let originalFile: File | null = null
  
  // 优先使用 originFileObj（这是 beforeUpload 接收到的原始文件）
  if (file.originFileObj && file.originFileObj instanceof File) {
    originalFile = file.originFileObj
    console.log('使用 originFileObj')
  } 
  // 其次尝试 raw
  else if (file.raw && file.raw instanceof File) {
    originalFile = file.raw
    console.log('使用 raw')
  }
  // 最后尝试 file 本身（在某些情况下可能是 File 对象）
  else if (file instanceof File) {
    originalFile = file
    console.log('使用 file 本身')
  }
  // 如果都没有，尝试从 beforeUpload 传入的文件（但这不应该在这里，因为 beforeUpload 是同步的）
  else if (file.file && file.file instanceof File) {
    originalFile = file.file
    console.log('使用 file.file')
  }
  
  if (originalFile && originalFile instanceof File) {
    // 验证文件
    const isValid = originalFile.size <= fileRules.maxSize && 
                   fileRules.accept.split(',').some(ext => originalFile!.name.toLowerCase().endsWith(ext.trim()))
    if (isValid) {
      uploadFile.value = originalFile
      console.log('✅ 文件已选择:', originalFile.name, originalFile.size, 'bytes', '类型:', originalFile.type, '构造函数:', originalFile.constructor.name)
    } else {
      console.warn('❌ 文件验证失败:', originalFile.name)
      uploadFile.value = null
    }
  } else {
    console.error('❌ 无法获取有效的文件对象')
    console.error('file 对象详情:', {
      type: typeof file,
      keys: Object.keys(file),
      originFileObj: file.originFileObj ? typeof file.originFileObj : 'null',
      raw: file.raw ? typeof file.raw : 'null',
      isFile: file instanceof File
    })
    uploadFile.value = null
  }
}

async function handleSubmit() {
  if (!selectedModel.value) {
    return message.warning('请选择检测模型')
  }
  if (dataSource.value === 'upload' && !uploadFile.value) {
    return message.warning('请上传待检测文件')
  }
  if (dataSource.value === 'newDomain' && !dateRange.value) {
    return message.warning('请选择日期范围')
  }
  if (dataSource.value === 'newDomain' && dateRange.value) {
    const [start, end] = dateRange.value
    const days = dayjs(end).startOf('day').diff(dayjs(start).startOf('day'), 'day')
    if (days > 30) {
      return message.warning('日期范围最多为一个月')
    }
  }
  submitLoading.value = true
  try {
    const fd = new FormData()
    fd.append('model', String(selectedModel.value))
    fd.append('dataSource', dataSource.value)
    fd.append('withAttribution', String(withAttribution.value))
    
    if (dataSource.value === 'upload' && uploadFile.value) {
      // 验证文件对象
      if (!(uploadFile.value instanceof File)) {
        console.error('❌ 文件对象类型错误:', {
          type: typeof uploadFile.value,
          constructor: uploadFile.value?.constructor?.name,
          value: uploadFile.value,
          keys: uploadFile.value ? Object.keys(uploadFile.value) : []
        })
        message.error('文件对象无效，请重新选择文件')
        throw new Error('文件对象无效，请重新上传文件')
      }
      
      // 再次验证文件确实是File实例
      const file = uploadFile.value as File
      console.log('✅ 准备上传文件:', {
        name: file.name,
        size: file.size,
        type: file.type,
        lastModified: file.lastModified,
        constructor: file.constructor.name,
        isFile: file instanceof File,
        isBlob: file instanceof Blob
      })
      
      // 确保使用原生File对象添加到FormData
      // FormData.append(name, value, filename?) - 第三个参数可选，但最好提供文件名
      fd.append('file', file, file.name)
      
      // 验证FormData中的文件
      if (fd.has('file')) {
        console.log('✅ FormData中已包含file字段')
      } else {
        console.error('❌ FormData中未找到file字段')
        throw new Error('文件添加失败')
      }
    }
    
    if (dataSource.value === 'newDomain' && dateRange.value) {
      fd.append('dateRange', JSON.stringify(dateRange.value))
    }
    
    // 调试：打印FormData内容
    console.log('提交FormData:', {
      model: selectedModel.value,
      dataSource: dataSource.value,
      withAttribution: withAttribution.value,
      hasFile: dataSource.value === 'upload' && uploadFile.value !== null,
      hasDateRange: dataSource.value === 'newDomain' && dateRange.value !== null
    })
    
    const headers: HeadersInit = {}
    if (userId.value) {
      headers['X-User-Id'] = userId.value
    }
    const resp = await fetch(`${API_BASE}/tasks`, { 
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
    message.success(`检测任务已提交！ task: ${json.task_id || ''}`)
    resetForm()
  }
  catch (e: any) {
    console.error('提交错误:', e)
    message.error(`提交失败: ${e.message || '未知错误'}`)
  }
  finally {
    submitLoading.value = false
  }
}
function resetForm() {
  selectedModel.value = ''
  dataSource.value = 'upload'
  uploadFile.value = null
  dateRange.value = null
  withAttribution.value = false
}
</script>

<template>
  <div class="task-layout">
    <a-row :gutter="[24, 24]">
      <a-col :xs="24" :xl="16">
        <a-card class="form-card" :bordered="false">
          <div class="card-header">
            <div class="card-title">
              创建恶意性检测任务
            </div>
            <div class="card-subtitle">
              上传待检测域名文件，或选择新注册域名时间窗进行批量检测。
            </div>
            <div class="header-tags">
              <span class="mini-tag">风险识别</span>
              <span class="mini-tag">批量检测</span>
              <span class="mini-tag">组织分析</span>
            </div>
          </div>

          <a-form layout="vertical" class="task-form">
            <div class="form-section">
              <div class="section-title">
                步骤 1：选择检测模型
              </div>
              <a-form-item label="检测模型">
                <a-select
                  v-model:value="selectedModel"
                  placeholder="请选择用于本次检测的模型"
                  :options="modelList.map(m => ({ label: m.name, value: m.id }))"
                  :loading="modelListLoading"
                  allow-clear
                />
              </a-form-item>
            </div>

            <div class="form-section">
              <div class="section-title">
                步骤 2：选择数据来源
              </div>
              <a-form-item label="数据来源">
                <a-radio-group v-model:value="dataSource" button-style="solid">
                  <a-radio-button value="upload">
                    上传文件
                  </a-radio-button>
                  <a-radio-button value="newDomain">
                    选择新注册域名
                  </a-radio-button>
                </a-radio-group>
              </a-form-item>
              <a-form-item
                v-if="dataSource === 'upload'"
                label="待检测数据文件"
              >
                <a-upload-dragger
                  :before-upload="beforeUpload"
                  :show-upload-list="false"
                  :accept="fileRules.accept"
                  :disabled="uploadLoading"
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
                  <p class="upload-subtitle">
                    支持 CSV / TXT / XLSX，单文件不超过 5MB
                  </p>
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
            </div>

            <div class="form-section">
              <div class="attribution-box">
                <a-checkbox v-model:checked="withAttribution">
                  输出组织关联分析
                </a-checkbox>
                <div class="attribution-tip">
                  勾选后，系统将结合历史 IOC 特征生成疑似关联组织与证据摘要。
                </div>
              </div>
            </div>

            <div class="action-footer">
              <a-button
                type="primary"
                :loading="submitLoading"
                class="submit-btn"
                @click="handleSubmit"
              >
                提交任务
              </a-button>
              <a-button @click="resetForm">
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
              <li><span class="dot">1</span><span>选择模型后再选择数据来源。</span></li>
              <li><span class="dot">2</span><span>文件支持 CSV、TXT、XLSX，大小不超过 5MB。</span></li>
              <li><span class="dot">3</span><span>新注册域名模式下，日期跨度最多 30 天。</span></li>
            </ul>
          </a-card>
          <a-card title="推荐流程" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>选择与任务类型匹配的模型。</span></li>
              <li><span class="dot">2</span><span>优先使用结构化域名文件。</span></li>
              <li><span class="dot">3</span><span>提交后在“我的任务”中查看进度。</span></li>
            </ul>
          </a-card>
          <a-card title="输出结果" class="guide-card" :bordered="false">
            <ul class="guide-list">
              <li><span class="dot">1</span><span>风险等级与高风险域名列表。</span></li>
              <li><span class="dot">2</span><span>可选组织关联分析。</span></li>
              <li><span class="dot">3</span><span>结果可用于预警订阅与后续核查。</span></li>
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
  border: 1px solid #dbeafe;
  color: #2563eb;
  background: #eff6ff;
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
  border-color: #dbe7ff;
  background: #f9fbff;
}

:deep(.upload-card.ant-upload-wrapper .ant-upload-drag:hover) {
  border-color: #1677ff;
}

.upload-icon {
  font-size: 30px;
  color: #7696d1;
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

.attribution-box {
  border-radius: 10px;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
  padding: 10px 12px;
}

.attribution-tip {
  margin-top: 6px;
  color: #667085;
  font-size: 13px;
  line-height: 1.6;
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
  background: #e8f1ff;
  color: #1677ff;
  font-size: 12px;
  font-weight: 600;
  line-height: 18px;
  text-align: center;
  flex-shrink: 0;
  margin-top: 4px;
}
</style>


