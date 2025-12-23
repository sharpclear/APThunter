<script setup lang="ts">
import { message } from 'ant-design-vue'
import { onMounted, ref } from 'vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'

defineOptions({
  name: 'MaliciousDetection',
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

// 日期范围控制
const dateRange = ref([])
const dateRangeLimit = {
  disabledDate(current: Date) {
    const now = new Date()
    const past = new Date(now.getTime() - 1000 * 60 * 60 * 24 * 30)
    return current < past || current > now
  },
}

// 归因分析
const withAttribution = ref(false)

const submitLoading = ref(false)

const API_BASE = 'http://localhost'

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
    const resp = await fetch(`${API_BASE}/api/models/available`, {
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
  if (dataSource.value === 'newDomain' && (!dateRange.value || dateRange.value.length === 0)) {
    return message.warning('请选择日期范围')
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
    const resp = await fetch(`${API_BASE}/api/tasks`, { 
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
  dateRange.value = []
  withAttribution.value = false
}

// 仿冒域名检测表单 新增部分
const officialDomainFile = ref<File | null>(null)
const officialDomainUploadLoading = ref(false)
const detectionDomainSource = ref<'upload' | 'newDomain'>('upload')
const detectionDomainFile = ref<File | null>(null)
const detectionDomainUploadLoading = ref(false)
const detectionDomainDateRange = ref<any>([])
const impersonationSubmitLoading = ref(false)

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
  detectionDomainDateRange.value = []
}
async function handleImpersonationSubmit() {
  if (!officialDomainFile.value) {
    return message.warning('请上传被仿冒官方域名文件')
  }
  if (detectionDomainSource.value === 'upload' && !detectionDomainFile.value) {
    return message.warning('请上传待检测域名文件')
  }
  if (detectionDomainSource.value === 'newDomain' && (!detectionDomainDateRange.value || detectionDomainDateRange.value.length === 0)) {
    return message.warning('请选择日期范围')
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
      if (!detectionDomainDateRange.value || detectionDomainDateRange.value.length === 0) {
        return message.warning('请选择日期范围')
      }
      fd.append('detectionDateRange', JSON.stringify(detectionDomainDateRange.value || []))
    }
    
    const headers: HeadersInit = {}
    if (userId.value) {
      headers['X-User-Id'] = userId.value
    }
    // 注意：不要设置 Content-Type，让浏览器自动设置 multipart/form-data 边界
    const resp = await fetch(`${API_BASE}/api/impersonation-tasks`, { 
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
  <page-container>
    <div style="display:flex;gap:24px;flex-wrap:wrap;justify-content:center;align-items:stretch;">
      <a-card title="恶意性检测任务创建" bordered style="max-width:600px;min-width:320px;flex:1 1 400px;">
        <a-form layout="vertical">
          <a-form-item label="检测模型">
            <a-select
              v-model:value="selectedModel"
              placeholder="请选择检测模型"
              :options="modelList.map(m => ({ label: m.name, value: m.id }))"
              :loading="modelListLoading"
              allow-clear
            />
          </a-form-item>
          <a-form-item label="数据来源">
            <a-radio-group v-model:value="dataSource">
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
            label="待检测数据文件（仅支持csv/txt/xlsx 小于5MB）"
          >
            <a-upload-dragger
              :before-upload="beforeUpload"
              :show-upload-list="false"
              :accept="fileRules.accept"
              :disabled="uploadLoading"
              :custom-request="() => {}"
              style="width:100%"
              @change="handleUpload"
            >
              <p class="ant-upload-drag-icon">
                <i class="iconfont icon-upload-cloud" style="font-size:32px;color:#999;" />
              </p>
              <p v-if="uploadFile">
                {{ uploadFile.name }}
              </p>
              <p v-else>
                点击或拖拽文件上传
              </p>
            </a-upload-dragger>
          </a-form-item>
          <a-form-item v-if="dataSource === 'newDomain'" label="新注册域名 数据日期范围">
            <a-range-picker
              v-model:value="dateRange"
              :disabled-date="dateRangeLimit.disabledDate"
              style="width:100%"
              format="YYYY-MM-DD"
            />
          </a-form-item>
          <a-form-item>
            <a-checkbox v-model:checked="withAttribution">
              输出归因（组织标签分析）
            </a-checkbox>
          </a-form-item>
          <a-form-item>
            <a-button
              type="primary"
              :loading="submitLoading"
              style="width:120px"
              @click="handleSubmit"
            >
              提交任务
            </a-button>
            <a-button style="margin-left:16px" @click="resetForm">
              重置
            </a-button>
          </a-form-item>
        </a-form>
      </a-card>
      <a-card title="仿冒域名检测" bordered style="max-width:600px;min-width:320px;flex:1 1 400px;">
        <a-form layout="vertical">
          <a-form-item label="官方域名" required>
            <a-upload-dragger
              :before-upload="beforeOfficialDomainUpload"
              :show-upload-list="false"
              accept=".csv,.txt,.xlsx"
              :disabled="officialDomainUploadLoading"
              :custom-request="() => {}"
              style="width:100%"
              @change="handleOfficialDomainUpload"
            >
              <p class="ant-upload-drag-icon">
                <i class="iconfont icon-upload-cloud" style="font-size:32px;color:#999;" />
              </p>
              <p v-if="officialDomainFile">
                {{ officialDomainFile.name }}
              </p>
              <p v-else>
                点击或拖拽上传官方域名文件（csv/txt/xlsx小于5MB）
              </p>
            </a-upload-dragger>
          </a-form-item>
          <a-form-item label="待检测域名来源" required>
            <a-radio-group v-model:value="detectionDomainSource">
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
            label="待检测域名文件（csv/txt/xlsx 小于5MB）"
            required
          >
            <a-upload-dragger
              :before-upload="beforeDetectionDomainUpload"
              :show-upload-list="false"
              accept=".csv,.txt,.xlsx"
              :disabled="detectionDomainUploadLoading"
              :custom-request="() => {}"
              style="width:100%"
              @change="handleDetectionDomainUpload"
            >
              <p class="ant-upload-drag-icon">
                <i class="iconfont icon-upload-cloud" style="font-size:32px;color:#999;" />
              </p>
              <p v-if="detectionDomainFile">
                {{ detectionDomainFile.name }}
              </p>
              <p v-else>
                点击或拖拽上传待检测域名文件
              </p>
            </a-upload-dragger>
          </a-form-item>
          <a-form-item v-if="detectionDomainSource === 'newDomain'" label="新注册域名 数据日期范围" required>
            <a-range-picker
              v-model:value="detectionDomainDateRange"
              :disabled-date="dateRangeLimit.disabledDate"
              style="width:100%"
              format="YYYY-MM-DD"
            />
          </a-form-item>
          <a-form-item>
            <a-button
              type="primary"
              :loading="impersonationSubmitLoading"
              style="width:120px"
              @click="handleImpersonationSubmit"
            >
              提交任务
            </a-button>
            <a-button style="margin-left:16px" @click="resetImpersonationForm">
              重置
            </a-button>
          </a-form-item>
        </a-form>
      </a-card>
    </div>
  </page-container>
</template>

<style scoped>
.iconfont.icon-upload-cloud::before {
  content: '\e68c';
  font-family: 'iconfont';
}
</style>
