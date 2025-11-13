<script setup lang="ts">
import { message } from 'ant-design-vue'
import { onMounted, ref } from 'vue'

defineOptions({
  name: 'MaliciousDetection',
})

// 模型列表
const modelList = ref<{ id: string | number, name: string }[]>([])
const selectedModel = ref<string | number | null>('')

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

// 动态获取模型列表
onMounted(async () => {
  try {
    // 实际应调用后端API获取模型列表
    // const resp = await fetch('/api/model/list')
    // modelList.value = await resp.json()
    modelList.value = [
      { id: 'model_1', name: '深度检测模型v1' },
      { id: 'model_2', name: 'AI快速识别模型' },
    ]
  }
  catch {
    message.error('模型列表获取失败')
  }
})

function beforeUpload(file: File) {
  const isValid = file.size <= fileRules.maxSize && fileRules.accept.split(',').includes(`.${file.name.split('.').pop()!}`)
  if (!isValid) {
    message.error('文件不符合要求，仅支持csv/txt/xlsx格式且不超过5MB')
  }
  return isValid
}
function handleUpload({ file }) {
  uploadFile.value = file
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
      fd.append('file', uploadFile.value)
    }
    else {
      fd.append('dateRange', JSON.stringify(dateRange.value || []))
    }
    const resp = await fetch('/api/tasks', { method: 'POST', body: fd })
    if (!resp.ok)
      throw new Error('提交失败')
    const json = await resp.json()
    message.success(`检测任务已提交！ task: ${json.task_id || ''}`)
    resetForm()
  }
  catch (e) {
    message.error('提交失败')
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
  return isValid
}
function handleOfficialDomainUpload({ file }: { file: File }) {
  officialDomainFile.value = file
}

function beforeDetectionDomainUpload(file: File) {
  const isValid = file.size <= fileRules.maxSize && fileRules.accept.split(',').includes(`.${file.name.split('.').pop()!}`)
  if (!isValid) {
    message.error('文件不符合要求，仅支持csv/txt/xlsx格式且不超过5MB')
  }
  return isValid
}
function handleDetectionDomainUpload({ file }: { file: File }) {
  detectionDomainFile.value = file
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
    const fd = new FormData()
    fd.append('officialFile', officialDomainFile.value as File)
    fd.append('detectionSource', detectionDomainSource.value)
    if (detectionDomainSource.value === 'upload' && detectionDomainFile.value) {
      fd.append('detectionFile', detectionDomainFile.value as File)
    }
    else {
      fd.append('detectionDateRange', JSON.stringify(detectionDomainDateRange.value || []))
    }
    const resp = await fetch('/api/impersonation-tasks', { method: 'POST', body: fd })
    if (!resp.ok)
      throw new Error('提交失败')
    const json = await resp.json()
    message.success(`仿冒域名检测任务已提交！ task: ${json.task_id || ''}`)
    resetImpersonationForm()
  }
  catch {
    message.error('提交失败')
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
