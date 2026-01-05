<script setup lang="ts">
import { message } from 'ant-design-vue'
import { ref } from 'vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'

defineOptions({
  name: 'ImpersonationDetectionForm',
})

const userId = useUserId()
const token = useAuthorization()

// 文件上传控制
const fileRules = {
  maxSize: 5 * 1024 * 1024, // 5MB
  accept: '.csv,.txt,.xlsx',
}

// 日期范围控制
const dateRangeLimit = {
  disabledDate(current: Date) {
    const now = new Date()
    const past = new Date(now.getTime() - 1000 * 60 * 60 * 24 * 30)
    return current < past || current > now
  },
}

// 仿冒域名检测表单
const officialDomainFile = ref<File | null>(null)
const officialDomainUploadLoading = ref(false)
const detectionDomainSource = ref<'upload' | 'newDomain'>('upload')
const detectionDomainFile = ref<File | null>(null)
const detectionDomainUploadLoading = ref(false)
const detectionDomainDateRange = ref<any>([])
const impersonationSubmitLoading = ref(false)

const API_BASE = 'http://localhost'

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
  <a-card title="仿冒域名检测" bordered style="max-width:800px;margin:0 auto;">
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
</template>

<style scoped>
.iconfont.icon-upload-cloud::before {
  content: '\e68c';
  font-family: 'iconfont';
}
</style>


