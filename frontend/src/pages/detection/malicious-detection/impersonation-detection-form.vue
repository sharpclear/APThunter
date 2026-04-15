<script setup lang="ts">
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { ref } from 'vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'
import { getApiBase } from '~/utils/api-public'

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
          :disabled-date="disabledNewDomainDate"
          format="YYYY-MM-DD"
          value-format="YYYY-MM-DD"
          style="width:100%"
          @calendar-change="onDetCalendarChange"
          @open-change="onDetOpenChange"
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


