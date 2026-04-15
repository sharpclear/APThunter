<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

interface PreviewRow {
  key: number
  domain: string
  label: number
}

const API_BASE = getApiBase()
const token = useAuthorization()
const userId = useUserId()

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

const formRef = ref()
const trainingForm = reactive({
  modelName: '',
  modelDesc: '',
  modelType: '恶意性检测',
  /* learningRate: 0.001,
  epochs: 10,
  batchSize: 64, */
})

const rules = reactive({
  modelName: [
    { required: true, message: '请输入模型名称', trigger: 'blur' },
    { min: 2, max: 50, message: '长度应为 2-50 个字符', trigger: 'blur' },
  ],
  modelDesc: [
    { max: 200, message: '描述不超过 200 字', trigger: 'blur' },
  ],
  /* learningRate: [
    { required: true, message: '请输入学习率', trigger: 'change' },
    {
      validator: (_: unknown, v: number) =>
        v > 0 && v <= 1 ? Promise.resolve() : Promise.reject('学习率需在 (0, 1]'),
      trigger: 'change',
    },
  ],
  epochs: [
    { required: true, message: '请输入轮次', trigger: 'change' },
    {
      validator: (_: unknown, v: number) =>
        Number.isInteger(v) && v > 0 && v <= 1000
          ? Promise.resolve()
          : Promise.reject('轮次需为 1-1000 的整数'),
      trigger: 'change',
    },
  ],
  batchSize: [
    { required: true, message: '请输入批大小', trigger: 'change' },
    {
      validator: (_: unknown, v: number) =>
        Number.isInteger(v) && v > 0 && v <= 100000
          ? Promise.resolve()
          : Promise.reject('批大小需为正整数且不超过 100000'),
      trigger: 'change',
    },
  ], */
})

// 上传/预览
const fileList = ref<any[]>([])
const selectedFile = ref<File | null>(null)
const previewData = ref<PreviewRow[]>([])
const isParsing = ref(false)
const uploadedFileId = ref<number | null>(null)
const isUploading = ref(false)
const previewColumns = [
  { title: '域名', dataIndex: 'domain', key: 'domain' },
  { title: '标签', dataIndex: 'label', key: 'label' },
]

const MAX_SIZE_MB = 5
const ACCEPT_TYPES = ['text/csv', 'text/plain']
const ACCEPT_EXTS = ['.csv', '.txt']

async function beforeUpload(file: File) {
  const extOk = ACCEPT_EXTS.some(ext => file.name.toLowerCase().endsWith(ext))
  const typeOk = ACCEPT_TYPES.includes(file.type) || file.type === ''
  if (!extOk || !typeOk) {
    message.error('仅支持 CSV/TXT 格式的文件')
    return false
  }
  const sizeOk = file.size / 1024 / 1024 < MAX_SIZE_MB
  if (!sizeOk) {
    message.error(`文件大小不能超过 ${MAX_SIZE_MB}MB`)
    return false
  }
  
  // 阻止自动上传，先本地解析预览
  selectedFile.value = file
  fileList.value = [file as any]
  parsePreview(file)
  
  // 上传文件到后端
  await uploadFileToBackend(file)
  
  return false
}

async function uploadFileToBackend(file: File) {
  isUploading.value = true
  try {
    const formData = new FormData()
    formData.append('file', file)
    
    // 注意：使用 FormData 时，不要设置 Content-Type，让浏览器自动设置 multipart/form-data 边界
    const headers = buildHeaders()
    // 移除 Content-Type，让浏览器自动设置
    delete headers['Content-Type']
    
    const resp = await fetch(`${API_BASE}/training/upload-data`, {
      method: 'POST',
      headers: headers,
      body: formData,
    })
    
    // 检查响应状态
    if (!resp.ok) {
      let errorMessage = '文件上传失败'
      try {
        const errorResult = await resp.json()
        errorMessage = errorResult.detail || errorResult.message || errorMessage
      } catch {
        errorMessage = `HTTP ${resp.status}: ${resp.statusText}`
      }
      throw new Error(errorMessage)
    }
    
    const result = await resp.json()
    
    if (result.code === 0 && result.data && result.data.fileId) {
      uploadedFileId.value = result.data.fileId
      message.success('文件上传成功')
      console.log('文件上传成功，fileId:', uploadedFileId.value)
    } else {
      const errorMsg = result.message || result.detail || '文件上传失败'
      message.error(errorMsg)
      uploadedFileId.value = null
      console.error('文件上传失败:', result)
    }
  } catch (error: any) {
    console.error('上传文件失败:', error)
    const errorMsg = error.message || '文件上传失败，请重试'
    message.error(errorMsg)
    uploadedFileId.value = null
  } finally {
    isUploading.value = false
  }
}

function parsePreview(file: File) {
  isParsing.value = true
  const reader = new FileReader()
  reader.onload = () => {
    try {
      const text = String(reader.result || '')
      const lines = text
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l.length > 0)
      const rows: PreviewRow[] = []
      for (let i = 0; i < Math.min(5, lines.length); i++) {
        const parts = lines[i].split(',').map(s => s.trim())
        if (parts.length < 2)
          continue
        const domain = parts[0]
        const labelNum = Number(parts[1])
        if (!(labelNum === 0 || labelNum === 1))
          continue
        rows.push({ key: i, domain, label: labelNum })
      }
      previewData.value = rows
      if (rows.length === 0) {
        message.warning('未解析到有效数据，格式应为：域名,标签(0/1)')
      }
    }
    catch (e) {
      message.error('解析文件失败')
    }
    finally {
      isParsing.value = false
    }
  }
  reader.onerror = () => {
    isParsing.value = false
    message.error('读取文件失败')
  }
  reader.readAsText(file)
}

// 训练状态
const trainingStatus = ref<'idle' | 'running' | 'paused' | 'completed' | 'stopped'>('idle')
const progress = ref(0)
const intervalId = ref<number | null>(null)
const startTimestamp = ref<number | null>(null)
const lastTick = ref<number | null>(null)
const currentTaskId = ref<string | null>(null)
const statusPollingId = ref<number | null>(null)

const canStart = computed(() => {
  return (
    trainingStatus.value === 'idle'
    || trainingStatus.value === 'completed'
    || trainingStatus.value === 'stopped'
  )
})

const hasFile = computed(() => !!selectedFile.value && uploadedFileId.value !== null)

const estimatedRemainingSeconds = ref<number | null>(null)

const estimatedRemaining = computed(() => {
  if (estimatedRemainingSeconds.value !== null && estimatedRemainingSeconds.value > 0) {
    return formatDuration(estimatedRemainingSeconds.value)
  }
  if (!startTimestamp.value || progress.value <= 0 || progress.value >= 100)
    return '—'
  const now = Date.now()
  const elapsedSec = (now - startTimestamp.value) / 1000
  const rate = progress.value / elapsedSec // % per sec
  if (rate <= 0)
    return '—'
  const remainSec = (100 - progress.value) / rate
  return formatDuration(remainSec)
})

function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(h)}:${pad(m)}:${pad(sec)}`
}

async function handleStart() {
  if (!hasFile.value || uploadedFileId.value === null) {
    message.error('请先上传训练数据文件')
    return
  }
  try {
    await formRef.value?.validate()
  }
  catch {
    message.error('请完善表单信息')
    return
  }
  
  // 调用后端API开始训练
  try {
    const resp = await fetch(`${API_BASE}/training/start`, {
      method: 'POST',
      headers: {
        ...buildHeaders(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        modelName: trainingForm.modelName,
        modelDesc: trainingForm.modelDesc,
        fileId: uploadedFileId.value,
      }),
    })
    
    const result = await resp.json()
    
    if (result.code === 0 && result.data?.taskId) {
      currentTaskId.value = result.data.taskId
      progress.value = 0
      trainingStatus.value = 'running'
      startTimestamp.value = Date.now()
      message.success('训练任务已提交，开始训练')
      // 开始轮询查询状态
      startStatusPolling()
    } else {
      message.error(result.message || '启动训练失败')
    }
  } catch (error) {
    console.error('启动训练失败:', error)
    message.error('启动训练失败，请重试')
  }
}

async function startStatusPolling() {
  if (!currentTaskId.value) return
  
  // 立即查询一次
  await fetchTrainingStatus()
  
  // 每2秒轮询一次
  statusPollingId.value = window.setInterval(async () => {
    if (trainingStatus.value === 'running' || trainingStatus.value === 'paused') {
      await fetchTrainingStatus()
    } else {
      stopStatusPolling()
    }
  }, 2000) as unknown as number
}

function stopStatusPolling() {
  if (statusPollingId.value) {
    clearInterval(statusPollingId.value)
    statusPollingId.value = null
  }
}

async function fetchTrainingStatus() {
  if (!currentTaskId.value) return
  
  try {
    const resp = await fetch(`${API_BASE}/training/tasks/${currentTaskId.value}/status`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    const result = await resp.json()
    
    if (result.code === 0 && result.data) {
      const data = result.data
      
      // 状态映射：后端 -> 前端
      const statusMap: Record<string, 'idle' | 'running' | 'paused' | 'completed' | 'stopped'> = {
        'idle': 'idle',
        'running': 'running',
        'training': 'running',
        'paused': 'paused',
        'stopped': 'stopped',
        'completed': 'completed',
        'failed': 'stopped',
      }
      
      trainingStatus.value = statusMap[data.status] || 'idle'
      progress.value = data.progress || 0
      estimatedRemainingSeconds.value = data.estimatedRemaining
      
      // 如果训练完成，获取结果
      if (data.status === 'completed' || trainingStatus.value === 'completed') {
        stopStatusPolling()
        await fetchTrainingResult()
        message.success('训练完成')
      } else if (data.status === 'failed') {
        stopStatusPolling()
        message.error(data.errorMessage || '训练失败')
      }
    }
  } catch (error) {
    console.error('查询训练状态失败:', error)
  }
}

async function fetchTrainingResult() {
  if (!currentTaskId.value) return
  
  try {
    const resp = await fetch(`${API_BASE}/training/tasks/${currentTaskId.value}/result`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    const result = await resp.json()
    
    if (result.code === 0 && result.data) {
      const data = result.data
      resultInfo.modelId = data.modelId ? String(data.modelId) : ''
      resultInfo.finishedAt = data.finishedAt ? new Date(data.finishedAt).toLocaleString() : new Date().toLocaleString()
      
      if (data.metrics) {
        resultInfo.metrics.accuracy = Number((data.metrics.accuracy || 0).toFixed(3))
        resultInfo.metrics.precision = Number((data.metrics.precision || 0).toFixed(3))
        resultInfo.metrics.recall = Number((data.metrics.recall || 0).toFixed(3))
        resultInfo.metrics.f1 = Number((data.metrics.f1 || 0).toFixed(3))
      }
      
      resultVisible.value = true
    }
  } catch (error) {
    console.error('获取训练结果失败:', error)
  }
}

async function handlePause() {
  if (trainingStatus.value !== 'running' || !currentTaskId.value)
    return
  
  try {
    const resp = await fetch(`${API_BASE}/training/tasks/${currentTaskId.value}/pause`, {
      method: 'POST',
      headers: buildHeaders(),
    })
    
    const result = await resp.json()
    if (result.code === 0) {
      trainingStatus.value = 'paused'
      message.info(result.message || '训练已暂停')
    } else {
      message.error(result.message || '暂停失败')
    }
  } catch (error) {
    console.error('暂停训练失败:', error)
    message.error('暂停训练失败')
  }
}

async function handleResume() {
  if (trainingStatus.value !== 'paused' || !currentTaskId.value)
    return
  
  try {
    const resp = await fetch(`${API_BASE}/training/tasks/${currentTaskId.value}/resume`, {
      method: 'POST',
      headers: buildHeaders(),
    })
    
    const result = await resp.json()
    if (result.code === 0) {
      trainingStatus.value = 'running'
      message.success('训练已恢复')
      startStatusPolling()
    } else {
      message.error(result.message || '恢复失败')
    }
  } catch (error) {
    console.error('恢复训练失败:', error)
    message.error('恢复训练失败')
  }
}

async function handleStop() {
  if ((trainingStatus.value !== 'running' && trainingStatus.value !== 'paused') || !currentTaskId.value)
    return
  
  Modal.confirm({
    title: '确认停止训练？',
    content: '停止后可重新启动新的训练任务。',
    okText: '停止',
    cancelText: '取消',
    onOk: async () => {
      try {
        const resp = await fetch(`${API_BASE}/training/tasks/${currentTaskId.value}/stop`, {
          method: 'POST',
          headers: buildHeaders(),
        })
        
        const result = await resp.json()
        if (result.code === 0) {
          stopStatusPolling()
          trainingStatus.value = 'stopped'
          progress.value = 0
          message.info(result.message || '训练已停止')
        } else {
          message.error(result.message || '停止失败')
        }
      } catch (error) {
        console.error('停止训练失败:', error)
        message.error('停止训练失败')
      }
    },
  })
}

onBeforeUnmount(() => {
  stopStatusPolling()
})

// 结果模拟
const resultVisible = ref(false)
const resultInfo = reactive({
  modelId: '',
  finishedAt: '',
  metrics: {
    accuracy: 0,
    precision: 0,
    recall: 0,
    f1: 0,
  },
})

// buildMockResult 函数已移除，改为使用 fetchTrainingResult

// 按钮状态
const isRunning = computed(() => trainingStatus.value === 'running')
const isPaused = computed(() => trainingStatus.value === 'paused')
const isCompleted = computed(() => trainingStatus.value === 'completed')

const statusText = computed(() => {
  switch (trainingStatus.value) {
    case 'idle': return '未开始'
    case 'running': return '训练中'
    case 'paused': return '已暂停'
    case 'completed': return '已完成'
    case 'stopped': return '已停止'
    default: return '—'
  }
})

onMounted(() => {
  // 无
})
</script>

<template>
  <div class="model-training-page">
    <a-row :gutter="16">
      <a-col :span="10">
        <a-card title="训练配置" :bordered="false">
          <a-form ref="formRef" :model="trainingForm" :rules="rules" layout="vertical">
            <a-form-item label="模型名称" name="modelName" required>
              <a-input v-model:value="trainingForm.modelName" placeholder="请输入模型名称" allow-clear />
            </a-form-item>
            <a-form-item label="模型描述" name="modelDesc">
              <a-textarea v-model:value="trainingForm.modelDesc" :rows="3" maxlength="200" show-count placeholder="该模型的用途与说明" />
            </a-form-item>
            <a-form-item label="模型类型">
              <a-input v-model:value="trainingForm.modelType" disabled />
            </a-form-item>

            <!-- <a-divider>训练参数</a-divider>
            <a-row :gutter="12">
              <a-col :span="8">
                <a-form-item label="学习率" name="learningRate" required>
                  <a-input-number v-model:value="trainingForm.learningRate" :min="0.000001" :max="1" :step="0.0005" :precision="6" style="width:100%" />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item label="轮次" name="epochs" required>
                  <a-input-number v-model:value="trainingForm.epochs" :min="1" :max="1000" :step="1" style="width:100%" />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item label="批大小" name="batchSize" required>
                  <a-input-number v-model:value="trainingForm.batchSize" :min="1" :max="100000" :step="1" style="width:100%" />
                </a-form-item>
              </a-col>
            </a-row> -->

            <a-divider>训练数据上传</a-divider>
            <a-alert type="info" show-icon style="margin-bottom:8px" message="数据格式：域名,标签(0/1)；示例：example.com,1" />
            <a-form-item label="数据文件 (CSV/TXT)" required>
              <a-upload
                :file-list="fileList"
                :before-upload="beforeUpload"
                :multiple="false"
                :max-count="1"
                accept=".csv,.txt"
                :show-upload-list="{ showRemoveIcon: true }"
                :disabled="isUploading"
                @remove="() => { fileList = []; selectedFile = null; previewData = []; uploadedFileId = null }"
              >
                <a-button type="dashed">
                  选择文件
                </a-button>
              </a-upload>
              <div class="tips">
                大小不超过 {{ MAX_SIZE_MB }}MB
              </div>
            </a-form-item>

            <a-form-item v-if="previewData.length" label="数据预览 (前几行)">
              <a-table :data-source="previewData" :columns="previewColumns" size="small" :pagination="false" :loading="isParsing" />
            </a-form-item>

            <a-space>
              <a-button type="primary" :disabled="!canStart || !hasFile" @click="handleStart">
                开始训练
              </a-button>
              <a-button :disabled="!isRunning" @click="handlePause">
                暂停
              </a-button>
              <a-button :disabled="!isPaused" @click="handleResume">
                继续
              </a-button>
              <a-button danger :disabled="!(isRunning || isPaused)" @click="handleStop">
                停止
              </a-button>
            </a-space>
          </a-form>
        </a-card>
      </a-col>

      <a-col :span="14">
        <a-card title="训练进度与结果" :bordered="false">
          <div class="status-line">
            <span>状态：</span>
            <a-tag :color="isRunning ? 'blue' : isPaused ? 'orange' : isCompleted ? 'green' : trainingStatus === 'stopped' ? 'red' : 'default'">
              {{ statusText }}
            </a-tag>
          </div>
          <div class="progress-wrap">
            <a-progress :percent="Number(progress.toFixed(1))" :status="isRunning ? 'active' : progress >= 100 ? 'success' : 'normal'" />
            <div class="eta">
              预计剩余时间：{{ estimatedRemaining }}
            </div>
          </div>

          <a-divider />

          <a-result v-if="isCompleted" status="success" title="训练完成">
            <template #subTitle>
              <div>模型ID：{{ resultInfo.modelId }}，完成时间：{{ resultInfo.finishedAt }}</div>
            </template>
            <template #extra>
              <a-descriptions bordered size="small" :column="2">
                <a-descriptions-item label="Accuracy">
                  {{ resultInfo.metrics.accuracy }}
                </a-descriptions-item>
                <a-descriptions-item label="Precision">
                  {{ resultInfo.metrics.precision }}
                </a-descriptions-item>
                <a-descriptions-item label="Recall">
                  {{ resultInfo.metrics.recall }}
                </a-descriptions-item>
                <a-descriptions-item label="F1">
                  {{ resultInfo.metrics.f1 }}
                </a-descriptions-item>
              </a-descriptions>
            </template>
          </a-result>
          <a-empty v-else description="暂无训练结果" />
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<style scoped>
.model-training-page {
  width: 100%;
}
.status-line {
  margin-bottom: 8px;
}
.progress-wrap {
  display: flex;
  align-items: center;
  gap: 16px;
}
.eta {
  color: rgba(0, 0, 0, 0.45);
}
.tips {
  margin-top: 6px;
  color: rgba(0, 0, 0, 0.45);
}
</style>
