<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'

interface PreviewRow {
  key: number
  domain: string
  label: number
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
const previewColumns = [
  { title: '域名', dataIndex: 'domain', key: 'domain' },
  { title: '标签', dataIndex: 'label', key: 'label' },
]

const MAX_SIZE_MB = 5
const ACCEPT_TYPES = ['text/csv', 'text/plain']
const ACCEPT_EXTS = ['.csv', '.txt']

function beforeUpload(file: File) {
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
  // 阻止自动上传，改为本地解析
  selectedFile.value = file
  fileList.value = [file as any]
  parsePreview(file)
  return false
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

// 训练模拟
const trainingStatus = ref<'idle' | 'running' | 'paused' | 'completed' | 'stopped'>('idle')
const progress = ref(0)
const intervalId = ref<number | null>(null)
const startTimestamp = ref<number | null>(null)
const lastTick = ref<number | null>(null)

const canStart = computed(() => {
  return (
    trainingStatus.value === 'idle'
    || trainingStatus.value === 'completed'
    || trainingStatus.value === 'stopped'
  )
})

const hasFile = computed(() => !!selectedFile.value)

const estimatedRemaining = computed(() => {
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
  if (!hasFile.value) {
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
  // 模拟提交训练任务
  progress.value = 0
  trainingStatus.value = 'running'
  startTimestamp.value = Date.now()
  lastTick.value = Date.now()
  spawnInterval()
  message.success('训练任务已提交，开始训练')
}

function spawnInterval() {
  clearTick()
  intervalId.value = window.setInterval(() => {
    if (trainingStatus.value !== 'running')
      return
    const now = Date.now()
    const delta = Math.min(4000, Math.max(300, (now - (lastTick.value || now))))
    lastTick.value = now

    // 模拟不同速度推进
    const step = Math.max(0.5, Math.min(4, (delta / 500) * (Math.random() * 2 + 0.5)))
    progress.value = Math.min(100, progress.value + step)

    if (progress.value >= 100) {
      clearTick()
      trainingStatus.value = 'completed'
      buildMockResult()
      message.success('训练完成')
    }
  }, 500)
}

function handlePause() {
  if (trainingStatus.value !== 'running')
    return
  trainingStatus.value = 'paused'
  clearTick()
}

function handleResume() {
  if (trainingStatus.value !== 'paused')
    return
  trainingStatus.value = 'running'
  spawnInterval()
}

function handleStop() {
  if (trainingStatus.value !== 'running' && trainingStatus.value !== 'paused')
    return
  Modal.confirm({
    title: '确认停止训练？',
    content: '停止后可重新启动新的训练任务。',
    okText: '停止',
    cancelText: '取消',
    onOk: () => {
      clearTick()
      trainingStatus.value = 'stopped'
      progress.value = 0
      message.info('训练已停止')
    },
  })
}

function clearTick() {
  if (intervalId.value) {
    clearInterval(intervalId.value)
    intervalId.value = null
  }
}

onBeforeUnmount(() => {
  clearTick()
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

function buildMockResult() {
  resultInfo.modelId = `mdl_${Math.random().toString(36).slice(2, 10)}`
  resultInfo.finishedAt = new Date().toLocaleString()
  // 简单依据参数和数据行数揉一个看起来合理的指标
  const base = 0.8 + Math.random() * 0.15
  resultInfo.metrics.accuracy = Number((base).toFixed(3))
  resultInfo.metrics.precision = Number((base - 0.02 + Math.random() * 0.04).toFixed(3))
  resultInfo.metrics.recall = Number((base - 0.03 + Math.random() * 0.06).toFixed(3))
  const p = resultInfo.metrics.precision
  const r = resultInfo.metrics.recall
  resultInfo.metrics.f1 = Number((2 * p * r / (p + r)).toFixed(3))
  resultVisible.value = true
}

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
                accept=".csv,.xlsx"
                :show-upload-list="{ showRemoveIcon: true }"
                @remove="() => { fileList = []; selectedFile = null; previewData = [] }"
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
