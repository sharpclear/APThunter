<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

defineOptions({ name: 'DetectionAlert' })

interface ModelItem {
  id: number
  name: string
  type: 'malicious' | 'phishing'
  description: string
}

interface SubscriptionItem {
  id: string
  modelId: number
  modelName: string
  type: 'malicious' | 'phishing'
  frequency: 'daily' | 'weekly' | 'monthly'
  createdAt: string
  nextRunAt: string
  range: 'week'
  threshold: number
  officialFileName?: string
}

interface AlertRecord {
  id: string
  time: string
  modelName: string
  type: 'malicious' | 'phishing'
  detectedCount: number
  highRiskDomains: string[]
  status: '已处理' | '未处理'
}

const API_BASE = getApiBase()
const loading = ref(false)
const token = useAuthorization()
const userId = useUserId()

const mockModels = ref<ModelItem[]>([])
const modelSearch = ref('')

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

const filteredModels = computed(() => {
  if (!modelSearch.value.trim())
    return mockModels.value
  const k = modelSearch.value.trim().toLowerCase()
  return mockModels.value.filter(m => m.name.toLowerCase().includes(k) || m.description.toLowerCase().includes(k))
})

const selectedModelId = ref<number | null>(null)
const selectedModel = computed(() => mockModels.value.find(m => m.id === selectedModelId.value) || null)

const formRef = ref()
const formState = reactive<{ frequency: 'daily' | 'weekly' | 'monthly' | '', range: 'week', threshold: number, officialFile?: File | null }>(
  { frequency: '', range: 'week', threshold: 60, officialFile: null },
)

const isPhishingModel = computed(() => selectedModel.value?.type === 'phishing')

const subscriptions = ref<SubscriptionItem[]>([])
const subTotal = ref(0)
const subLoading = ref(false)

const alertRecords = ref<AlertRecord[]>([])
const alertTotal = ref(0)
const alertLoading = ref(false)
const alertPage = ref(1)
const alertPageSize = ref(5)

const frequencyOptions = [
  { label: '每天', value: 'daily' },
  { label: '每周', value: 'weekly' },
  { label: '每月', value: 'monthly' },
]

function fmtDate(d: Date) {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function nextRun(from: Date, freq: 'daily' | 'weekly' | 'monthly') {
  const d = new Date(from)
  if (freq === 'daily')
    d.setDate(d.getDate() + 1)
  if (freq === 'weekly')
    d.setDate(d.getDate() + 7)
  if (freq === 'monthly')
    d.setMonth(d.getMonth() + 1)
  return d
}

// 获取可订阅模型列表
async function fetchModels() {
  loading.value = true
  try {
    const resp = await fetch(`${API_BASE}/subscriptions/models`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '获取模型列表失败' }))
      throw new Error(errorData.message || errorData.detail || '获取模型列表失败')
    }
    
    const json = await resp.json()
    if (json.code === 0 && json.data) {
      mockModels.value = json.data.map((item: any) => ({
        id: item.id,
        name: item.name,
        type: item.type,
        description: item.description || '',
      }))
    } else {
      throw new Error(json.message || '获取模型列表失败')
    }
  }
  catch (e: any) {
    message.error(`获取模型列表失败：${e?.message || '未知错误'}`)
  }
  finally {
    loading.value = false
  }
}

// 获取订阅列表
async function fetchSubscriptions() {
  subLoading.value = true
  try {
    const resp = await fetch(`${API_BASE}/subscriptions?page=1&pageSize=100`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '获取订阅列表失败' }))
      throw new Error(errorData.message || errorData.detail || '获取订阅列表失败')
    }
    
    const json = await resp.json()
    if (json.items) {
      subscriptions.value = json.items.map((item: any) => ({
        id: item.id,
        modelId: item.modelId,
        modelName: item.modelName,
        type: item.type,
        frequency: item.frequency,
        createdAt: item.createdAt,
        nextRunAt: item.nextRunAt,
        range: item.range || 'week',
        threshold: item.threshold,
        officialFileName: item.officialFileName,
      }))
      subTotal.value = json.total || 0
    }
  }
  catch (e: any) {
    message.error(`获取订阅列表失败：${e?.message || '未知错误'}`)
  }
  finally {
    subLoading.value = false
  }
}

// 获取预警历史
async function fetchAlerts() {
  alertLoading.value = true
  try {
    const resp = await fetch(`${API_BASE}/alerts?page=${alertPage.value}&pageSize=${alertPageSize.value}`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '获取预警历史失败' }))
      throw new Error(errorData.message || errorData.detail || '获取预警历史失败')
    }
    
    const json = await resp.json()
    if (json.items) {
      alertRecords.value = json.items.map((item: any) => ({
        id: item.id,
        time: item.time,
        modelName: item.modelName,
        type: item.type,
        detectedCount: item.detectedCount,
        highRiskDomains: item.highRiskDomains || [],
        status: item.status,
      }))
      alertTotal.value = json.total || 0
    }
  }
  catch (e: any) {
    message.error(`获取预警历史失败：${e?.message || '未知错误'}`)
  }
  finally {
    alertLoading.value = false
  }
}

// 初始化数据
async function loadData() {
  await Promise.all([
    fetchModels(),
    fetchSubscriptions(),
    fetchAlerts(),
  ])
}

onMounted(loadData)

function resetForm() {
  formState.frequency = ''
  formState.range = 'week'
  formState.threshold = 60
  formState.officialFile = null
}

function handleSelectModel(m: ModelItem) {
  selectedModelId.value = m.id
  resetForm()
}

function beforeUpload(file: File) {
  const ok = file.size <= 5 * 1024 * 1024 && ['csv', 'txt', 'xlsx'].includes(file.name.split('.').pop()!.toLowerCase())
  if (!ok)
    message.error('仅支持 csv/txt/xlsx 且不超过5MB')
  return ok
}

function onUploadChange({ file }: { file: File }) {
  formState.officialFile = file
}

async function handleSubscribe() {
  if (!selectedModel.value) {
    return message.warning('请先选择模型')
  }
  if (!formState.frequency) {
    return message.warning('请选择检测频率')
  }
  if (isPhishingModel.value && !formState.officialFile) {
    return message.warning('请上传官方域名文件')
  }
  subLoading.value = true
  try {
    const formData = new FormData()
    formData.append('modelId', String(selectedModel.value.id))
    formData.append('frequency', formState.frequency)
    formData.append('threshold', String(formState.threshold))
    
    if (isPhishingModel.value && formState.officialFile) {
      formData.append('officialFile', formState.officialFile)
    }
    
    const resp = await fetch(`${API_BASE}/subscriptions`, {
      method: 'POST',
      headers: buildHeaders(),
      body: formData,
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '订阅失败' }))
      throw new Error(errorData.message || errorData.detail || '订阅失败')
    }
    
    const json = await resp.json()
    if (json.ok) {
    message.success('订阅成功')
    resetForm()
      selectedModelId.value = null
      // 刷新订阅列表
      await fetchSubscriptions()
    } else {
      throw new Error(json.message || '订阅失败')
    }
  }
  catch (e: any) {
    message.error(`订阅失败：${e?.message || '未知错误'}`)
  }
  finally {
    subLoading.value = false
  }
}

function findSubscription(id: string) {
  return subscriptions.value.find(s => s.id === id)
}

async function cancelSubscription(record: SubscriptionItem) {
  Modal.confirm({
    title: `确认取消订阅「${record.modelName}」？`,
    onOk: async () => {
      try {
        subLoading.value = true
        const resp = await fetch(`${API_BASE}/subscriptions/${record.id}`, {
          method: 'DELETE',
          headers: buildHeaders(),
        })
        
        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({ message: '取消失败' }))
          throw new Error(errorData.message || errorData.detail || '取消失败')
        }
        
        const json = await resp.json()
        if (json.ok) {
        message.success('已取消订阅')
          // 刷新订阅列表
          await fetchSubscriptions()
        } else {
          throw new Error(json.message || '取消失败')
        }
      }
      catch (e: any) {
        message.error(`取消失败：${e?.message || '未知错误'}`)
      }
      finally {
        subLoading.value = false
      }
    },
  })
}

const editVisible = ref(false)
const editState = reactive<{ id: string | null, frequency: 'daily' | 'weekly' | 'monthly' | '', threshold: number }>(
  { id: null, frequency: '', threshold: 60 },
)

function openEdit(record: SubscriptionItem) {
  editState.id = record.id
  editState.frequency = record.frequency
  editState.threshold = record.threshold
  editVisible.value = true
}

async function submitEdit() {
  if (!editState.id || !editState.frequency) {
    return message.warning('请完善编辑表单')
  }
  subLoading.value = true
  try {
    const formData = new FormData()
    formData.append('frequency', editState.frequency)
    formData.append('threshold', String(editState.threshold))
    
    const resp = await fetch(`${API_BASE}/subscriptions/${editState.id}`, {
      method: 'PUT',
      headers: buildHeaders(),
      body: formData,
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '编辑失败' }))
      throw new Error(errorData.message || errorData.detail || '编辑失败')
    }
    
    const json = await resp.json()
    if (json.ok) {
    editVisible.value = false
    message.success('编辑成功')
      // 刷新订阅列表
      await fetchSubscriptions()
    } else {
      throw new Error(json.message || '编辑失败')
    }
  }
  catch (e: any) {
    message.error(`编辑失败：${e?.message || '未知错误'}`)
  }
  finally {
    subLoading.value = false
  }
}

function viewAlertHistory(record: SubscriptionItem) {
  const list = alertRecords.value.filter(a => a.modelName === record.modelName)
  if (!list.length)
    return message.info('暂无预警记录')
  const text = list.map(a => `${a.time}｜${a.modelName}｜数量:${a.detectedCount}｜高风险:${a.highRiskDomains.join(', ')}`).join('\n')
  Modal.info({ title: '预警历史', content: text })
}

// 监听分页变化，重新获取数据
watch([alertPage, alertPageSize], () => {
  fetchAlerts()
})

// 更新预警状态
async function updateAlertStatus(alertId: string, status: 'pending' | 'processed') {
  try {
    const formData = new FormData()
    formData.append('status', status)
    
    const resp = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
      method: 'PUT',
      headers: buildHeaders(),
      body: formData,
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '更新状态失败' }))
      throw new Error(errorData.message || errorData.detail || '更新状态失败')
    }
    
    const json = await resp.json()
    if (json.ok) {
      message.success('状态已更新')
      // 刷新预警列表
      await fetchAlerts()
    } else {
      throw new Error(json.message || '更新状态失败')
    }
  }
  catch (e: any) {
    message.error(`更新状态失败：${e?.message || '未知错误'}`)
  }
}
</script>

<template>
  <page-container>
    <a-card :bordered="false">
      <h2 style="margin: 0 0 16px 0;">
        订阅与预警
      </h2>

      <a-row :gutter="16" style="align-items: stretch;">
        <a-col :xl="8" :lg="9" :md="24" :sm="24" :xs="24">
          <a-card title="可订阅模型" :loading="loading">
            <a-input-search
              v-model:value="modelSearch"
              placeholder="搜索模型名称或描述"
              allow-clear
              style="margin-bottom:12px;"
            />
            <a-list :data-source="filteredModels" item-layout="horizontal">
              <template #renderItem="{ item }">
                <a-list-item class="ant-list-item">
                  <a-list-item-meta :title="item.name" :description="item.description" />
                  <template #actions>
                    <a-tag :color="item.type === 'malicious' ? 'processing' : 'purple'">
                      {{ item.type === 'malicious' ? '恶意性检测' : '仿冒域名检测' }}
                    </a-tag>
                    <a-button type="link" @click="handleSelectModel(item)">
                      选择
                    </a-button>
                  </template>
                </a-list-item>
              </template>
            </a-list>
          </a-card>
        </a-col>

        <a-col :xl="16" :lg="15" :md="24" :sm="24" :xs="24">
          <a-card :title="selectedModel ? `订阅配置 - ${selectedModel.name}` : '订阅配置'" :loading="loading">
            <a-form ref="formRef" layout="vertical" @submit.prevent>
              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item label="检测频率" :required="true">
                    <a-select v-model:value="formState.frequency" placeholder="请选择检测频率">
                      <a-select-option v-for="opt in frequencyOptions" :key="opt.value" :value="opt.value">
                        {{ opt.label }}
                      </a-select-option>
                    </a-select>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item label="数据范围">
                    <a-input disabled value="近一周新注册域名" />
                  </a-form-item>
                </a-col>
              </a-row>
              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item label="预警阈值（0-100）">
                    <a-slider v-model:value="formState.threshold" :min="0" :max="100" />
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <div style="margin-top: 8px;">
                    当前阈值：<b>{{ formState.threshold }}</b>
                  </div>
                </a-col>
              </a-row>
              <a-form-item v-if="isPhishingModel" label="官方域名文件（仅仿冒检测订阅必填）" :required="true">
                <a-upload-dragger
                  :before-upload="beforeUpload"
                  :show-upload-list="false"
                  accept=".csv,.txt,.xlsx"
                  style="width:100%"
                  @change="onUploadChange"
                >
                  <p class="ant-upload-drag-icon">
                    <i class="iconfont icon-upload-cloud" style="font-size:32px;color:#999;" />
                  </p>
                  <p v-if="formState.officialFile">
                    {{ formState.officialFile.name }}
                  </p>
                  <p v-else>
                    点击或拖拽上传官方域名文件（csv/txt/xlsx 小于5MB）
                  </p>
                </a-upload-dragger>
              </a-form-item>

              <a-space>
                <a-button type="primary" :loading="subLoading" :disabled="!selectedModel" @click="handleSubscribe">
                  订阅
                </a-button>
                <a-button :disabled="!selectedModel" @click="resetForm">
                  重置
                </a-button>
              </a-space>
            </a-form>
          </a-card>
        </a-col>
      </a-row>

      <a-tabs style="margin-top:16px;">
        <a-tab-pane key="subs" tab="我的订阅">
          <a-table
            :data-source="subscriptions"
            row-key="id"
            :loading="subLoading"
            bordered
            size="middle"
            :pagination="{ pageSize: 8 }"
          >
            <a-table-column key="id" title="订阅ID" data-index="id" width="180" />
            <a-table-column key="modelName" title="模型" data-index="modelName" />
            <a-table-column key="type" title="类型" width="140">
              <template #default="{ record }">
                <a-tag :color="record.type === 'malicious' ? 'processing' : 'purple'">
                  {{ record.type === 'malicious' ? '恶意性检测' : '仿冒域名检测' }}
                </a-tag>
              </template>
            </a-table-column>
            <a-table-column key="frequency" title="频率" width="120">
              <template #default="{ record }">
                <span v-if="record.frequency === 'daily'">每天</span>
                <span v-else-if="record.frequency === 'weekly'">每周</span>
                <span v-else>每月</span>
              </template>
            </a-table-column>
            <a-table-column key="threshold" title="阈值" width="100">
              <template #default="{ record }">
                {{ record.threshold }}
              </template>
            </a-table-column>
            <a-table-column key="createdAt" title="创建时间" data-index="createdAt" width="180" />
            <a-table-column key="nextRunAt" title="下次检测" data-index="nextRunAt" width="180" />
            <a-table-column key="actions" title="操作" width="260">
              <template #default="{ record }">
                <a-space>
                  <a-button size="small" @click="() => openEdit(record)">
                    编辑
                  </a-button>
                  <a-button size="small" @click="() => viewAlertHistory(record)">
                    预警历史
                  </a-button>
                  <a-button size="small" danger @click="() => cancelSubscription(record)">
                    取消订阅
                  </a-button>
                </a-space>
              </template>
            </a-table-column>
          </a-table>
        </a-tab-pane>

        <a-tab-pane key="alerts" tab="预警历史">
          <a-table
            :data-source="pagedAlerts"
            row-key="id"
            :loading="alertLoading"
            bordered
            size="middle"
            :pagination="false"
          >
            <a-table-column key="time" title="预警时间" data-index="time" width="180" />
            <a-table-column key="modelName" title="模型" data-index="modelName" />
            <a-table-column key="type" title="类型" width="140">
              <template #default="{ record }">
                <a-tag :color="record.type === 'malicious' ? 'processing' : 'purple'">
                  {{ record.type === 'malicious' ? '恶意性检测' : '仿冒域名检测' }}
                </a-tag>
              </template>
            </a-table-column>
            <a-table-column key="detectedCount" title="检测域名数量" data-index="detectedCount" width="140" />
            <a-table-column key="highRiskDomains" title="高风险域名">
              <template #default="{ record }">
                <a-space wrap>
                  <a-tag v-for="d in record.highRiskDomains" :key="d">
                    {{ d }}
                  </a-tag>
                </a-space>
              </template>
            </a-table-column>
            <a-table-column key="status" title="状态" width="150">
              <template #default="{ record }">
                <a-space>
                <a-tag :color="record.status === '未处理' ? 'orange' : 'green'">
                  {{ record.status }}
                </a-tag>
                  <a-button 
                    v-if="record.status === '未处理'" 
                    size="small" 
                    type="link"
                    @click="() => updateAlertStatus(record.id, 'processed')"
                  >
                    标记为已处理
                  </a-button>
                </a-space>
              </template>
            </a-table-column>
          </a-table>
          <div style="margin-top:12px; display:flex; justify-content:flex-end;">
            <a-pagination
              :current="alertPage"
              :page-size="alertPageSize"
              :total="alertTotal"
              show-size-changer
              show-quick-jumper
              @change="(p:number, s:number) => { alertPage = p; alertPageSize = s }"
              @show-size-change="(p:number, s:number) => { alertPage = 1; alertPageSize = s }"
            />
          </div>
        </a-tab-pane>
      </a-tabs>

      <a-modal v-model:open="editVisible" title="编辑订阅" :confirm-loading="subLoading" @ok="submitEdit">
        <a-form layout="vertical">
          <a-form-item label="检测频率" :required="true">
            <a-select v-model:value="editState.frequency" placeholder="请选择检测频率">
              <a-select-option v-for="opt in frequencyOptions" :key="opt.value" :value="opt.value">
                {{ opt.label }}
              </a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item label="预警阈值（0-100）">
            <a-slider v-model:value="editState.threshold" :min="0" :max="100" />
          </a-form-item>
          <div>当前阈值：<b>{{ editState.threshold }}</b></div>
        </a-form>
      </a-modal>
    </a-card>
  </page-container>
</template>

<style scoped>
</style>
