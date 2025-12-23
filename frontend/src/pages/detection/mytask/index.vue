<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onMounted, ref } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'

interface TaskItem {
  id: string
  createdAt: string
  taskType: '恶意性检测' | '仿冒域名检测'
  model: string
  dataSource: {
    type: '上传文件' | '新注册域名'
    fileName?: string | null
    dateRange?: [string, string]
  }
  status: '待执行' | '执行中' | '已完成' | '失败' | '已取消'
  progress?: number
  eta?: string
  resultFileKey?: string | null
  resultBucket?: string | null
  resultFileName?: string | null
}

const API_BASE = 'http://localhost'

// 加载与数据
const loading = ref(false)
const tableData = ref<TaskItem[]>([])
const token = useAuthorization()
const userId = useUserId()

// 选择与分页
const selectedRowKeys = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(10)

// 筛选条件
const filterTaskType = ref<string | undefined>(undefined)
const filterStatus = ref<string | undefined>(undefined)
const filterDateRange = ref<any[]>([])
const pickerDateRange = computed({
  get: () => filterDateRange.value as any,
  set: (val) => {
    filterDateRange.value = (val ?? []) as any[]
  },
})
const keyword = ref('')

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

// 从服务端获取任务列表
async function fetchTasks() {
  loading.value = true
  try {
    const resp = await fetch(`${API_BASE}/api/tasks`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    if (!resp.ok) {
      throw new Error(await resp.text())
    }
    const json = await resp.json()
    tableData.value = (json.items || []) as TaskItem[]
  }
  catch (e: any) {
    message.error(`任务列表加载失败：${e?.message || '未知错误'}`)
  }
  finally {
    loading.value = false
  }
}

onMounted(fetchTasks)

// 计算筛选与搜索后的数据
const filteredData = computed(() => {
  let data = tableData.value.slice()
  if (filterTaskType.value) {
    data = data.filter(d => d.taskType === filterTaskType.value)
  }
  if (filterStatus.value) {
    data = data.filter(d => d.status === filterStatus.value)
  }
  if (filterDateRange.value && (filterDateRange.value as any[]).length === 2) {
    const [start, end] = filterDateRange.value
    const s = new Date(start as string).getTime()
    const e = new Date(end as string).getTime() + 24 * 60 * 60 * 1000 - 1
    data = data.filter((d) => {
      const t = new Date(d.createdAt).getTime()
      return t >= s && t <= e
    })
  }
  if (keyword.value?.trim()) {
    const k = keyword.value.trim().toLowerCase()
    data = data.filter(d =>
      d.id.toLowerCase().includes(k)
      || d.model.toLowerCase().includes(k)
      || (d.dataSource.fileName?.toLowerCase().includes(k) ?? false),
    )
  }
  return data
})

// 分页后的数据
const pagedData = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  return filteredData.value.slice(start, end)
})

function resetFilters() {
  filterTaskType.value = undefined
  filterStatus.value = undefined
  filterDateRange.value = []
  keyword.value = ''
  currentPage.value = 1
}

function handleSearch() {
  currentPage.value = 1
}

// 行选择（改为函数，避免模板中对 ref 直接赋值）
function onRowSelectChange(keys: (string | number)[]) {
  selectedRowKeys.value = keys as string[]
}

async function deleteTaskById(taskId: string) {
  const resp = await fetch(`${API_BASE}/api/tasks/${taskId}`, {
    method: 'DELETE',
    headers: buildHeaders(),
  })
  if (!resp.ok)
    throw new Error(await resp.text())
}

function confirmDelete(record: TaskItem) {
  Modal.confirm({
    title: `确认删除任务 ${record.id}？`,
    onOk: async () => {
      try {
        loading.value = true
        await deleteTaskById(record.id)
        message.success('删除成功')
        await fetchTasks()
      }
      catch (e: any) {
        message.error(`删除失败：${e?.message || '未知错误'}`)
      }
      finally {
        loading.value = false
      }
    },
  })
}

async function downloadResult(record: TaskItem) {
  if (!record.resultFileKey) {
    return message.warning('该任务暂无可下载的结果')
  }
  try {
    loading.value = true
    const resp = await fetch(`${API_BASE}/api/tasks/${record.id}/download`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    if (!resp.ok) {
      throw new Error(await resp.text())
    }
    const blob = await resp.blob()
    const disposition = resp.headers.get('content-disposition') || ''
    const match = disposition.match(/filename\*=utf-8''(.+)/i)
    const filename = decodeURIComponent(match?.[1] || record.resultFileName || `${record.id}.xlsx`)
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
    message.success('结果开始下载')
  }
  catch (e: any) {
    message.error(`下载失败：${e?.message || '未知错误'}`)
  }
  finally {
    loading.value = false
  }
}

function batchDelete() {
  if (!selectedRowKeys.value.length)
    return message.warning('请选择要删除的任务')
  Modal.confirm({
    title: `确认删除选中的 ${selectedRowKeys.value.length} 个任务？`,
    onOk: async () => {
      try {
        loading.value = true
        await Promise.all(selectedRowKeys.value.map(taskId => deleteTaskById(taskId)))
        selectedRowKeys.value = []
        message.success('批量删除完成')
        await fetchTasks()
      }
      catch (e: any) {
        message.error(`批量删除失败：${e?.message || '未知错误'}`)
      }
      finally {
        loading.value = false
      }
    },
  })
}

function statusTagColor(status: TaskItem['status']) {
  switch (status) {
    case '待执行': return 'default'
    case '执行中': return 'processing'
    case '已完成': return 'success'
    case '已取消': return 'warning'
    case '失败': return 'error'
    default: return 'default'
  }
}
</script>

<template>
  <page-container>
    <a-card :bordered="false">
      <h2 style="margin:0 0 16px 0;">
        我的任务
      </h2>
      <!-- 顶部筛选区 -->
      <a-form layout="inline" style="margin-bottom: 12px;" @submit.prevent>
        <a-form-item label="任务类型">
          <a-select
            v-model:value="filterTaskType"
            allow-clear
            style="width: 180px;"
            placeholder="全部类型"
          >
            <a-select-option value="恶意性检测">
              恶意性检测
            </a-select-option>
            <a-select-option value="仿冒域名检测">
              仿冒域名检测
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="状态">
          <a-select
            v-model:value="filterStatus"
            allow-clear
            style="width: 160px;"
            placeholder="全部状态"
          >
            <a-select-option value="待执行">
              待执行
            </a-select-option>
            <a-select-option value="执行中">
              执行中
            </a-select-option>
            <a-select-option value="已完成">
              已完成
            </a-select-option>
            <a-select-option value="已取消">
              已取消
            </a-select-option>
            <a-select-option value="失败">
              失败
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="时间范围">
          <a-range-picker v-model:value="pickerDateRange" style="width: 260px;" />
        </a-form-item>
        <a-form-item>
          <a-input-search
            v-model:value="keyword"
            allow-clear
            placeholder="搜索任务ID/模型/文件名"
            style="width: 240px;"
            @search="handleSearch"
          />
        </a-form-item>
        <a-form-item>
          <a-space>
            <a-button type="primary" @click="handleSearch">
              查询
            </a-button>
            <a-button @click="resetFilters">
              重置
            </a-button>
          </a-space>
        </a-form-item>
      </a-form>

      <!-- 批量操作工具栏 -->
      <div style="margin-bottom: 8px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <a-button danger :disabled="!selectedRowKeys.length" @click="batchDelete">
          批量删除
        </a-button>
        <span style="color:#888;">已选择 {{ selectedRowKeys.length }} 项</span>
      </div>

      <!-- 表格 -->
      <a-table
        :loading="loading"
        :data-source="pagedData"
        row-key="id"
        :pagination="false"
        :row-selection="{ selectedRowKeys, onChange: onRowSelectChange }"
        bordered
        size="middle"
      >
        <a-table-column key="id" title="任务ID" data-index="id" width="180" />
        <a-table-column key="createdAt" title="创建时间" data-index="createdAt" width="180" />
        <a-table-column key="taskType" title="任务类型" data-index="taskType" width="120" />
        <a-table-column key="model" title="调用模型" data-index="model" width="160" />

        <!-- 数据来源 列，使用插槽替代 custom-render JSX -->
        <a-table-column key="dataSource" title="数据来源">
          <template #default="{ record }">
            <template v-if="record.dataSource.type === '上传文件'">
              {{ record.dataSource.fileName }}
            </template>
            <template v-else>
              {{ record.dataSource.dateRange?.[0] ?? '' }} ~ {{ record.dataSource.dateRange?.[1] ?? '' }}
            </template>
          </template>
        </a-table-column>

        <!-- 状态 列，使用插槽替代 custom-render JSX -->
        <a-table-column key="status" title="状态" width="110">
          <template #default="{ record }">
            <a-tag :color="statusTagColor(record.status)">
              {{ record.status }}
            </a-tag>
          </template>
        </a-table-column>

        <!-- 进度 列，使用插槽替代 custom-render JSX -->
        <a-table-column key="progress" title="进度" width="180">
          <template #default="{ record }">
            <template v-if="record.status === '执行中'">
              <a-progress :percent="record.progress || 0" :status="record.progress && record.progress < 100 ? 'active' : undefined" />
            </template>
            <template v-else-if="record.status === '已完成'">
              <a-progress :percent="100" />
            </template>
            <template v-else>
              -
            </template>
          </template>
        </a-table-column>

        <a-table-column key="eta" title="预期完成时间" data-index="eta" width="180" />

        <!-- 操作 列，使用插槽替代 custom-render JSX -->
        <a-table-column key="actions" title="操作" width="220">
          <template #default="{ record }">
            <a-space>
              <a-button
                size="small"
                type="primary"
                :disabled="record.status !== '已完成' || !record.resultFileKey"
                @click="() => downloadResult(record)"
              >
                下载结果
              </a-button>
              <a-button size="small" danger @click="() => confirmDelete(record)">
                删除
              </a-button>
            </a-space>
          </template>
        </a-table-column>
      </a-table>

      <!-- 分页 -->
      <div style="margin-top: 12px; display:flex; justify-content:flex-end;">
        <a-pagination
          :current="currentPage"
          :page-size="pageSize"
          :total="filteredData.length"
          show-size-changer
          show-quick-jumper
          @change="(p:number, s:number) => { currentPage = p; pageSize = s }"
          @show-size-change="(_p:number, s:number) => { currentPage = 1; pageSize = s }"
        />
      </div>
    </a-card>
  </page-container>
</template>

<style scoped>
</style>
