<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onMounted, ref } from 'vue'

interface TaskItem {
  id: string
  createdAt: string
  taskType: '恶意性检测' | '仿冒域名检测'
  model: string
  dataSource: {
    type: '上传文件' | '新注册域名'
    fileName?: string
    dateRange?: [string, string]
  }
  status: '待执行' | '执行中' | '已完成' | '已取消' | '失败'
  progress?: number
  eta?: string
}

// 加载与数据
const loading = ref(false)
const tableData = ref<TaskItem[]>([])

// 选择与分页
const selectedRowKeys = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(10)

// 筛选条件
const filterTaskType = ref<string | undefined>(undefined)
const filterStatus = ref<string | undefined>(undefined)
const filterDateRange = ref<[string, string] | []>([])
const keyword = ref('')

// 模拟获取任务列表
async function fetchTasks() {
  loading.value = true
  try {
    await new Promise(resolve => setTimeout(resolve, 500))
    // mock 数据
    const now = new Date()
    const fmt = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
    const earlier = (mins: number) => fmt(new Date(now.getTime() - mins * 60 * 1000))
    const later = (mins: number) => fmt(new Date(now.getTime() + mins * 60 * 1000))

    tableData.value = [
      {
        id: 'T202510310001',
        createdAt: earlier(180),
        taskType: '恶意性检测',
        model: '深度检测模型v1',
        dataSource: { type: '上传文件', fileName: 'domains_20251031.csv' },
        status: '已完成',
        progress: 100,
        eta: earlier(120),
      },
      {
        id: 'T202510310002',
        createdAt: earlier(90),
        taskType: '仿冒域名检测',
        model: 'AI快速识别模型',
        dataSource: { type: '新注册域名', dateRange: ['2025-10-30', '2025-10-31'] },
        status: '执行中',
        progress: 48,
        eta: later(30),
      },
      {
        id: 'T202510310003',
        createdAt: earlier(30),
        taskType: '恶意性检测',
        model: '深度检测模型v1',
        dataSource: { type: '上传文件', fileName: 'today_list.txt' },
        status: '待执行',
        progress: 0,
        eta: later(60),
      },
      {
        id: 'T202510310004',
        createdAt: earlier(240),
        taskType: '仿冒域名检测',
        model: 'AI快速识别模型',
        dataSource: { type: '新注册域名', dateRange: ['2025-10-28', '2025-10-30'] },
        status: '失败',
        progress: 0,
        eta: earlier(200),
      },
      {
        id: 'T202510310005',
        createdAt: earlier(15),
        taskType: '恶意性检测',
        model: 'AI快速识别模型',
        dataSource: { type: '上传文件', fileName: 'batch_05.xlsx' },
        status: '待执行',
        progress: 0,
        eta: later(80),
      },
    ]
  }
  catch {
    message.error('任务列表加载失败')
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

// 操作：单条
function cancelTask(record: TaskItem) {
  Modal.confirm({
    title: '确认取消该任务？',
    onOk: async () => {
      try {
        loading.value = true
        await new Promise(resolve => setTimeout(resolve, 600))
        record.status = '已取消'
        record.progress = 0
        message.success('任务已取消')
      }
      catch {
        message.error('取消失败')
      }
      finally {
        loading.value = false
      }
    },
  })
}

function stopTask(record: TaskItem) {
  Modal.confirm({
    title: '确认停止执行？',
    onOk: async () => {
      try {
        loading.value = true
        await new Promise(resolve => setTimeout(resolve, 600))
        record.status = '已取消'
        record.progress = 0
        message.success('已停止任务')
      }
      catch {
        message.error('停止失败')
      }
      finally {
        loading.value = false
      }
    },
  })
}

function deleteTask(record: TaskItem) {
  Modal.confirm({
    title: '确认删除该任务记录？',
    onOk: async () => {
      try {
        loading.value = true
        await new Promise(resolve => setTimeout(resolve, 600))
        tableData.value = tableData.value.filter(d => d.id !== record.id)
        message.success('删除成功')
      }
      catch {
        message.error('删除失败')
      }
      finally {
        loading.value = false
      }
    },
  })
}

async function viewDetail(record: TaskItem) {
  await new Promise(resolve => setTimeout(resolve, 300))
  Modal.info({
    title: `任务 ${record.id} 详情`,
    content: `任务类型：${record.taskType}\n模型：${record.model}\n数据来源：${record.dataSource.type}${record.dataSource.fileName ? ` (${record.dataSource.fileName})` : ''}${record.dataSource.dateRange ? ` (${record.dataSource.dateRange[0]} ~ ${record.dataSource.dateRange[1]})` : ''}`,
  })
}

async function downloadResult(record: TaskItem) {
  try {
    loading.value = true
    await new Promise(resolve => setTimeout(resolve, 800))
    message.success(`结果已开始下载：${record.id}.zip`)
  }
  catch {
    message.error('下载失败')
  }
  finally {
    loading.value = false
  }
}

// 批量操作
function batchCancel() {
  if (!selectedRowKeys.value.length)
    return message.warning('请选择要取消的任务')
  Modal.confirm({
    title: `确认取消选中的 ${selectedRowKeys.value.length} 个任务？`,
    onOk: async () => {
      try {
        loading.value = true
        await new Promise(resolve => setTimeout(resolve, 800))
        tableData.value = tableData.value.map((d) => {
          if (selectedRowKeys.value.includes(d.id) && d.status === '待执行')
            return { ...d, status: '已取消', progress: 0 }
          return d
        })
        selectedRowKeys.value = []
        message.success('批量取消完成')
      }
      catch {
        message.error('批量取消失败')
      }
      finally {
        loading.value = false
      }
    },
  })
}

function batchDelete() {
  if (!selectedRowKeys.value.length)
    return message.warning('请选择要删除的任务')
  Modal.confirm({
    title: `确认删除选中的 ${selectedRowKeys.value.length} 条记录？`,
    onOk: async () => {
      try {
        loading.value = true
        await new Promise(resolve => setTimeout(resolve, 800))
        tableData.value = tableData.value.filter((d) => {
          if (!selectedRowKeys.value.includes(d.id))
            return true
          return d.status !== '已完成'
        })
        selectedRowKeys.value = []
        message.success('批量删除完成（仅删除已完成任务）')
      }
      catch {
        message.error('批量删除失败')
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
          <a-range-picker v-model:value="filterDateRange" style="width: 260px;" />
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
        <a-button type="default" :disabled="!selectedRowKeys.length" @click="batchCancel">
          批量取消
        </a-button>
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
        <a-table-column key="actions" title="操作" width="260">
          <template #default="{ record }">
            <template v-if="record.status === '待执行'">
              <a-space>
                <a-button size="small" @click="() => cancelTask(record)">
                  取消
                </a-button>
                <a-button size="small" disabled>
                  查看
                </a-button>
                <a-button size="small" disabled>
                  下载
                </a-button>
              </a-space>
            </template>
            <template v-else-if="record.status === '执行中'">
              <a-space>
                <a-button size="small" danger @click="() => stopTask(record)">
                  停止
                </a-button>
                <a-button size="small" @click="() => viewDetail(record)">
                  查看
                </a-button>
                <a-button size="small" disabled>
                  下载
                </a-button>
              </a-space>
            </template>
            <template v-else-if="record.status === '已完成'">
              <a-space>
                <a-button size="small" type="primary" @click="() => downloadResult(record)">
                  下载结果
                </a-button>
                <a-button size="small" @click="() => viewDetail(record)">
                  查看
                </a-button>
                <a-button size="small" danger @click="() => deleteTask(record)">
                  删除
                </a-button>
              </a-space>
            </template>
            <template v-else>
              <a-space>
                <a-button size="small" @click="() => viewDetail(record)">
                  查看
                </a-button>
                <a-button size="small" danger :disabled="record.status !== '已完成'" @click="() => deleteTask(record)">
                  删除
                </a-button>
              </a-space>
            </template>
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
          @show-size-change="(p:number, s:number) => { currentPage = 1; pageSize = s }"
        />
      </div>
    </a-card>
  </page-container>
</template>

<style scoped>
</style>
