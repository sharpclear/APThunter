<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, reactive, ref, watch } from 'vue'

type SourceType = 'custom' | 'official' | 'market'
interface ModelItem {
  id: number
  name: string
  type: '恶意性检测' | '仿冒域名检测'
  description: string
  source: SourceType
  accuracy?: number
  createTime: string
  isEditable: boolean
  status?: '启用' | '停用'
}

// 模拟数据，支持本地存储持久化
const STORAGE_KEY = 'my_models_all'
const defaultModels: ModelItem[] = [
  { id: 1, name: '我的检测模型v1', type: '恶意性检测', description: '基于XGBoost训练的恶意域名检测模型', source: 'custom', accuracy: 0.923, createTime: '2024-01-15 12:00', isEditable: true, status: '启用' },
  { id: 2, name: '官方恶意检测Baseline', type: '恶意性检测', description: '官方提供基础模型', source: 'official', accuracy: 0.881, createTime: '2024-02-01 09:00', isEditable: false, status: '启用' },
  { id: 3, name: '市场·高效恶意检测v3', type: '恶意性检测', description: '市场获取模型，Transformer结构', source: 'market', accuracy: 0.941, createTime: '2024-03-10 18:23', isEditable: false, status: '停用' },
  { id: 4, name: '我的仿冒域名识别v2', type: '仿冒域名检测', description: '提升召回率版本', source: 'custom', accuracy: 0.903, createTime: '2024-05-22 14:10', isEditable: true, status: '启用' },
]

function loadStorage<T>(key: string, fallback: T): T {
  try {
    const str = localStorage.getItem(key)
    return str ? (JSON.parse(str) as T) : fallback
  }
  catch {
    return fallback
  }
}
function saveStorage<T>(key: string, data: T) {
  localStorage.setItem(key, JSON.stringify(data))
}

const allModels = ref<ModelItem[]>(loadStorage(STORAGE_KEY, defaultModels))

// 工具栏：搜索与筛选
const keyword = ref('')
const filterType = ref<'全部' | '恶意性检测' | '仿冒域名检测'>('全部')
const filterSource = ref<'全部' | '官方' | '自定义' | '市场获取'>('全部')

// 选中与批量
const selectedRowKeys = ref<number[]>([])

// 行内编辑状态与缓存
const editingIds = ref<Set<number>>(new Set())
const editCache = reactive<Record<number, Pick<ModelItem, 'name' | 'description'>>>({})

// 分页
const pagination = reactive({ current: 1, pageSize: 8 })

const filteredModels = computed<ModelItem[]>(() => {
  let data = [...allModels.value]
  const kw = keyword.value.trim().toLowerCase()
  if (kw) {
    data = data.filter((m: ModelItem) => m.name.toLowerCase().includes(kw) || m.description.toLowerCase().includes(kw))
  }
  if (filterType.value !== '全部') {
    data = data.filter((m: ModelItem) => m.type === filterType.value)
  }
  if (filterSource.value !== '全部') {
    const map: Record<string, SourceType> = { '官方': 'official', '自定义': 'custom', '市场获取': 'market' }
    data = data.filter((m: ModelItem) => m.source === map[filterSource.value])
  }
  return data
})

const pagedModels = computed(() => {
  const start = (pagination.current - 1) * pagination.pageSize
  return filteredModels.value.slice(start, start + pagination.pageSize)
})

watch([filteredModels, () => pagination.pageSize], () => {
  // 过滤变化时，回到第一页
  pagination.current = 1
})

function mapSourceTag(s: SourceType) {
  if (s === 'official')
    return { color: 'blue', text: '官方' }
  if (s === 'custom')
    return { color: 'green', text: '自定义' }
  return { color: 'purple', text: '市场获取' }
}

function startEdit(record: ModelItem) {
  if (!record.isEditable)
    return
  editingIds.value.add(record.id)
  editCache[record.id] = { name: record.name, description: record.description }
}

function cancelEdit(record: ModelItem) {
  editingIds.value.delete(record.id)
  delete editCache[record.id]
}

function saveEdit(record: ModelItem) {
  const cache = editCache[record.id]
  if (!cache)
    return
  const name = (cache.name || '').trim()
  if (!name) {
    message.error('名称不能为空')
    return
  }
  const target = allModels.value.find((m: ModelItem) => m.id === record.id)
  if (target) {
    target.name = name
    target.description = (cache.description || '').trim()
    message.success('已保存修改')
    saveStorage(STORAGE_KEY, allModels.value)
  }
  cancelEdit(record)
}

function removeOne(record: ModelItem) {
  if (record.source !== 'custom')
    return
  Modal.confirm({
    title: '确认删除该模型？',
    content: '删除后无法恢复',
    okText: '删除',
    cancelText: '取消',
    onOk: () => {
      const idx = allModels.value.findIndex(m => m.id === record.id)
      if (idx >= 0) {
        allModels.value.splice(idx, 1)
        message.success('已删除')
        saveStorage(STORAGE_KEY, allModels.value)
      }
    },
  })
}

function batchRemove() {
  const ids = selectedRowKeys.value
  if (!ids.length) {
    message.info('请选择要删除的自定义模型')
    return
  }
  const deletableIds = allModels.value
    .filter((m: ModelItem) => m.source === 'custom' && ids.includes(m.id))
    .map((m: ModelItem) => m.id)
  if (!deletableIds.length) {
    message.info('选中的模型均不可删除')
    return
  }
  Modal.confirm({
    title: '批量删除确认',
    content: `将删除 ${deletableIds.length} 个自定义模型，操作不可恢复`,
    okText: '删除',
    cancelText: '取消',
    onOk: () => {
      allModels.value = allModels.value.filter((m: ModelItem) => !deletableIds.includes(m.id))
      selectedRowKeys.value = []
      message.success('批量删除完成')
      saveStorage(STORAGE_KEY, allModels.value)
    },
  })
}

/* function toggleStatus(record: ModelItem) {
  record.status = record.status === '启用' ? '停用' : '启用'
  saveStorage(STORAGE_KEY, allModels.value)
} */
</script>

<template>
  <div class="my-model-page">
    <a-card :bordered="false">
      <div class="toolbar">
        <a-input-search v-model:value="keyword" allow-clear style="max-width: 320px" placeholder="搜索模型名称/描述" />
        <div class="filters">
          <a-select
            v-model:value="filterType" style="width: 160px" :options="[
              { label: '全部类型', value: '全部' },
              { label: '恶意性检测', value: '恶意性检测' },
              { label: '仿冒域名检测', value: '仿冒域名检测' },
            ]"
          />
          <a-select
            v-model:value="filterSource" style="width: 160px" :options="[
              { label: '全部来源', value: '全部' },
              { label: '官方', value: '官方' },
              { label: '自定义', value: '自定义' },
              { label: '市场获取', value: '市场获取' },
            ]"
          />
          <a-button danger @click="batchRemove">
            批量删除
          </a-button>
        </div>
      </div>

      <a-table
        row-key="id"
        :data-source="pagedModels"
        :pagination="{ current: pagination.current, pageSize: pagination.pageSize, total: filteredModels.length, showSizeChanger: true }"
        :row-selection="{ selectedRowKeys, onChange: (keys:number[]) => { selectedRowKeys = keys } }"
        @change="(p:any) => { pagination.current = p.current; pagination.pageSize = p.pageSize }"
      >
        <a-table-column key="name" title="模型名称">
          <template #default="{ record }">
            <template v-if="editingIds.has(record.id)">
              <a-input v-model:value="editCache[record.id].name" style="max-width: 220px" />
            </template>
            <template v-else>
              {{ record.name }}
            </template>
          </template>
        </a-table-column>
        <a-table-column key="type" title="类型" :custom-render="({ record }: any) => record.type" />
        <a-table-column key="description" title="描述" :width="320">
          <template #default="{ record }">
            <template v-if="editingIds.has(record.id)">
              <a-input v-model:value="editCache[record.id].description" />
            </template>
            <template v-else>
              <a-typography-paragraph :ellipsis="{ rows: 2 }">
                {{ record.description }}
              </a-typography-paragraph>
            </template>
          </template>
        </a-table-column>
        <a-table-column key="source" title="来源">
          <template #default="{ record }">
            <a-tag :color="mapSourceTag(record.source).color">
              {{ mapSourceTag(record.source).text }}
            </a-tag>
          </template>
        </a-table-column>
        <a-table-column key="createTime" title="创建时间" :custom-render="({ record }: any) => record.createTime" />
        <!-- <a-table-column key="status" title="状态">
          <template #default="{ record }">
            <a-switch :checked="record.status==='启用'" @change="() => toggleStatus(record)" />
            <span style="margin-left:8px">{{ record.status }}</span>
          </template>
        </a-table-column> -->
        <a-table-column key="actions" title="操作" :width="200">
          <template #default="{ record }">
            <template v-if="record.isEditable">
              <template v-if="editingIds.has(record.id)">
                <a-space>
                  <a-button type="link" @click="saveEdit(record)">
                    保存
                  </a-button>
                  <a-button type="link" @click="cancelEdit(record)">
                    取消
                  </a-button>
                </a-space>
              </template>
              <template v-else>
                <a-space>
                  <a-button type="link" @click="startEdit(record)">
                    编辑
                  </a-button>
                  <a-popconfirm title="确认删除该模型？" ok-text="删除" cancel-text="取消" @confirm="() => removeOne(record)">
                    <a-button type="link" danger>
                      删除
                    </a-button>
                  </a-popconfirm>
                </a-space>
              </template>
            </template>
            <template v-else>
              <a-typography-text type="secondary">
                不可编辑
              </a-typography-text>
            </template>
          </template>
        </a-table-column>
      </a-table>
    </a-card>
  </div>
</template>

<style scoped>
.my-model-page {
  width: 100%;
}
.toolbar {
  margin-bottom: 12px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.filters {
  display: flex;
  gap: 8px;
  align-items: center;
}
</style>
