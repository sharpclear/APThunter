<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, reactive, ref, watch, onMounted } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { getApiBase } from '~/utils/api-public'

type SourceType = 'custom' | 'official' | 'market'
interface ModelItem {
  id: number
  name: string
  type: '恶意性检测' | '仿冒域名检测' | null
  description: string
  source: SourceType
  createTime: string
  isEditable: boolean
  status?: '启用' | '停用'
}

const API_BASE = getApiBase()
const loading = ref(false)
const allModels = ref<ModelItem[]>([])
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

// 从API获取模型列表
async function fetchModels() {
  loading.value = true
  try {
    const resp = await fetch(`${API_BASE}/models/my-models`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    // 即使返回401，也尝试解析响应（可能包含官方模型数据）
    let json
    try {
      json = await resp.json()
    }
    catch {
      // 如果无法解析JSON，说明是纯文本错误
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${await resp.text()}`)
      }
    }
    
    if (json && json.code === 0 && json.data) {
      // 转换API返回的数据格式为前端需要的格式
      allModels.value = json.data.map((item: any) => ({
        id: item.id,
        name: item.name,
        type: item.type || null,
        description: item.description || '',
        source: item.source,
        createTime: item.createTime,
        isEditable: item.isEditable,
        status: item.status === 'active' ? '启用' : '停用',
      }))
      
      // 如果token过期但返回了数据（官方模型），提示用户重新登录以查看完整列表
      if (!resp.ok && resp.status === 401 && allModels.value.length > 0) {
        message.warning('Token已过期，仅显示官方模型。请重新登录以查看完整列表。')
      }
    }
    else if (!resp.ok) {
      // 如果返回错误且没有数据
      throw new Error(json?.message || json?.detail || `HTTP ${resp.status}`)
    }
    else {
      // 响应格式不正确
      throw new Error(json?.message || '获取模型列表失败')
    }
  }
  catch (e: any) {
    // 只有在完全没有数据时才显示错误
    if (allModels.value.length === 0) {
      message.error(`模型列表加载失败：${e?.message || '未知错误'}`)
    }
    else {
      // 有部分数据但加载出错，只显示警告
      message.warning(`部分数据加载失败：${e?.message || '未知错误'}`)
    }
  }
  finally {
    loading.value = false
  }
}

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

async function saveEdit(record: ModelItem) {
  const cache = editCache[record.id]
  if (!cache)
    return
  const name = (cache.name || '').trim()
  if (!name) {
    message.error('名称不能为空')
    return
  }
  
  try {
    const resp = await fetch(`${API_BASE}/models/${record.id}`, {
      method: 'PUT',
      headers: {
        ...buildHeaders(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
        description: (cache.description || '').trim(),
      }),
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '更新失败' }))
      throw new Error(errorData.message || '更新失败')
    }
    
    const json = await resp.json()
    if (json.code === 0) {
      message.success('已保存修改')
      // 更新本地数据
      const target = allModels.value.find((m: ModelItem) => m.id === record.id)
      if (target) {
        target.name = name
        target.description = (cache.description || '').trim()
      }
      cancelEdit(record)
    }
    else {
      throw new Error(json.message || '更新失败')
    }
  }
  catch (e: any) {
    message.error(`保存失败：${e?.message || '未知错误'}`)
  }
}

function removeOne(record: ModelItem) {
  if (record.source !== 'custom' || !record.isEditable)
    return
  Modal.confirm({
    title: '确认删除该模型？',
    content: '删除后无法恢复',
    okText: '删除',
    cancelText: '取消',
    onOk: async () => {
      try {
        const resp = await fetch(`${API_BASE}/models/${record.id}`, {
          method: 'DELETE',
          headers: buildHeaders(),
        })
        
        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({ message: '删除失败' }))
          throw new Error(errorData.message || '删除失败')
        }
        
        const json = await resp.json()
        if (json.code === 0) {
          message.success('已删除')
          // 刷新列表以获取最新数据
          await fetchModels()
        }
        else {
          throw new Error(json.message || '删除失败')
        }
      }
      catch (e: any) {
        message.error(`删除失败：${e?.message || '未知错误'}`)
      }
    },
  })
}

async function batchRemove() {
  const ids = selectedRowKeys.value
  if (!ids.length) {
    message.info('请选择要删除的自定义模型')
    return
  }
  const deletableIds = allModels.value
    .filter((m: ModelItem) => m.source === 'custom' && m.isEditable && ids.includes(m.id))
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
    onOk: async () => {
      try {
        // 批量删除
        const deletePromises = deletableIds.map(id =>
          fetch(`${API_BASE}/models/${id}`, {
            method: 'DELETE',
            headers: buildHeaders(),
          }),
        )
        const results = await Promise.allSettled(deletePromises)
        
        const successCount = results.filter(r => r.status === 'fulfilled').length
        const failedCount = results.length - successCount
        
        if (failedCount === 0) {
          message.success(`批量删除完成，已删除 ${successCount} 个模型`)
          // 从列表中移除已删除的模型
          allModels.value = allModels.value.filter((m: ModelItem) => !deletableIds.includes(m.id))
          selectedRowKeys.value = []
        }
        else {
          message.warning(`部分删除失败：成功 ${successCount} 个，失败 ${failedCount} 个`)
          // 刷新列表以同步状态
          await fetchModels()
          selectedRowKeys.value = []
        }
      }
      catch (e: any) {
        message.error(`批量删除失败：${e?.message || '未知错误'}`)
      }
    },
  })
}

// 移除从市场获取的模型
async function removeMarketModel(record: ModelItem) {
  Modal.confirm({
    title: '从我的模型中移除该模型？',
    okText: '移除',
    cancelText: '取消',
    onOk: async () => {
      try {
        const resp = await fetch(`${API_BASE}/models/${record.id}/acquire`, {
          method: 'DELETE',
          headers: buildHeaders(),
        })
        
        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({ message: '移除失败' }))
          throw new Error(errorData.message || '移除失败')
        }
        
        const json = await resp.json()
        if (json.code === 0) {
          message.success('已移除')
          // 刷新列表以获取最新数据
          await fetchModels()
        }
        else {
          throw new Error(json.message || '移除失败')
        }
      }
      catch (e: any) {
        message.error(`移除失败：${e?.message || '未知错误'}`)
      }
    },
  })
}

// 页面加载时获取数据
onMounted(() => {
  fetchModels()
})

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
        :loading="loading"
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
        <a-table-column key="type" title="类型" :custom-render="({ record }: any) => record.type || '-'" />
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
            <template v-else-if="record.source === 'market'">
              <a-popconfirm title="从我的模型中移除该模型？" ok-text="移除" cancel-text="取消" @confirm="() => removeMarketModel(record)">
                <a-button type="link" danger>
                  移除
                </a-button>
              </a-popconfirm>
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
