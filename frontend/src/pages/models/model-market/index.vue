<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'

interface MyModel {
  id: number
  name: string
  type: '恶意性检测' | '仿冒域名检测' | null
  description: string
  createTime: string
  source: 'custom' | 'official' | 'market'
  isPublic: number
  isEditable: boolean
}

interface MarketModel {
  id: number
  name: string
  creator: string
  type: '恶意性检测' | '仿冒域名检测' | null
  description: string
  isAdded: boolean
  createTime: string
}

const API_BASE = 'http://localhost'
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

// 我的模型列表（与我的模型页面一致）
const myModels = ref<MyModel[]>([])
const myModelsLoading = ref(false)

// 模型市场列表
const marketModels = ref<MarketModel[]>([])
const marketModelsLoading = ref(false)

// 可公开的模型列表（用于判断哪些可以公开）
const publishableModelIds = ref<number[]>([])

// 顶部选项卡
const activeTab = ref<'mine' | 'market'>('mine')

// 公开弹窗
const publishModalVisible = ref(false)
const publishingModel = ref<MyModel | null>(null)
const publishForm = reactive({
  description: '',
})

// 获取我的模型列表（与我的模型页面一致）
async function fetchMyModels() {
  myModelsLoading.value = true
  try {
    const resp = await fetch(`${API_BASE}/api/models/my-models`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    let json
    try {
      json = await resp.json()
    }
    catch {
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${await resp.text()}`)
      }
    }
    
    if (json && json.code === 0 && json.data) {
      myModels.value = json.data.map((item: any) => ({
        id: item.id,
        name: item.name,
        type: item.type || null,
        description: item.description || '',
        createTime: item.createTime,
        source: item.source,
        isPublic: item.is_public || 0,
        isEditable: item.isEditable !== undefined ? item.isEditable : false,
      }))
    }
    else if (!resp.ok) {
      throw new Error(json?.message || json?.detail || `HTTP ${resp.status}`)
    }
    else {
      throw new Error(json?.message || '获取模型列表失败')
    }
  }
  catch (e: any) {
    message.error(`加载我的模型失败：${e?.message || '未知错误'}`)
    myModels.value = []
  }
  finally {
    myModelsLoading.value = false
  }
}

// 获取可公开的模型列表
async function fetchPublishableModels() {
  try {
    const resp = await fetch(`${API_BASE}/api/models/publishable`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      return
    }
    
    const json = await resp.json()
    if (json.code === 0 && json.data) {
      publishableModelIds.value = json.data.map((item: any) => item.id)
    }
  }
  catch (e: any) {
    // 静默失败，不影响主流程
    console.error('获取可公开模型列表失败:', e)
  }
}

// 获取模型市场列表
async function fetchMarketModels() {
  marketModelsLoading.value = true
  try {
    const url = new URL(`${API_BASE}/api/models/market`)
    if (searchKeyword.value.trim()) {
      url.searchParams.set('keyword', searchKeyword.value.trim())
    }
    // 根据筛选条件设置category
    if (filterCategory.value === '恶意性检测') {
      url.searchParams.set('category', 'malicious')
    }
    else if (filterCategory.value === '仿冒域名检测') {
      url.searchParams.set('category', 'impersonation')
    }
    // 其他类型不设置category，后端会返回所有类型
    
    const resp = await fetch(url.toString(), {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      const errorText = await resp.text()
      throw new Error(errorText)
    }
    
    const json = await resp.json()
    if (json.code === 0 && json.data) {
      marketModels.value = json.data.map((item: any) => ({
        id: item.id,
        name: item.name,
        creator: item.creator || '未知',
        type: item.type || null,
        description: item.description || '',
        isAdded: item.isAdded || false,
        createTime: item.created_at || item.createTime || '',
      }))
    }
    else {
      throw new Error(json.message || '获取模型市场列表失败')
    }
  }
  catch (e: any) {
    message.error(`加载模型市场失败：${e?.message || '未知错误'}`)
    marketModels.value = []
  }
  finally {
    marketModelsLoading.value = false
  }
}

function openPublish(model: MyModel) {
  publishingModel.value = model
  publishForm.description = model.description || ''
  publishModalVisible.value = true
}

async function confirmPublish() {
  if (!publishingModel.value)
    return
  
  try {
    const resp = await fetch(`${API_BASE}/api/models/${publishingModel.value.id}/publish`, {
      method: 'POST',
      headers: {
        ...buildHeaders(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: publishForm.description.trim(),
      }),
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '发布失败' }))
      throw new Error(errorData.message || '发布失败')
    }
    
    const json = await resp.json()
    if (json.code === 0) {
      message.success('模型已公开到市场')
      publishModalVisible.value = false
      // 刷新列表
      await Promise.all([fetchMyModels(), fetchMarketModels(), fetchPublishableModels()])
    }
    else {
      throw new Error(json.message || '发布失败')
    }
  }
  catch (e: any) {
    message.error(`发布失败：${e?.message || '未知错误'}`)
  }
}

async function revokePublic(model: MyModel) {
  Modal.confirm({
    title: '取消公开该模型？',
    okText: '确定',
    cancelText: '取消',
    onOk: async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/models/${model.id}/unpublish`, {
          method: 'POST',
          headers: buildHeaders(),
        })
        
        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({ message: '取消公开失败' }))
          throw new Error(errorData.message || '取消公开失败')
        }
        
        const json = await resp.json()
        if (json.code === 0) {
          message.success('已取消公开')
          // 刷新列表
          await Promise.all([fetchMyModels(), fetchMarketModels()])
        }
        else {
          throw new Error(json.message || '取消公开失败')
        }
      }
      catch (e: any) {
        message.error(`取消公开失败：${e?.message || '未知错误'}`)
      }
    },
  })
}

// 市场筛选/搜索/排序
const searchKeyword = ref('')
const sortKey = ref<'latest' | 'nameAsc' | 'nameDesc'>('latest')
const filterCategory = ref<'全部' | '恶意性检测' | '仿冒域名检测' | '其他'>('全部')

const filteredMarket = computed(() => {
  let data = [...marketModels.value]
  
  // 按类别筛选
  if (filterCategory.value !== '全部') {
    data = data.filter(m => {
      if (filterCategory.value === '恶意性检测') {
        return m.type === '恶意性检测'
      }
      else if (filterCategory.value === '仿冒域名检测') {
        return m.type === '仿冒域名检测'
      }
      else if (filterCategory.value === '其他') {
        return m.type === null || (m.type !== '恶意性检测' && m.type !== '仿冒域名检测')
      }
      return true
    })
  }
  
  // 前端排序（后端已经按时间排序，这里做二次排序）
  switch (sortKey.value) {
    case 'nameAsc':
      data.sort((a, b) => a.name.localeCompare(b.name))
      break
    case 'nameDesc':
      data.sort((a, b) => b.name.localeCompare(a.name))
      break
    case 'latest':
    default:
      // 保持后端返回的顺序（已按时间排序）
      break
  }
  return data
})

// 添加到我的模型
async function addToMyModels(m: MarketModel) {
  if (m.isAdded)
    return
  
  try {
    const resp = await fetch(`${API_BASE}/api/models/${m.id}/acquire`, {
      method: 'POST',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({ message: '获取失败' }))
      throw new Error(errorData.message || '获取失败')
    }
    
    const json = await resp.json()
    if (json.code === 0) {
      message.success('已添加到我的模型')
      m.isAdded = true
      // 刷新我的模型列表
      await fetchMyModels()
    }
    else {
      throw new Error(json.message || '获取失败')
    }
  }
  catch (e: any) {
    message.error(`获取模型失败：${e?.message || '未知错误'}`)
  }
}

async function removeFromMyModels(m: MarketModel) {
  Modal.confirm({
    title: '从我的模型中移除该模型？',
    okText: '移除',
    cancelText: '取消',
    onOk: async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/models/${m.id}/acquire`, {
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
          m.isAdded = false
          // 刷新我的模型列表
          await fetchMyModels()
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

// 判断模型是否可以公开
// 条件：自定义模型 + 未公开
// 后端会做最终验证（检查是否是用户自己创建的模型）
function canPublish(model: MyModel): boolean {
  // 必须是自定义模型且未公开
  // 如果 isEditable 为 true，说明是用户自己创建的模型，肯定可以发布
  // 如果 isEditable 为 false 但 source 是 'custom'，可能是数据不一致，也允许尝试发布（后端会做最终验证）
  return model.source === 'custom' && model.isPublic === 0
}

// 判断模型是否可以取消公开
// 条件：自定义模型 + 已公开 + 可编辑（属于当前用户）
function canUnpublish(model: MyModel): boolean {
  return model.source === 'custom' && model.isPublic === 1 && model.isEditable
}

// 监听搜索关键词变化，延迟搜索
let searchTimer: ReturnType<typeof setTimeout> | null = null
watch(searchKeyword, () => {
  if (searchTimer) {
    clearTimeout(searchTimer)
  }
  searchTimer = setTimeout(() => {
    if (activeTab.value === 'market') {
      fetchMarketModels()
    }
  }, 500)
})

// 监听筛选类别变化
watch(filterCategory, () => {
  if (activeTab.value === 'market') {
    fetchMarketModels()
  }
})

// 监听选项卡切换
watch(activeTab, (newTab) => {
  if (newTab === 'mine') {
    fetchMyModels()
    fetchPublishableModels()
  }
  else if (newTab === 'market') {
    fetchMarketModels()
  }
})

onMounted(() => {
  fetchMyModels()
  fetchPublishableModels()
  fetchMarketModels()
})

function mapTypeLabel(t: '恶意性检测' | '仿冒域名检测' | null) {
  return t || '未知类型'
}
</script>

<template>
  <div class="model-market-page">
    <a-row :gutter="16">
      <a-col :span="5">
        <a-card title="筛选与排序" :bordered="false">
          <div class="side-block">
            <div class="label">
              模型类型
            </div>
            <a-radio-group v-model:value="filterCategory" @change="fetchMarketModels">
              <a-radio-button value="全部">
                全部
              </a-radio-button>
              <a-radio-button value="恶意性检测">
                恶意性检测
              </a-radio-button>
              <a-radio-button value="仿冒域名检测">
                仿冒域名检测
              </a-radio-button>
              <a-radio-button value="其他">
                其他
              </a-radio-button>
            </a-radio-group>
          </div>
          <div class="side-block">
            <div class="label">
              排序方式
            </div>
            <a-radio-group v-model:value="sortKey">
              <a-radio-button value="latest">
                最新
              </a-radio-button>
              <a-radio-button value="nameAsc">
                名称↑
              </a-radio-button>
              <a-radio-button value="nameDesc">
                名称↓
              </a-radio-button>
            </a-radio-group>
          </div>
        </a-card>
      </a-col>

      <a-col :span="19">
        <a-card :bordered="false">
          <a-tabs v-model:active-key="activeTab">
            <a-tab-pane key="mine" tab="我的模型">
              <a-list :data-source="myModels" :loading="myModelsLoading" item-layout="horizontal">
                <template #header>
                  <div class="toolbar">
                    <a-tag color="blue">
                      共 {{ myModels.length }} 个
                    </a-tag>
                  </div>
                </template>
                <template #renderItem="{ item }">
                  <a-list-item>
                    <a-row style="width:100%" :gutter="8" align="middle">
                      <a-col :span="16">
                        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                          <span style="font-weight:600">{{ item.name }}</span>
                          <a-tag v-if="item.type">{{ mapTypeLabel(item.type) }}</a-tag>
                          <a-typography-text type="secondary">
                            {{ item.description || '无描述' }}
                          </a-typography-text>
                        </div>
                        <div style="color:rgba(0,0,0,0.45);margin-top:4px">
                          创建时间：{{ item.createTime }}
                        </div>
                      </a-col>
                      <a-col :span="8" style="text-align:right">
                        <a-tag :color="item.isPublic === 1 ? 'green' : 'default'">
                          {{ item.isPublic === 1 ? '公开' : '私有' }}
                        </a-tag>
                        <a-button v-if="canPublish(item)" type="link" @click="openPublish(item)">
                          公开到市场
                        </a-button>
                        <a-button v-else-if="canUnpublish(item)" type="link" danger @click="revokePublic(item)">
                          取消公开
                        </a-button>
                      </a-col>
                    </a-row>
                  </a-list-item>
                </template>
              </a-list>
            </a-tab-pane>

            <a-tab-pane key="market" tab="模型市场">
              <div class="market-toolbar">
                <a-input-search 
                  v-model:value="searchKeyword" 
                  placeholder="搜索名称/描述/创建者" 
                  allow-clear 
                  style="max-width:360px"
                  @search="fetchMarketModels"
                />
              </div>
              <a-spin :spinning="marketModelsLoading">
                <a-row :gutter="16">
                  <a-col v-for="m in filteredMarket" :key="m.id" :xs="24" :sm="12" :md="8" :lg="8" :xl="6" style="margin-bottom:16px">
                    <a-card :title="m.name" hoverable>
                      <template #extra>
                        <a-tag v-if="m.type">{{ mapTypeLabel(m.type) }}</a-tag>
                      </template>
                      <div class="card-desc">
                        {{ m.description || '无描述' }}
                      </div>
                      <div class="card-meta">
                        创建者：{{ m.creator }}
                      </div>
                      <div class="card-actions">
                        <a-button type="primary" size="small" :disabled="m.isAdded" @click="addToMyModels(m)">
                          {{ m.isAdded ? '已添加' : '添加到我的模型' }}
                        </a-button>
                        <a-button v-if="m.isAdded" size="small" @click="removeFromMyModels(m)">
                          移除
                        </a-button>
                      </div>
                    </a-card>
                  </a-col>
                </a-row>
                <a-empty v-if="!marketModelsLoading && filteredMarket.length === 0" description="没有匹配的模型" />
              </a-spin>
            </a-tab-pane>
          </a-tabs>
        </a-card>
      </a-col>
    </a-row>

    <!-- 发布到市场弹窗 -->
    <a-modal v-model:open="publishModalVisible" title="公开到市场" ok-text="确认公开" cancel-text="取消" @ok="confirmPublish">
      <a-form layout="vertical">
        <a-form-item label="模型名称">
          <a-input :value="publishingModel?.name" disabled />
        </a-form-item>
        <a-form-item label="描述">
          <a-textarea v-model:value="publishForm.description" :rows="3" maxlength="200" show-count placeholder="为你的模型提供简要描述" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.model-market-page {
  width: 100%;
}
.side-block {
  margin-bottom: 16px;
}
.label {
  margin-bottom: 8px;
  color: rgba(0, 0, 0, 0.65);
}
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.market-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.card-desc {
  min-height: 44px;
  color: rgba(0, 0, 0, 0.88);
}
.card-meta {
  margin-top: 8px;
  color: rgba(0, 0, 0, 0.45);
}
.card-actions {
  margin-top: 12px;
  display: flex;
  gap: 8px;
}
</style>
