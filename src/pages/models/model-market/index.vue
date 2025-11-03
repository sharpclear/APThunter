<script setup lang="ts">
import { message, Modal } from 'ant-design-vue'
import { computed, onMounted, reactive, ref, watch } from 'vue'

type ModelType = 'malicious' | 'phishing' | 'spam' | 'other'

interface MyModel {
  id: number
  name: string
  type: ModelType
  description?: string
  createdAt: string
  isPublic: boolean
  tags?: string[]
  usage?: string
}

interface MarketModel {
  id: number
  name: string
  creator: string
  type: ModelType
  description: string
  isAdded: boolean
}

// 模拟数据（可用本地存储持久化）
const STORAGE_KEYS = {
  MY_MODELS: 'market_my_models',
  MARKET_MODELS: 'market_models',
  ADDED_IDS: 'market_added_ids',
}

const defaultMyModels: MyModel[] = [
  { id: 101, name: '我的恶意检测v1', type: 'malicious', description: '第一版实验模型', createdAt: '2025-10-01 10:20', isPublic: false, tags: ['baseline'], usage: '命令行推理示例...' },
  { id: 102, name: '域名钓鱼识别v2', type: 'phishing', description: '改进召回率', createdAt: '2025-10-12 09:12', isPublic: true, tags: ['recall'], usage: 'HTTP接口示例...' },
]

const defaultMarketModels: MarketModel[] = [
  { id: 1, name: '高效恶意检测v3', creator: '安全研究员A', type: 'malicious', description: '基于Transformer的高精度检测模型', isAdded: false },
  { id: 2, name: '智能钓鱼识别Pro', creator: '蓝队工程师B', type: 'phishing', description: '大规模黑样本训练，抗混淆域名', isAdded: false },
  { id: 3, name: '域名风险综合评估', creator: '安全研究员D', type: 'other', description: '多维度评分融合，解释性强', isAdded: false },
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

const myModels = ref<MyModel[]>(loadStorage<MyModel[]>(STORAGE_KEYS.MY_MODELS, defaultMyModels))
const marketModels = ref<MarketModel[]>(loadStorage<MarketModel[]>(STORAGE_KEYS.MARKET_MODELS, defaultMarketModels))

// 顶部选项卡
const activeTab = ref<'mine' | 'market'>('mine')

// 公开弹窗
const publishModalVisible = ref(false)
const publishingModel = ref<MyModel | null>(null)
const publishForm = reactive({
  description: '',
  tags: [] as string[],
  usage: '',
})

function openPublish(model: MyModel) {
  publishingModel.value = model
  publishForm.description = model.description || ''
  publishForm.tags = model.tags ? [...model.tags] : []
  publishForm.usage = model.usage || ''
  publishModalVisible.value = true
}

function confirmPublish() {
  if (!publishingModel.value)
    return
  const target = myModels.value.find((m: MyModel) => m.id === publishingModel.value!.id)
  if (!target)
    return
  target.isPublic = true
  target.description = publishForm.description
  target.tags = [...publishForm.tags]
  target.usage = publishForm.usage
  publishModalVisible.value = false
  message.success('模型已公开到市场')
  persistAll()
  // 同步到市场（若不存在则添加一条）
  const existed = marketModels.value.some((m: MarketModel) => m.name === target.name)
  if (!existed) {
    marketModels.value.unshift({
      id: Math.floor(Math.random() * 100000) + 1000,
      name: target.name,
      creator: '我',
      type: target.type,
      description: target.description || '无描述',
      isAdded: true,
    })
  }
}

function revokePublic(model: MyModel) {
  Modal.confirm({
    title: '取消公开该模型？',
    okText: '确定',
    cancelText: '取消',
    onOk: () => {
      model.isPublic = false
      persistAll()
      message.success('已取消公开')
    },
  })
}

// 市场筛选/搜索/排序
const searchKeyword = ref('')
const selectedTypes = ref<ModelType[]>([])
const sortKey = ref<'latest' | 'nameAsc' | 'nameDesc'>('latest')

const typeOptions = [
  { label: '恶意检测', value: 'malicious' },
  { label: '钓鱼检测', value: 'phishing' },
  { label: '其他', value: 'other' },
]

const filteredMarket = computed(() => {
  let data = [...marketModels.value]
  if (selectedTypes.value.length) {
    data = data.filter(m => selectedTypes.value.includes(m.type))
  }
  if (searchKeyword.value.trim()) {
    const kw = searchKeyword.value.trim().toLowerCase()
    data = data.filter(
      m => m.name.toLowerCase().includes(kw) || m.description.toLowerCase().includes(kw) || m.creator.toLowerCase().includes(kw),
    )
  }
  switch (sortKey.value) {
    case 'nameAsc':
      data.sort((a, b) => a.name.localeCompare(b.name))
      break
    case 'nameDesc':
      data.sort((a, b) => b.name.localeCompare(a.name))
      break
    case 'latest':
    default:
      data.sort((a, b) => b.id - a.id)
      break
  }
  return data
})

// 添加到我的模型
function addToMyModels(m: MarketModel) {
  if (m.isAdded)
    return
  const newId = Math.floor(Math.random() * 100000) + 2000
  myModels.value.unshift({
    id: newId,
    name: m.name,
    type: m.type,
    description: m.description,
    createdAt: new Date().toLocaleString(),
    isPublic: false,
  })
  m.isAdded = true
  message.success('已添加到我的模型')
  persistAll()
}

function removeFromMyModels(m: MarketModel) {
  Modal.confirm({
    title: '从我的模型中移除该模型？',
    okText: '移除',
    cancelText: '取消',
    onOk: () => {
      const idx = myModels.value.findIndex((x: MyModel) => x.name === m.name)
      if (idx >= 0)
        myModels.value.splice(idx, 1)
      m.isAdded = false
      persistAll()
      message.success('已移除')
    },
  })
}

function persistAll() {
  saveStorage(STORAGE_KEYS.MY_MODELS, myModels.value)
  saveStorage(STORAGE_KEYS.MARKET_MODELS, marketModels.value)
}

watch([myModels, marketModels], () => {
  persistAll()
}, { deep: true })

onMounted(() => {
  // 初次加载时可做一些演示状态同步
})

function mapTypeLabel(t: ModelType) {
  switch (t) {
    case 'malicious': return '恶意检测'
    case 'phishing': return '钓鱼检测'
    case 'spam': return '垃圾检测'
    default: return '其他'
  }
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
            <a-checkbox-group v-model:value="selectedTypes" :options="typeOptions" />
          </div>
          <div class="side-block">
            <div class="label">
              排序
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
              <a-list :data-source="myModels" item-layout="horizontal">
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
                          <a-tag>{{ mapTypeLabel(item.type) }}</a-tag>
                          <a-typography-text type="secondary">
                            {{ item.description || '无描述' }}
                          </a-typography-text>
                        </div>
                        <div style="color:rgba(0,0,0,0.45);margin-top:4px">
                          创建时间：{{ item.createdAt }}
                        </div>
                      </a-col>
                      <a-col :span="8" style="text-align:right">
                        <a-tag :color="item.isPublic ? 'green' : 'default'">
                          {{ item.isPublic ? '公开' : '私有' }}
                        </a-tag>
                        <a-button v-if="!item.isPublic" type="link" @click="openPublish(item)">
                          公开到市场
                        </a-button>
                        <a-button v-else type="link" danger @click="revokePublic(item)">
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
                <a-input-search v-model:value="searchKeyword" placeholder="搜索名称/描述/创建者" allow-clear style="max-width:360px" />
              </div>
              <a-row :gutter="16">
                <a-col v-for="m in filteredMarket" :key="m.id" :xs="24" :sm="12" :md="8" :lg="8" :xl="6" style="margin-bottom:16px">
                  <a-card :title="m.name" hoverable>
                    <template #extra>
                      <a-tag>{{ mapTypeLabel(m.type) }}</a-tag>
                    </template>
                    <div class="card-desc">
                      {{ m.description }}
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
              <a-empty v-if="filteredMarket.length === 0" description="没有匹配的模型" />
            </a-tab-pane>
          </a-tabs>
        </a-card>
      </a-col>
    </a-row>

    <!-- 发布到市场弹窗 -->
    <a-modal v-model:open="publishModalVisible" title="公开到市场" ok-text="确认公开" cancel-text="取消" @ok="confirmPublish">
      <a-form layout="vertical">
        <a-form-item label="描述">
          <a-textarea v-model:value="publishForm.description" :rows="3" maxlength="200" show-count placeholder="为你的模型提供简要描述" />
        </a-form-item>
        <a-form-item label="标签">
          <a-select v-model:value="publishForm.tags" mode="tags" placeholder="输入并回车添加标签" />
        </a-form-item>
        <a-form-item label="使用说明">
          <a-textarea v-model:value="publishForm.usage" :rows="4" maxlength="500" show-count placeholder="简要说明如何使用该模型" />
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
