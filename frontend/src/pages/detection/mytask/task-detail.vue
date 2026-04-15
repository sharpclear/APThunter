<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'
import { getApiBase } from '~/utils/api-public'

interface MaliciousResultItem {
  域名: string
  预测标签: number
  预测结果: string
}

interface PhishingResultItem {
  钓鱼域名: string
  目标域名: string
  公司名称: string
  相似度: string
  匹配类型: string
}

interface MaliciousStatistics {
  总域名数?: string | number
  恶意域名数?: string | number
  正常域名数?: string | number
  恶意域名占比?: string
}

interface PhishingStatistics {
  总域名数?: string | number
  钓鱼域名数?: string | number
  正常域名数?: string | number
  钓鱼域名占比?: string
}

type ResultItem = MaliciousResultItem | PhishingResultItem
type Statistics = MaliciousStatistics | PhishingStatistics

interface ResultData {
  task_id: string
  task_type: string
  statistics: Statistics
  results: ResultItem[]
  malicious_domains?: ResultItem[]
  phishing_domains?: ResultItem[]
  result_filename: string
  total_count: number
  malicious_count?: number
  phishing_count?: number
}

const route = useRoute()
const router = useRouter()
const userId = useUserId()
const token = useAuthorization()
const API_BASE = getApiBase()

const loading = ref(false)
const resultData = ref<ResultData | null>(null)
const taskId = computed(() => route.params.taskId as string)

// 计算列配置
const resultColumns = computed(() => {
  if (resultData.value?.task_type === 'impersonation') {
    // 仿冒域名检测的列
    return [
      {
        title: '钓鱼域名',
        dataIndex: '钓鱼域名',
        key: 'phishing_domain',
        width: '25%',
        ellipsis: true,
      },
      {
        title: '目标域名',
        dataIndex: '目标域名',
        key: 'target_domain',
        width: '25%',
        ellipsis: true,
      },
      {
        title: '公司名称',
        dataIndex: '公司名称',
        key: 'company_name',
        width: '20%',
        ellipsis: true,
      },
      {
        title: '相似度',
        dataIndex: '相似度',
        key: 'similarity',
        width: '15%',
        align: 'center' as const,
      },
      {
        title: '匹配类型',
        dataIndex: '匹配类型',
        key: 'match_type',
        width: '15%',
        align: 'center' as const,
      },
    ]
  } else {
    // 恶意性检测的列
    return [
      {
        title: '域名',
        dataIndex: '域名',
        key: 'domain',
        width: '50%',
        ellipsis: true,
      },
      {
        title: '预测标签',
        dataIndex: '预测标签',
        key: 'label',
        width: '15%',
        align: 'center' as const,
      },
      {
        title: '预测结果',
        dataIndex: '预测结果',
        key: 'result',
        width: '15%',
        align: 'center' as const,
      },
    ]
  }
})

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

async function fetchResult() {
  if (!taskId.value) {
    message.error('任务ID无效')
    router.back()
    return
  }
  
  loading.value = true
  resultData.value = null
  
  try {
    const resp = await fetch(`${API_BASE}/tasks/${taskId.value}/result`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      if (resp.status === 404) {
        message.error('任务不存在或结果未找到')
        router.back()
        return
      }
      const errorText = await resp.text()
      throw new Error(errorText)
    }
    
    const json = await resp.json()
    if (json.ok && json.task_id) {
      resultData.value = json
    } else {
      throw new Error(json.message || '获取结果失败')
    }
  }
  catch (e: any) {
    message.error(`获取结果失败：${e?.message || '未知错误'}`)
    console.error('获取结果错误:', e)
    router.back()
  }
  finally {
    loading.value = false
  }
}

async function handleDownload() {
  if (!taskId.value) return
  
  try {
    loading.value = true
    const resp = await fetch(`${API_BASE}/tasks/${taskId.value}/download`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      throw new Error(await resp.text())
    }
    
    const blob = await resp.blob()
    const disposition = resp.headers.get('content-disposition') || ''
    const match = disposition.match(/filename\*=utf-8''(.+)/i)
    const filename = decodeURIComponent(match?.[1] || resultData.value?.result_filename || `${taskId.value}.xlsx`)
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

onMounted(() => {
  fetchResult()
})
</script>

<template>
  <page-container>
    <a-card :bordered="false">
      <template #title>
        <a-space>
          <a-button type="text" @click="router.back()">
            <template #icon>
              <ArrowLeftOutlined />
            </template>
            返回
          </a-button>
          <span>任务详情 - {{ taskId }}</span>
        </a-space>
      </template>

      <a-spin :spinning="loading">
        <div v-if="resultData">
          <!-- 统计卡片 -->
          <a-row :gutter="16" style="margin-bottom: 24px;">
            <a-col :xs="24" :sm="12" :md="6">
              <a-card>
                <a-statistic
                  title="总域名数"
                  :value="resultData.statistics['总域名数']"
                  :value-style="{ fontSize: '28px' }"
                />
              </a-card>
            </a-col>
            <a-col :xs="24" :sm="12" :md="6">
              <a-card>
                <a-statistic
                  :title="resultData.task_type === 'impersonation' ? '钓鱼域名' : '恶意域名'"
                  :value="resultData.task_type === 'impersonation'
                    ? resultData.statistics['钓鱼域名数']
                    : resultData.statistics['恶意域名数']"
                  :value-style="{ color: '#cf1322', fontSize: '28px' }"
                />
              </a-card>
            </a-col>
            <a-col :xs="24" :sm="12" :md="6">
              <a-card>
                <a-statistic
                  title="正常域名"
                  :value="resultData.task_type === 'impersonation'
                    ? resultData.statistics['正常域名数']
                    : resultData.statistics['正常域名数']"
                  :value-style="{ color: '#3f8600', fontSize: '28px' }"
                />
              </a-card>
            </a-col>
            <a-col :xs="24" :sm="12" :md="6">
              <a-card>
                <a-statistic
                  :title="resultData.task_type === 'impersonation' ? '钓鱼域名占比' : '恶意域名占比'"
                  :value="resultData.task_type === 'impersonation'
                    ? resultData.statistics['钓鱼域名占比'] || '0%'
                    : resultData.statistics['恶意域名占比'] || '0%'"
                  :value-style="{ fontSize: '28px' }"
                />
              </a-card>
            </a-col>
          </a-row>

          <!-- 结果表格 -->
          <a-card :title="resultData.task_type === 'impersonation' ? '检测结果详情' : '检测结果详情'" style="margin-bottom: 24px;">
            <a-table
              :data-source="resultData.results"
              :columns="resultColumns"
              :pagination="{
                pageSize: 50,
                showSizeChanger: true,
                showQuickJumper: true,
                showTotal: (total: number) => `共 ${total} 条记录`,
                pageSizeOptions: ['20', '50', '100', '200']
              }"
              size="middle"
              :row-key="resultData.task_type === 'impersonation' ? '钓鱼域名' : '域名'"
              :scroll="{ y: 500 }"
              bordered
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'result'">
                  <a-tag :color="record['预测结果'] === '恶意' ? 'red' : 'green'">
                    {{ record['预测结果'] }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'label'">
                  <a-tag :color="record['预测标签'] === 1 ? 'red' : 'green'">
                    {{ record['预测标签'] }}
                  </a-tag>
                </template>
              </template>
            </a-table>
          </a-card>

          <!-- 恶意/钓鱼域名列表（如果有） -->
          <a-card
            v-if="(resultData.task_type === 'malicious' && resultData.malicious_domains && resultData.malicious_domains.length > 0) ||
                  (resultData.task_type === 'impersonation' && resultData.phishing_domains && resultData.phishing_domains.length > 0)"
            :title="resultData.task_type === 'impersonation' ? '钓鱼域名列表' : '恶意域名列表'"
            style="margin-bottom: 24px;"
          >
            <a-list
              :data-source="resultData.task_type === 'impersonation' ? resultData.phishing_domains : resultData.malicious_domains"
              :pagination="{ pageSize: 20, showSizeChanger: true }"
              size="large"
              bordered
            >
              <template #renderItem="{ item }">
                <a-list-item>
                  <a-list-item-meta>
                    <template #title>
                      <span style="color: #cf1322; font-weight: bold; font-size: 16px;">
                        {{ resultData.task_type === 'impersonation' ? item.钓鱼域名 : item.域名 }}
                      </span>
                    </template>
                    <template v-if="resultData.task_type === 'impersonation'" #description>
                      <div>
                        <span>目标域名: {{ item.目标域名 }}</span><br>
                        <span>公司: {{ item.公司名称 }}</span> |
                        <span>相似度: {{ item.相似度 }}</span>
                      </div>
                    </template>
                    <template v-else #description>
                      <a-tag color="red">恶意域名</a-tag>
                    </template>
                  </a-list-item-meta>
                </a-list-item>
              </template>
            </a-list>
          </a-card>

          <!-- 操作按钮 -->
          <div style="text-align: center; padding: 16px 0;">
            <a-space size="large">
              <a-button type="primary" size="large" @click="handleDownload">
                <template #icon>
                  <DownloadOutlined />
                </template>
                下载Excel结果
              </a-button>
              <a-button size="large" @click="router.back()">
                返回任务列表
              </a-button>
            </a-space>
          </div>
        </div>
        
        <a-empty v-else-if="!loading" description="暂无结果数据" />
      </a-spin>
    </a-card>
  </page-container>
</template>

<script lang="ts">
import { ArrowLeftOutlined, DownloadOutlined } from '@ant-design/icons-vue'
export default {
  components: {
    ArrowLeftOutlined,
    DownloadOutlined,
  },
}
</script>

<style scoped>
:deep(.ant-statistic-title) {
  font-size: 16px;
  color: #666;
  margin-bottom: 8px;
}
:deep(.ant-card-body) {
  padding: 20px;
}
</style>


