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
  关联组织?: string
  组织置信度?: string
  组织评分?: number
  关联状态?: string
  关联说明?: string
}

interface PhishingResultItem {
  仿冒域名?: string
  钓鱼域名?: string
  官方域名?: string
  目标域名?: string
  官方域名单位名称?: string
  公司名称?: string
  单位类型?: string
  单位小类?: string
  相似度?: string
  匹配类型?: string
  风险等级?: string
  LLM研判标签?: string
  LLM研判分数?: string | number
  LLM处置结果?: string
  研判原因?: string
  关键特征?: string
}

interface OfficialDomainItem {
  单位名称?: string
  官方域名: string
  置信度?: string | number
  来源?: string
  说明?: string
}

interface DgaResultItem {
  域名: string
  规范化域名?: string
  SLD?: string
  DGA_score?: number
  模型候选?: string
  预测标签?: number
  预测结果?: string
  命中方式?: string
  DGA家族?: string
  家族置信度?: string | number
  家族归因状态?: string
  Top1家族?: string
  Top1家族置信度?: string | number
}

interface HistorySimilarityResultItem {
  域名: string
  规范化域名?: string
  匹配历史恶意域名?: string
  综合相似度?: number
  'TF-IDF相似度'?: number
  重排序相似度?: number
  命中原因?: string
  预测标签?: number
  预测结果?: string
}

interface AptTemplateNrdResultItem {
  域名: string
  规范化域名?: string
  注册域名?: string
  score?: number
  risk_level?: string
  风险等级?: string
  匹配模板?: string
  reason?: string
  命中原因?: string
  预测标签?: number
  预测结果?: string
}

interface MaliciousStatistics {
  总域名数?: string | number
  恶意域名数?: string | number
  正常域名数?: string | number
  恶意域名占比?: string
}

interface PhishingStatistics {
  总域名数?: string | number
  算法候选数?: string | number
  仿冒域名数?: string | number
  仿冒域名占比?: string
  钓鱼域名数?: string | number
  正常域名数?: string | number
  钓鱼域名占比?: string
  LLM研判状态?: string
  LLM研判模型?: string
  LLM已研判数?: string | number
}

interface DgaStatistics {
  总域名数?: string | number
  DGA候选数?: string | number
  DGA域名数?: string | number
  高置信DGA域名数?: string | number
  主模型高置信数?: string | number
  家族确认提升数?: string | number
  识别出DGA家族的域名数?: string | number
  识别出的DGA家族种类数?: string | number
  正常域名数?: string | number
  DGA域名占比?: string
}

interface HistorySimilarityStatistics {
  总域名数?: string | number
  历史相似域名数?: string | number
  正常域名数?: string | number
  历史相似域名占比?: string
  历史匹配对数?: string | number
  最低相似度阈值?: string | number
}

interface AptTemplateNrdStatistics {
  总域名数?: string | number
  模板化APT域名数?: string | number
  APT模板命中域名数?: string | number
  高风险域名数?: string | number
  正常域名数?: string | number
  模板化APT域名占比?: string
  APT模板命中域名占比?: string
  高风险域名占比?: string
  预警阈值?: string | number
}

type ResultItem = MaliciousResultItem | PhishingResultItem | DgaResultItem | HistorySimilarityResultItem | AptTemplateNrdResultItem
type Statistics = MaliciousStatistics | PhishingStatistics | DgaStatistics | HistorySimilarityStatistics | AptTemplateNrdStatistics

interface ResultData {
  task_id: string
  task_type: string
  statistics: Statistics
  results: ResultItem[]
  malicious_domains?: ResultItem[]
  phishing_domains?: ResultItem[]
  official_domains?: OfficialDomainItem[]
  dga_domains?: ResultItem[]
  history_similarity_domains?: ResultItem[]
  apt_template_nrd_domains?: ResultItem[]
  result_filename: string
  word_report_filename?: string
  total_count: number
  malicious_count?: number
  phishing_count?: number
  dga_count?: number
  history_similarity_count?: number
  apt_template_nrd_count?: number
  attribution_enabled?: boolean
  attribution_results?: any[]
}

const officialDomainColumns = [
  {
    title: '官方域名',
    dataIndex: '官方域名',
    key: 'official_domain',
    width: '30%',
    ellipsis: true,
  },
  {
    title: '单位名称',
    dataIndex: '单位名称',
    key: 'organization',
    width: '24%',
    ellipsis: true,
  },
  {
    title: '置信度',
    dataIndex: '置信度',
    key: 'confidence',
    width: '12%',
    align: 'center' as const,
  },
  {
    title: '来源',
    dataIndex: '来源',
    key: 'source',
    width: '12%',
    align: 'center' as const,
  },
  {
    title: '说明',
    dataIndex: '说明',
    key: 'reason',
    width: '22%',
    ellipsis: true,
  },
]

const route = useRoute()
const router = useRouter()
const userId = useUserId()
const token = useAuthorization()
const API_BASE = getApiBase()

const loading = ref(false)
const resultData = ref<ResultData | null>(null)
const taskId = computed(() => route.params.taskId as string)

const confidenceLabels: Record<string, string> = {
  high: '高',
  medium: '中',
  low: '低',
  candidate: '候选',
  none: '无',
}

const confidenceDescriptions = [
  {
    label: '高',
    color: 'green',
    description: '多项关联证据一致，组织关联结果可信度较高，可作为优先处置依据。',
  },
  {
    label: '中',
    color: 'blue',
    description: '存在较明确的关联线索，但证据完整度一般，建议结合业务背景进一步复核。',
  },
  {
    label: '低',
    color: 'orange',
    description: '仅命中少量或较弱的关联特征，表示可能存在关联，不宜直接作为最终结论。',
  },
  {
    label: '候选',
    color: 'purple',
    description: '域名进入了关联候选范围，但尚未达到明确匹配条件，需要人工确认。',
  },
  {
    label: '无/未关联',
    color: 'default',
    description: '当前未检索到足够证据指向具体组织，或关联算法未给出有效候选。',
  },
]

const associationStatusColors: Record<string, string> = {
  疑似关联: 'blue',
  候选关联: 'purple',
  多候选不确定: 'orange',
  未关联: 'default',
  关联失败: 'red',
}

function displayConfidence(value?: string) {
  return value ? confidenceLabels[value] || value : '未知'
}

function associationStatusColor(value?: string) {
  return associationStatusColors[value || ''] || 'default'
}

function displayLlmDisposition(item: Partial<PhishingResultItem>) {
  if (item.LLM处置结果)
    return item.LLM处置结果
  const labelMap: Record<string, string> = {
    likely_impersonation: '保留高危告警',
    suspicious_impersonation: '保留人工复核',
    unlikely_impersonation: '建议剔除',
    uncertain: '降低优先级',
    likely_phishing: '保留高危告警',
    suspicious_phishing: '保留人工复核',
    unlikely_phishing: '建议剔除',
  }
  return labelMap[item.LLM研判标签 || ''] || '未知'
}

function displayLlmScore(item: Partial<PhishingResultItem>) {
  return item.LLM研判分数 || '未知'
}

function getImpersonationDomain(item: Partial<PhishingResultItem>) {
  return item.仿冒域名 || item.钓鱼域名 || '未知域名'
}

function getOfficialDomain(item: Partial<PhishingResultItem>) {
  return item.官方域名 || item.目标域名 || '未知'
}

function getOfficialUnitName(item: Partial<PhishingResultItem>) {
  return item.官方域名单位名称 || item.公司名称 || '未知单位'
}

function getUnitType(item: Partial<PhishingResultItem>) {
  return item.单位类型 || item.单位小类 || '未分类'
}

function getRiskLevel(item: Partial<PhishingResultItem>) {
  return item.风险等级 || '未知'
}

function riskLevelColor(level?: string) {
  if (level === '高')
    return 'red'
  if (level === '中')
    return 'orange'
  if (level === '低')
    return 'blue'
  return 'default'
}

function riskStatTitle(taskType?: string) {
  if (taskType === 'impersonation')
    return '仿冒域名'
  if (taskType === 'dga')
    return 'DGA域名'
  if (taskType === 'history_similarity')
    return '历史APT相似域名'
  if (taskType === 'apt_template_nrd')
    return '模板化APT域名'
  return '恶意域名'
}

function riskStatValue(data: ResultData) {
  if (data.task_type === 'impersonation')
    return data.statistics['仿冒域名数'] || data.statistics['钓鱼域名数']
  if (data.task_type === 'dga')
    return data.statistics['DGA域名数']
  if (data.task_type === 'history_similarity')
    return data.statistics['历史相似域名数']
  if (data.task_type === 'apt_template_nrd')
    return data.statistics['高风险域名数'] || data.statistics['模板化APT域名数'] || data.statistics['APT模板命中域名数']
  return data.statistics['恶意域名数']
}

function riskRateTitle(taskType?: string) {
  if (taskType === 'impersonation')
    return '仿冒域名占比'
  if (taskType === 'dga')
    return 'DGA域名占比'
  if (taskType === 'history_similarity')
    return '历史APT相似域名占比'
  if (taskType === 'apt_template_nrd')
    return '高风险域名占比'
  return '恶意域名占比'
}

function riskRateValue(data: ResultData) {
  if (data.task_type === 'impersonation')
    return data.statistics['仿冒域名占比'] || data.statistics['钓鱼域名占比'] || '0%'
  if (data.task_type === 'dga')
    return data.statistics['DGA域名占比'] || '0%'
  if (data.task_type === 'history_similarity')
    return data.statistics['历史相似域名占比'] || '0%'
  if (data.task_type === 'apt_template_nrd')
    return data.statistics['高风险域名占比'] || data.statistics['模板化APT域名占比'] || data.statistics['APT模板命中域名占比'] || '0%'
  return data.statistics['恶意域名占比'] || '0%'
}

function hasRiskDomains(data: ResultData) {
  return (data.task_type === 'malicious' && !!data.malicious_domains?.length)
    || (data.task_type === 'impersonation' && !!data.phishing_domains?.length)
    || (data.task_type === 'dga' && !!data.dga_domains?.length)
    || (data.task_type === 'history_similarity' && !!data.history_similarity_domains?.length)
    || (data.task_type === 'apt_template_nrd' && !!data.apt_template_nrd_domains?.length)
}

function riskListTitle(taskType?: string) {
  if (taskType === 'impersonation')
    return '仿冒域名列表'
  if (taskType === 'dga')
    return 'DGA域名列表'
  if (taskType === 'history_similarity')
    return '历史APT相似域名列表'
  if (taskType === 'apt_template_nrd')
    return '模板化APT域名列表'
  return '恶意域名列表'
}

function riskListData(data: ResultData) {
  if (data.task_type === 'impersonation')
    return data.phishing_domains
  if (data.task_type === 'dga')
    return data.dga_domains
  if (data.task_type === 'history_similarity')
    return data.history_similarity_domains
  if (data.task_type === 'apt_template_nrd')
    return data.apt_template_nrd_domains
  return data.malicious_domains
}

function displaySimilarityScore(item: Partial<HistorySimilarityResultItem>) {
  const score = Number(item.综合相似度)
  if (Number.isNaN(score))
    return '未知'
  return score.toFixed(4)
}

function displayAptScore(item: Partial<AptTemplateNrdResultItem>) {
  const score = Number(item.score)
  if (Number.isNaN(score))
    return '未知'
  return score.toFixed(4)
}

// 计算列配置
const resultColumns = computed(() => {
  if (resultData.value?.task_type === 'apt_template_nrd') {
    return [
      {
        title: '域名',
        dataIndex: '域名',
        key: 'domain',
        width: '22%',
        ellipsis: true,
      },
      {
        title: '风险分',
        dataIndex: 'score',
        key: 'apt_score',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: '风险等级',
        dataIndex: '风险等级',
        key: 'risk_level',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: '匹配模板',
        dataIndex: '匹配模板',
        key: 'matched_template',
        width: '24%',
        ellipsis: true,
      },
      {
        title: '命中原因',
        dataIndex: '命中原因',
        key: 'reason',
        width: '30%',
        ellipsis: true,
      },
    ]
  }
  if (resultData.value?.task_type === 'history_similarity') {
    return [
      {
        title: '域名',
        dataIndex: '域名',
        key: 'domain',
        width: '22%',
        ellipsis: true,
      },
      {
        title: '匹配历史APT域名',
        dataIndex: '匹配历史恶意域名',
        key: 'matched_positive',
        width: '22%',
        ellipsis: true,
      },
      {
        title: '综合相似度',
        dataIndex: '综合相似度',
        key: 'similarity_score',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: '预测结果',
        dataIndex: '预测结果',
        key: 'result',
        width: '14%',
        align: 'center' as const,
      },
      {
        title: '命中原因',
        dataIndex: '命中原因',
        key: 'reason',
        width: '30%',
        ellipsis: true,
      },
    ]
  }
  if (resultData.value?.task_type === 'dga') {
    return [
      {
        title: '域名',
        dataIndex: '域名',
        key: 'domain',
        width: '24%',
        ellipsis: true,
      },
      {
        title: 'DGA_score',
        dataIndex: 'DGA_score',
        key: 'dga_score',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: '预测结果',
        dataIndex: '预测结果',
        key: 'result',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: 'DGA家族',
        dataIndex: 'DGA家族',
        key: 'dga_family',
        width: '16%',
        ellipsis: true,
      },
      {
        title: '家族置信度',
        dataIndex: '家族置信度',
        key: 'family_confidence',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: '命中方式',
        dataIndex: '命中方式',
        key: 'hit_type',
        width: '24%',
        ellipsis: true,
      },
    ]
  }
  if (resultData.value?.task_type === 'impersonation') {
    // 仿冒域名检测的列
    return [
      {
        title: '检测出的仿冒域名',
        dataIndex: '仿冒域名',
        key: 'phishing_domain',
        width: '24%',
        ellipsis: true,
      },
      {
        title: '官方域名',
        dataIndex: '官方域名',
        key: 'target_domain',
        width: '20%',
        ellipsis: true,
      },
      {
        title: '官方域名单位名称',
        dataIndex: '官方域名单位名称',
        key: 'company_name',
        width: '18%',
        ellipsis: true,
      },
      {
        title: '单位类型',
        dataIndex: '单位类型',
        key: 'unit_type',
        width: '12%',
        align: 'center' as const,
      },
      {
        title: '匹配类型',
        dataIndex: '匹配类型',
        key: 'match_type',
        width: '14%',
        ellipsis: true,
      },
      {
        title: '风险等级',
        dataIndex: '风险等级',
        key: 'risk_level',
        width: '12%',
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
      {
        title: '关联组织',
        dataIndex: '关联组织',
        key: 'attribution',
        width: '20%',
        ellipsis: true,
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
    const fallbackFilename = resultData.value?.task_type === 'impersonation'
      ? (resultData.value?.word_report_filename || `${taskId.value}_prediction_report.docx`)
      : (resultData.value?.result_filename || `${taskId.value}.xlsx`)
    const filename = decodeURIComponent(match?.[1] || fallbackFilename)
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
                  :title="riskStatTitle(resultData.task_type)"
                  :value="riskStatValue(resultData)"
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
                  :title="riskRateTitle(resultData.task_type)"
                  :value="riskRateValue(resultData)"
                  :value-style="{ fontSize: '28px' }"
                />
              </a-card>
            </a-col>
          </a-row>

          <a-card v-if="resultData.task_type === 'malicious'" title="组织关联置信度说明" style="margin-bottom: 24px;">
            <a-list :data-source="confidenceDescriptions" size="small">
              <template #renderItem="{ item }">
                <a-list-item>
                  <a-list-item-meta>
                    <template #title>
                      <a-tag :color="item.color">{{ item.label }}</a-tag>
                    </template>
                    <template #description>
                      {{ item.description }}
                    </template>
                  </a-list-item-meta>
                </a-list-item>
              </template>
            </a-list>
          </a-card>

          <a-card
            v-if="resultData.task_type === 'impersonation' && resultData.official_domains && resultData.official_domains.length > 0"
            title="本次使用的官方域名列表"
            style="margin-bottom: 24px;"
          >
            <a-table
              :data-source="resultData.official_domains"
              :columns="officialDomainColumns"
              :pagination="{ pageSize: 10, showSizeChanger: true }"
              row-key="官方域名"
              size="middle"
              bordered
            />
          </a-card>

          <!-- 结果表格 -->
          <a-card v-if="resultData.task_type !== 'malicious'" title="检测结果详情" style="margin-bottom: 24px;">
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
              :row-key="resultData.task_type === 'impersonation' ? '仿冒域名' : '域名'"
              :scroll="{ y: 500 }"
              bordered
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'result'">
                  <a-tag :color="record['预测结果'] === '恶意' || record['预测结果'] === 'DGA-like' || record['预测结果'] === '高置信DGA' || record['预测结果'] === '历史高度相似' || record['预测结果'] === '模板化APT命中' || record['预测结果'] === 'APT模板命中' ? 'red' : 'green'">
                    {{ record['预测结果'] }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'label'">
                  <a-tag :color="record['预测标签'] === 1 ? 'red' : 'green'">
                    {{ record['预测标签'] }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'llm_disposition'">
                  {{ displayLlmDisposition(record) }}
                </template>
                <template v-else-if="column.key === 'llm_score'">
                  {{ displayLlmScore(record) }}
                </template>
              </template>
            </a-table>
          </a-card>

          <!-- 恶意/钓鱼域名列表（如果有） -->
          <a-card
            v-if="hasRiskDomains(resultData)"
            :title="riskListTitle(resultData.task_type)"
            style="margin-bottom: 24px;"
          >
            <a-list
              :data-source="riskListData(resultData)"
              :pagination="{ pageSize: 20, showSizeChanger: true }"
              size="large"
              bordered
            >
              <template #renderItem="{ item }">
                <a-list-item>
                  <a-list-item-meta>
                    <template #title>
                      <span style="color: #cf1322; font-weight: bold; font-size: 16px;">
                        {{ resultData.task_type === 'impersonation' ? getImpersonationDomain(item) : item.域名 }}
                      </span>
                    </template>
                    <template v-if="resultData.task_type === 'impersonation'" #description>
                      <div>
                        <div>官方域名: {{ getOfficialDomain(item) }}</div>
                        <div>官方域名单位名称: {{ getOfficialUnitName(item) }}</div>
                        <span>单位类型: {{ getUnitType(item) }}</span>
                        <span> | 匹配类型: {{ item.匹配类型 || '未知' }}</span>
                        <a-tag :color="riskLevelColor(getRiskLevel(item))">风险等级: {{ getRiskLevel(item) }}</a-tag>
                      </div>
                    </template>
                    <template v-else-if="resultData.task_type === 'dga'" #description>
                      <a-tag color="red">高置信DGA</a-tag>
                      <span>DGA_score: {{ item.DGA_score }}</span>
                      <span v-if="item.DGA家族"> | DGA家族: {{ item.DGA家族 }}</span>
                      <span v-if="item.家族置信度"> | 家族置信度: {{ item.家族置信度 }}</span>
                      <div v-if="item.命中方式" style="margin-top: 4px; color: #667085;">
                        命中方式: {{ item.命中方式 }}
                      </div>
                    </template>
                    <template v-else-if="resultData.task_type === 'history_similarity'" #description>
                      <a-tag color="red">历史APT相似</a-tag>
                      <span>综合相似度: {{ displaySimilarityScore(item) }}</span>
                      <span> | 匹配历史APT域名: {{ item.匹配历史恶意域名 || '未知' }}</span>
                      <div v-if="item.命中原因" style="margin-top: 4px; color: #667085;">
                        命中原因: {{ item.命中原因 }}
                      </div>
                    </template>
                    <template v-else-if="resultData.task_type === 'apt_template_nrd'" #description>
                      <a-tag color="red">模板化APT命中</a-tag>
                      <span>风险分: {{ displayAptScore(item) }}</span>
                      <span> | 风险等级: {{ item.风险等级 || item.risk_level || '未知' }}</span>
                      <span> | 匹配模板: {{ item.匹配模板 || '未知' }}</span>
                      <div v-if="item.命中原因 || item.reason" style="margin-top: 4px; color: #667085;">
                        命中原因: {{ item.命中原因 || item.reason }}
                      </div>
                    </template>
                    <template v-else #description>
                      <a-tag color="red">恶意域名</a-tag>
                      <template v-if="item.关联组织">
                        <a-tag color="blue">{{ item.关联组织 }}</a-tag>
                        <a-tag v-if="item.关联状态" :color="associationStatusColor(item.关联状态)">
                          {{ item.关联状态 }}
                        </a-tag>
                        <span>置信度: {{ displayConfidence(item.组织置信度) }}</span>
                        <span v-if="item.组织评分 !== undefined"> | 评分: {{ item.组织评分 }}</span>
                        <div v-if="item.关联说明" style="margin-top: 4px; color: #667085;">
                          {{ item.关联说明 }}
                        </div>
                      </template>
                      <template v-else-if="resultData.attribution_enabled">
                        <a-tag>未关联到组织</a-tag>
                      </template>
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
                {{ ['history_similarity', 'apt_template_nrd'].includes(resultData.task_type) ? '下载PDF报告' : '下载Excel结果' }}
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
