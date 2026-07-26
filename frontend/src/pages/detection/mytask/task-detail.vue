<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'
import { getApiBase } from '~/utils/api-public'

interface AptAttributionFields {
  归因组织?: string
  归因级别?: string
  APT置信度?: number
  强证据数?: number
  归因说明?: string
  APT归因详情?: Record<string, any>
}

interface MaliciousResultItem extends AptAttributionFields {
  域名: string
  预测标签?: number
  预测结果?: string
  判定结果?: string
  恶意类别?: string
  恶意类别标签?: string[]
  命中模块数?: number
  命中详情?: string
  module_hits?: Record<string, any>
  关联组织?: string
  组织置信度?: string
  组织评分?: number
  关联状态?: string
  关联说明?: string
}

interface PhishingResultItem extends AptAttributionFields {
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
  研判原因?: string
  关键特征?: string
}

interface OfficialDomainItem {
  单位名称?: string
  官方域名: string
  置信度?: string | number
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
  APT组织名?: string
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

type ResultItem = (
  MaliciousResultItem
  | PhishingResultItem
  | DgaResultItem
  | HistorySimilarityResultItem
  | AptTemplateNrdResultItem
) & AptAttributionFields
type Statistics = MaliciousStatistics | PhishingStatistics | DgaStatistics | HistorySimilarityStatistics | AptTemplateNrdStatistics

interface ResultData {
  task_id: string
  task_type: string
  unified_detection?: boolean
  focus_impersonation_detection?: boolean
  focus_query_name?: string
  statistics: Statistics
  results: ResultItem[]
  malicious_domains?: ResultItem[]
  unified_malicious_domains?: ResultItem[]
  normal_domains?: ResultItem[]
  phishing_domains?: ResultItem[]
  official_domains?: OfficialDomainItem[]
  dga_domains?: ResultItem[]
  history_similarity_domains?: ResultItem[]
  apt_template_nrd_domains?: ResultItem[]
  result_filename: string
  focus_report_filename?: string
  pdf_report_filename?: string
  word_report_filename?: string
  total_count: number
  malicious_count?: number
  phishing_count?: number
  dga_count?: number
  history_similarity_count?: number
  apt_template_nrd_count?: number
  normal_count?: number
  label_counts?: Record<string, number>
  overlap_counts?: Record<string, number>
  attribution_enabled?: boolean
  attribution_results?: any[]
}

const officialDomainColumns = [
  {
    title: '官方域名',
    dataIndex: '官方域名',
    key: 'official_domain',
    width: '34%',
    ellipsis: true,
  },
  {
    title: '单位名称',
    dataIndex: '单位名称',
    key: 'organization',
    width: '28%',
    ellipsis: true,
  },
  {
    title: '置信度',
    dataIndex: '置信度',
    key: 'confidence',
    width: '14%',
    align: 'center' as const,
  },
  {
    title: '说明',
    dataIndex: '说明',
    key: 'reason',
    width: '24%',
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

const aptAttributionDescriptions = [
  {
    label: '历史IOC直接归因',
    color: 'green',
    description: '待归因域名本身已能沿历史图谱中的IOC证据路径关联到APT组织。',
  },
  {
    label: '基础设施复用归因',
    color: 'blue',
    description: '实时补全的DNS、证书、RDAP、IP情报或Web指纹与历史图谱基础设施发生复用。',
  },
  {
    label: '未归因',
    color: 'default',
    description: '当前历史图谱中没有达到阈值的组织证据路径，需结合更多情报人工研判。',
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
  if (isUnifiedMalicious(resultData.value))
    return '恶意域名'
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
  if (isUnifiedMalicious(data))
    return data.statistics['恶意域名数'] || data.malicious_count || data.unified_malicious_domains?.length || 0
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
  if (isUnifiedMalicious(resultData.value))
    return '恶意域名占比'
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
  if (isUnifiedMalicious(data))
    return data.statistics['恶意域名占比'] || '0%'
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
  return (isUnifiedMalicious(data) && (!!data.unified_malicious_domains?.length || !!data.malicious_domains?.length))
    || (data.task_type === 'malicious' && !!data.malicious_domains?.length)
    || (data.task_type === 'impersonation' && !!data.phishing_domains?.length)
    || (data.task_type === 'dga' && !!data.dga_domains?.length)
    || (data.task_type === 'history_similarity' && !!data.history_similarity_domains?.length)
    || (data.task_type === 'apt_template_nrd' && !!data.apt_template_nrd_domains?.length)
}

function riskListTitle(taskType?: string) {
  if (isUnifiedMalicious(resultData.value))
    return '恶意域名多标签列表'
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
  if (isUnifiedMalicious(data))
    return data.unified_malicious_domains || data.malicious_domains
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

function isUnifiedMalicious(data?: ResultData | null) {
  return !!data?.unified_detection || data?.task_type === 'malicious' && Array.isArray(data.unified_malicious_domains)
}

function hasAptAttribution(item: ResultItem) {
  return !!item.APT归因详情 || item.归因组织 !== undefined
}

function usesAptAttribution(data?: ResultData | null) {
  return !!data && (
    (data.attribution_results || []).some(item => item?.attribution_level !== undefined)
    || (data.results || []).some(item => hasAptAttribution(item))
  )
}

function aptAttributionColor(level?: string) {
  if (level === '历史IOC直接归因')
    return 'green'
  if (level === '基础设施复用归因')
    return 'blue'
  return 'default'
}

function displayAptConfidence(value?: number) {
  const score = Number(value)
  return Number.isFinite(score) ? score.toFixed(4) : '0.0000'
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
        width: '20%',
        ellipsis: true,
      },
      {
        title: 'DGA_score',
        dataIndex: 'DGA_score',
        key: 'dga_score',
        width: '10%',
        align: 'center' as const,
      },
      {
        title: '预测结果',
        dataIndex: '预测结果',
        key: 'result',
        width: '10%',
        align: 'center' as const,
      },
      {
        title: 'DGA家族',
        dataIndex: 'DGA家族',
        key: 'dga_family',
        width: '14%',
        ellipsis: true,
      },
      {
        title: 'APT组织名',
        dataIndex: 'APT组织名',
        key: 'apt_organization_names',
        width: '20%',
        ellipsis: true,
      },
      {
        title: '家族置信度',
        dataIndex: '家族置信度',
        key: 'family_confidence',
        width: '10%',
        align: 'center' as const,
      },
      {
        title: '命中方式',
        dataIndex: '命中方式',
        key: 'hit_type',
        width: '16%',
        ellipsis: true,
      },
    ]
  }
  if (resultData.value?.task_type === 'impersonation') {
    // 仿冒域名检测的列
    const columns = [
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
    if (resultData.value.attribution_enabled) {
      columns.push(
        {
          title: '归因组织',
          dataIndex: '归因组织',
          key: 'apt_attribution',
          width: '16%',
          ellipsis: true,
        },
        {
          title: '归因级别',
          dataIndex: '归因级别',
          key: 'apt_attribution_level',
          width: '14%',
          ellipsis: true,
        },
        {
          title: 'APT置信度',
          dataIndex: 'APT置信度',
          key: 'apt_confidence',
          width: '12%',
          align: 'center' as const,
        },
      )
    }
    return columns
  } else {
    // 兼容旧二分类恶意检测的列
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
    const fallbackFilename = isUnifiedMalicious(resultData.value)
      ? (resultData.value?.result_filename || `${taskId.value}_malicious_domain_report.pdf`)
      : resultData.value?.focus_impersonation_detection
      ? (resultData.value?.focus_report_filename || `${taskId.value}_focus_impersonation_report.pdf`)
      : resultData.value?.task_type === 'impersonation'
      ? (resultData.value?.pdf_report_filename || resultData.value?.word_report_filename || `${taskId.value}_prediction_report.pdf`)
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

          <a-card
            v-if="['malicious', 'impersonation'].includes(resultData.task_type) && resultData.attribution_enabled"
            :title="usesAptAttribution(resultData) ? 'APT归因说明' : '组织关联置信度说明'"
            style="margin-bottom: 24px;"
          >
            <a-list
              :data-source="usesAptAttribution(resultData) ? aptAttributionDescriptions : confidenceDescriptions"
              size="small"
            >
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
                        <div v-if="resultData.attribution_enabled" style="margin-top: 6px;">
                          <template v-if="hasAptAttribution(item) && item.归因组织 !== 'unknown'">
                            <a-tag color="blue">归因组织: {{ item.归因组织 }}</a-tag>
                            <a-tag :color="aptAttributionColor(item.归因级别)">{{ item.归因级别 }}</a-tag>
                            <span>APT置信度: {{ displayAptConfidence(item.APT置信度) }}</span>
                            <span> | 强证据数: {{ item.强证据数 || 0 }}</span>
                          </template>
                          <a-tag v-else>未归因到组织</a-tag>
                        </div>
                      </div>
                    </template>
                    <template v-else-if="resultData.task_type === 'dga'" #description>
                      <a-tag color="red">高置信DGA</a-tag>
                      <span>DGA_score: {{ item.DGA_score }}</span>
                      <span v-if="item.DGA家族"> | DGA家族: {{ item.DGA家族 }}</span>
                      <span v-if="item.家族置信度"> | 家族置信度: {{ item.家族置信度 }}</span>
                      <span v-if="item.APT组织名"> | APT组织名: {{ item.APT组织名 }}</span>
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
                      <template v-if="isUnifiedMalicious(resultData)">
                        <a-tag
                          v-for="label in item.恶意类别标签 || []"
                          :key="`${item.域名}-${label}`"
                          color="red"
                        >
                          {{ label }}
                        </a-tag>
                        <span>命中模块数: {{ item.命中模块数 || (item.恶意类别标签 || []).length }}</span>
                        <div v-if="item.命中详情" style="margin-top: 4px; color: #667085;">
                          {{ item.命中详情 }}
                        </div>
                        <div v-if="resultData.attribution_enabled" style="margin-top: 6px;">
                          <template v-if="hasAptAttribution(item) && item.归因组织 !== 'unknown'">
                            <a-tag color="blue">归因组织: {{ item.归因组织 }}</a-tag>
                            <a-tag :color="aptAttributionColor(item.归因级别)">{{ item.归因级别 }}</a-tag>
                            <span>APT置信度: {{ displayAptConfidence(item.APT置信度) }}</span>
                            <span> | 强证据数: {{ item.强证据数 || 0 }}</span>
                          </template>
                          <a-tag v-else>未归因到组织</a-tag>
                        </div>
                      </template>
                      <template v-else>
                        <a-tag color="red">恶意域名</a-tag>
                        <template v-if="hasAptAttribution(item) && item.归因组织 !== 'unknown'">
                          <a-tag color="blue">{{ item.归因组织 }}</a-tag>
                          <a-tag :color="aptAttributionColor(item.归因级别)">{{ item.归因级别 }}</a-tag>
                          <span>APT置信度: {{ displayAptConfidence(item.APT置信度) }}</span>
                          <span> | 强证据数: {{ item.强证据数 || 0 }}</span>
                          <div v-if="item.归因说明" style="margin-top: 4px; color: #667085;">
                            {{ item.归因说明 }}
                          </div>
                        </template>
                        <template v-else-if="item.关联组织">
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
                          <a-tag>未归因到组织</a-tag>
                        </template>
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
                {{ isUnifiedMalicious(resultData) || resultData.focus_impersonation_detection || ['impersonation', 'history_similarity', 'apt_template_nrd'].includes(resultData.task_type) ? '下载PDF报告' : '下载Excel结果' }}
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
