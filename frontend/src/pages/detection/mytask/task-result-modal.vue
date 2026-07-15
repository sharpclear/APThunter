<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'
import { getApiBase } from '~/utils/api-public'

interface MaliciousResultItem {
  域名: string
  预测标签?: number
  预测结果?: string
  判定结果?: string
  恶意类别?: string
  恶意类别标签?: string[]
  命中模块数?: number
  命中详情?: string
  module_hits?: Record<string, any>
  二分类置信度?: number
  关联组织?: string
  组织置信度?: string
  组织评分?: number
  关联状态?: string
  关联说明?: string
  组织关联详情?: AttributionDetail
}

interface AttributionEvidence {
  strength?: 'strong' | 'medium' | 'weak' | string
  category?: 'domain' | 'whois' | 'dns' | 'ssl' | string
  field?: string
  values?: string[]
  score?: number
  description?: string
}

interface AttributionScores {
  final_score?: number
  domain_profile_score?: number
  infra_evidence_score?: number | null
  whois_infra_score?: number
  dns_infra_score?: number
  ssl_cert_score?: number
}

interface AttributionDetail {
  scores?: AttributionScores
  evidence_json?: AttributionEvidence[]
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

interface Props {
  open: boolean
  taskId: string | null
}

const props = defineProps<Props>()
const emit = defineEmits<{
  'update:open': [value: boolean]
  'download': [taskId: string]
}>()

const userId = useUserId()
const token = useAuthorization()
const API_BASE = getApiBase()

const loading = ref(false)
const resultData = ref<ResultData | null>(null)
const expandedEvidenceDomains = ref<string[]>([])

const modalVisible = ref(false)

const UNIT_TYPE_PRIORITY = ['政府', '金融', '教育']
const CHINESE_ORDINALS = ['一', '二', '三', '四', '五', '六', '七', '八', '九', '十']

const impersonationPreviewGroups = computed(() => {
  if (resultData.value?.task_type !== 'impersonation')
    return []
  const items = ((resultData.value.phishing_domains || []) as PhishingResultItem[])
    .filter(item => getImpersonationDomain(item) !== '未知域名')
  const groupMap = new Map<string, PhishingResultItem[]>()
  for (const item of items) {
    const unitType = getUnitType(item)
    const groupItems = groupMap.get(unitType) || []
    groupItems.push(item)
    groupMap.set(unitType, groupItems)
  }
  return Array.from(groupMap.entries())
    .map(([unitType, groupItems]) => ({ unitType, items: groupItems }))
    .sort((left, right) => {
      const leftPriority = UNIT_TYPE_PRIORITY.indexOf(left.unitType)
      const rightPriority = UNIT_TYPE_PRIORITY.indexOf(right.unitType)
      if (leftPriority !== -1 || rightPriority !== -1)
        return (leftPriority === -1 ? 999 : leftPriority) - (rightPriority === -1 ? 999 : rightPriority)
      return right.items.length - left.items.length
    })
})

function chineseOrdinal(index: number) {
  return CHINESE_ORDINALS[index] || `${index + 1}`
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

function displayBinaryConfidence(value?: number) {
  if (value === undefined || value === null || Number.isNaN(Number(value)))
    return '未知'
  return `${(Number(value) * 100).toFixed(2)}%`
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

const evidenceStrengthMeta: Record<string, { label: string, color: string, weight: number }> = {
  strong: { label: '强', color: 'red', weight: 3 },
  medium: { label: '中', color: 'orange', weight: 2 },
  weak: { label: '弱', color: 'default', weight: 1 },
}

const evidenceCategoryLabels: Record<string, string> = {
  domain: '域名相似性',
  whois: 'WHOIS',
  dns: 'DNS',
  ssl: 'SSL',
}

const scoreLabels: Array<{ key: keyof AttributionScores, label: string }> = [
  { key: 'domain_profile_score', label: '域名画像分' },
  { key: 'infra_evidence_score', label: '基础设施分' },
  { key: 'whois_infra_score', label: 'WHOIS 分' },
  { key: 'dns_infra_score', label: 'DNS 分' },
  { key: 'ssl_cert_score', label: 'SSL 分' },
  { key: 'final_score', label: '综合评分' },
]

function getEvidence(item: MaliciousResultItem): AttributionEvidence[] {
  return Array.isArray(item.组织关联详情?.evidence_json)
    ? item.组织关联详情.evidence_json
    : []
}

function getEvidenceStrength(value?: string) {
  return evidenceStrengthMeta[value || ''] || { label: value || '未知', color: 'default', weight: 0 }
}

function formatEvidence(evidence: AttributionEvidence, includeValues = true) {
  const description = evidence.description || '命中关联证据'
  const values = (evidence.values || []).filter(Boolean)
  return includeValues && values.length > 0
    ? `${description}：${values.slice(0, 2).join('、')}${values.length > 2 ? ' 等' : ''}`
    : description
}

function getSummaryEvidence(item: MaliciousResultItem) {
  return [...getEvidence(item)]
    .filter(evidence => !(evidence.field === 'sld_structure' && getEvidenceStrength(evidence.strength).weight <= 1))
    .sort((left, right) => getEvidenceStrength(right.strength).weight - getEvidenceStrength(left.strength).weight)
    .slice(0, 3)
}

function getGroupedEvidence(item: MaliciousResultItem) {
  const grouped = new Map<string, AttributionEvidence[]>()
  for (const evidence of getEvidence(item)) {
    const category = evidence.category || 'other'
    grouped.set(category, [...(grouped.get(category) || []), evidence])
  }
  return [...grouped.entries()].map(([category, evidence]) => ({
    category,
    label: evidenceCategoryLabels[category] || '其他',
    evidence,
  }))
}

function getScoreEntries(item: MaliciousResultItem) {
  const scores = item.组织关联详情?.scores || {}
  return scoreLabels
    .map(({ key, label }) => ({ key, label, value: scores[key] }))
    .filter(entry => entry.value !== undefined && entry.value !== null)
}

function isEvidenceExpanded(domain?: string) {
  return !!domain && expandedEvidenceDomains.value.includes(domain)
}

function toggleEvidence(domain?: string) {
  if (!domain)
    return
  expandedEvidenceDomains.value = isEvidenceExpanded(domain)
    ? expandedEvidenceDomains.value.filter(item => item !== domain)
    : [...expandedEvidenceDomains.value, domain]
}

watch(() => props.open, (val) => {
  modalVisible.value = val
  if (val && props.taskId) {
    expandedEvidenceDomains.value = []
    fetchResult()
  }
})

watch(modalVisible, (val) => {
  emit('update:open', val)
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
  if (!props.taskId) return
  
  loading.value = true
  resultData.value = null
  
  try {
    const resp = await fetch(`${API_BASE}/tasks/${props.taskId}/result`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
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
  }
  finally {
    loading.value = false
  }
}

function handleDownload() {
  if (props.taskId) {
    emit('download', props.taskId)
  }
}

function downloadButtonText() {
  if (isUnifiedMalicious(resultData.value))
    return '下载PDF报告'
  if (resultData.value?.focus_impersonation_detection)
    return '下载PDF报告'
  if (resultData.value?.task_type === 'impersonation')
    return '下载PDF报告'
  if (['history_similarity', 'apt_template_nrd'].includes(resultData.value?.task_type || ''))
    return '下载PDF报告'
  return '下载Excel'
}
</script>

<template>
  <a-modal
    v-model:open="modalVisible"
    title="检测结果"
    width="90%"
    :footer="null"
    :mask-closable="false"
  >
    <a-spin :spinning="loading">
      <div v-if="resultData">
        <!-- 统计卡片 -->
        <a-row :gutter="16" style="margin-bottom: 24px;">
          <a-col :xs="24" :sm="12" :md="6">
            <a-card>
              <a-statistic
                title="总域名数"
                :value="resultData.statistics['总域名数']"
                :value-style="{ fontSize: '24px' }"
              />
            </a-card>
          </a-col>
          <a-col :xs="24" :sm="12" :md="6">
            <a-card>
              <a-statistic
                :title="riskStatTitle(resultData.task_type)"
                :value="riskStatValue(resultData)"
                :value-style="{ color: '#cf1322', fontSize: '24px' }"
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
                :value-style="{ color: '#3f8600', fontSize: '24px' }"
              />
            </a-card>
          </a-col>
          <a-col :xs="24" :sm="12" :md="6">
            <a-card>
              <a-statistic
                :title="riskRateTitle(resultData.task_type)"
                :value="riskRateValue(resultData)"
                :value-style="{ fontSize: '24px' }"
              />
            </a-card>
          </a-col>
        </a-row>

        <a-card v-if="resultData.task_type === 'malicious' && resultData.attribution_enabled" title="组织关联置信度说明" style="margin-bottom: 16px;">
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
          style="margin-bottom: 16px;"
        >
          <a-table
            :data-source="resultData.official_domains"
            :columns="officialDomainColumns"
            :pagination="{ pageSize: 10, showSizeChanger: true }"
            row-key="官方域名"
            size="small"
            bordered
          />
        </a-card>

        <!-- 恶意/钓鱼域名列表（如果有） -->
        <a-card
          v-if="resultData.task_type === 'impersonation' && hasRiskDomains(resultData)"
          title="仿冒域名明细"
          style="margin-bottom: 16px;"
        >
          <div class="impersonation-preview">
            <div class="impersonation-summary-line">检测类型：仿冒域名检测</div>
            <div class="impersonation-summary-line">仿冒域名数量：{{ resultData.phishing_count || resultData.phishing_domains?.length || 0 }}</div>
            <div
              v-for="(group, groupIndex) in impersonationPreviewGroups"
              :key="group.unitType"
              class="impersonation-group"
            >
              <div class="impersonation-group-title">
                {{ chineseOrdinal(groupIndex) }}、单位类型：{{ group.unitType }}
              </div>
              <div
                v-for="(item, itemIndex) in group.items"
                :key="getImpersonationDomain(item)"
                class="impersonation-item"
              >
                <div>{{ itemIndex + 1 }}. 仿冒域名：{{ getImpersonationDomain(item) }}</div>
                <div>官方域名：{{ getOfficialDomain(item) }}</div>
                <div>官方单位名称：{{ getOfficialUnitName(item) }}</div>
                <div>匹配类型：{{ item.匹配类型 || '未知' }}</div>
                <div>
                  风险等级：
                  <a-tag :color="riskLevelColor(getRiskLevel(item))">{{ getRiskLevel(item) }}</a-tag>
                </div>
              </div>
            </div>
          </div>
        </a-card>

        <a-card
          v-else-if="hasRiskDomains(resultData)"
          :title="riskListTitle(resultData.task_type)"
          style="margin-bottom: 16px;"
        >
          <a-list
            :data-source="riskListData(resultData)"
            :pagination="{ pageSize: 10, showSizeChanger: true }"
            size="large"
            bordered
          >
            <template #renderItem="{ item }">
              <a-list-item>
                <a-list-item-meta>
                  <template #title>
                    <span style="color: #cf1322; font-weight: bold;">
                      {{ resultData.task_type === 'impersonation' ? getImpersonationDomain(item) : item.域名 }}
                    </span>
                  </template>
                  <template v-if="resultData.task_type === 'impersonation'" #description>
                    <div>
                      <div>官方域名: {{ getOfficialDomain(item) }}</div>
                      <div>官方域名单位名称: {{ getOfficialUnitName(item) }}</div>
                      <span class="summary-item">单位类型: {{ getUnitType(item) }}</span>
                      <span class="summary-item">匹配类型: {{ item.匹配类型 || '未知' }}</span>
                      <a-tag :color="riskLevelColor(getRiskLevel(item))">风险等级: {{ getRiskLevel(item) }}</a-tag>
                    </div>
                  </template>
                  <template v-else-if="resultData.task_type === 'dga'" #description>
                    <div>
                      <a-tag color="red">高置信DGA</a-tag>
                      <span class="summary-item">DGA_score: {{ item.DGA_score }}</span>
                      <span v-if="item.DGA家族" class="summary-item">DGA家族: {{ item.DGA家族 }}</span>
                      <span v-if="item.家族置信度" class="summary-item">家族置信度: {{ item.家族置信度 }}</span>
                      <div v-if="item.命中方式" style="margin-top: 4px; color: #667085;">
                        命中方式: {{ item.命中方式 }}
                      </div>
                    </div>
                  </template>
                  <template v-else-if="resultData.task_type === 'history_similarity'" #description>
                    <div>
                      <a-tag color="red">历史APT相似</a-tag>
                      <span class="summary-item">综合相似度: {{ displaySimilarityScore(item) }}</span>
                      <span class="summary-item">匹配历史APT域名: {{ item.匹配历史恶意域名 || '未知' }}</span>
                      <div v-if="item.命中原因" style="margin-top: 4px; color: #667085;">
                        命中原因: {{ item.命中原因 }}
                      </div>
                    </div>
                  </template>
                  <template v-else-if="resultData.task_type === 'apt_template_nrd'" #description>
                    <div>
                      <a-tag color="red">模板化APT命中</a-tag>
                      <span class="summary-item">风险分: {{ displayAptScore(item) }}</span>
                      <span class="summary-item">风险等级: {{ item.风险等级 || item.risk_level || '未知' }}</span>
                      <span class="summary-item">匹配模板: {{ item.匹配模板 || '未知' }}</span>
                      <div v-if="item.命中原因 || item.reason" style="margin-top: 4px; color: #667085;">
                        命中原因: {{ item.命中原因 || item.reason }}
                      </div>
                    </div>
                  </template>
                  <template v-else #description>
                    <template v-if="isUnifiedMalicious(resultData)">
                      <div class="malicious-summary">
                        <a-tag
                          v-for="label in item.恶意类别标签 || []"
                          :key="`${item.域名}-${label}`"
                          color="red"
                        >
                          {{ label }}
                        </a-tag>
                        <span class="summary-item">命中模块数: {{ item.命中模块数 || (item.恶意类别标签 || []).length }}</span>
                      </div>
                      <div v-if="item.命中详情" style="margin-top: 4px; color: #667085;">
                        {{ item.命中详情 }}
                      </div>
                    </template>
                    <template v-else>
                      <div class="malicious-summary">
                        <a-tag color="red">恶意域名</a-tag>
                        <template v-if="item.关联组织">
                          <a-tag color="blue">{{ item.关联组织 }}</a-tag>
                          <a-tag v-if="item.关联状态" :color="associationStatusColor(item.关联状态)">
                            {{ item.关联状态 }}
                          </a-tag>
                        </template>
                        <template v-else-if="resultData.attribution_enabled">
                          <a-tag>未关联到组织</a-tag>
                        </template>
                        <span class="summary-item">恶意性置信度: {{ displayBinaryConfidence(item.二分类置信度) }}</span>
                        <template v-if="item.关联组织">
                          <span class="summary-item">组织置信度: {{ displayConfidence(item.组织置信度) }}</span>
                          <span v-if="item.组织评分 !== undefined" class="summary-item">组织评分: {{ item.组织评分 }}</span>
                        </template>
                      </div>
                      <template v-if="item.关联组织">
                        <div v-if="item.关联说明" style="margin-top: 4px; color: #667085;">
                          {{ item.关联说明 }}
                        </div>
                        <div v-if="getSummaryEvidence(item).length > 0" class="evidence-summary">
                          <span class="evidence-summary-label">关联依据：</span>
                          <span
                            v-for="(evidence, index) in getSummaryEvidence(item)"
                            :key="`${item.域名}-summary-${index}`"
                            class="evidence-summary-item"
                          >
                            {{ formatEvidence(evidence) }}
                          </span>
                        </div>
                        <a-button
                          v-if="getEvidence(item).length > 0"
                          type="link"
                          class="evidence-toggle"
                          @click="toggleEvidence(item.域名)"
                        >
                          {{ isEvidenceExpanded(item.域名) ? '收起依据' : '查看依据' }}
                        </a-button>
                        <div v-if="isEvidenceExpanded(item.域名)" class="evidence-panel">
                          <div
                            v-for="group in getGroupedEvidence(item)"
                            :key="`${item.域名}-${group.category}`"
                            class="evidence-group"
                          >
                            <div class="evidence-group-title">{{ group.label }}</div>
                            <div
                              v-for="(evidence, index) in group.evidence"
                              :key="`${item.域名}-${group.category}-${index}`"
                              class="evidence-row"
                            >
                              <a-tag :color="getEvidenceStrength(evidence.strength).color">
                                {{ getEvidenceStrength(evidence.strength).label }}
                              </a-tag>
                              <span>{{ formatEvidence(evidence) }}</span>
                            </div>
                          </div>
                          <div v-if="getScoreEntries(item).length > 0" class="score-grid">
                            <div
                              v-for="entry in getScoreEntries(item)"
                              :key="`${item.域名}-${entry.key}`"
                              class="score-item"
                            >
                              <span>{{ entry.label }}</span>
                              <strong>{{ Number(entry.value).toFixed(2) }}</strong>
                            </div>
                        </div>
                      </div>
                      </template>
                    </template>
                  </template>
                </a-list-item-meta>
              </a-list-item>
            </template>
          </a-list>
        </a-card>

        <!-- 操作按钮 -->
        <div style="margin-top: 16px; text-align: right;">
          <a-space>
            <a-button type="primary" @click="handleDownload">
              {{ downloadButtonText() }}
            </a-button>
            <a-button @click="modalVisible = false">
              关闭
            </a-button>
          </a-space>
        </div>
      </div>
      
      <a-empty v-else-if="!loading" description="暂无结果数据" />
    </a-spin>
  </a-modal>
</template>

<style scoped>
:deep(.ant-statistic-title) {
  font-size: 14px;
  color: #666;
}
:deep(.ant-card-body) {
  padding: 16px;
}
.malicious-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.summary-item {
  color: #475467;
}
.impersonation-preview {
  color: #344054;
  line-height: 1.8;
}
.impersonation-summary-line {
  font-weight: 600;
}
.impersonation-group {
  margin-top: 14px;
}
.impersonation-group-title {
  margin-bottom: 8px;
  color: #101828;
  font-weight: 700;
}
.impersonation-item {
  margin: 8px 0 12px;
  padding: 10px 12px;
  border: 1px solid #eaecf0;
  border-radius: 8px;
  background: #fcfcfd;
}
.evidence-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  margin-top: 8px;
  color: #667085;
}
.evidence-summary-label {
  color: #344054;
  font-weight: 500;
}
.evidence-summary-item {
  padding: 2px 8px;
  border-radius: 999px;
  background: #f2f4f7;
}
.evidence-toggle {
  height: auto;
  padding: 4px 0 0;
}
.evidence-panel {
  margin-top: 8px;
  padding: 12px;
  border: 1px solid #eaecf0;
  border-radius: 8px;
  background: #fcfcfd;
}
.evidence-group + .evidence-group {
  margin-top: 12px;
}
.evidence-group-title {
  margin-bottom: 6px;
  color: #344054;
  font-weight: 600;
}
.evidence-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 6px;
  color: #475467;
}
.score-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 8px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px dashed #d0d5dd;
}
.score-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
  color: #667085;
}
.score-item strong {
  color: #101828;
}
</style>
