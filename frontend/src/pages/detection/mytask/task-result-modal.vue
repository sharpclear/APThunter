<script setup lang="ts">
import { ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { useUserId } from '~/composables/user-id'
import { useAuthorization } from '~/composables/authorization'
import { getApiBase } from '~/utils/api-public'

interface MaliciousResultItem {
  域名: string
  预测标签: number
  预测结果: string
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
  钓鱼域名: string
  官方域名: string
  目标域名?: string
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
                :title="resultData.task_type === 'impersonation' ? '钓鱼域名' : '恶意域名'"
                :value="resultData.task_type === 'impersonation'
                  ? resultData.statistics['钓鱼域名数']
                  : resultData.statistics['恶意域名数']"
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
                :title="resultData.task_type === 'impersonation' ? '钓鱼域名占比' : '恶意域名占比'"
                :value="resultData.task_type === 'impersonation'
                  ? resultData.statistics['钓鱼域名占比'] || '0%'
                  : resultData.statistics['恶意域名占比'] || '0%'"
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

        <!-- 恶意/钓鱼域名列表（如果有） -->
        <a-card
          v-if="(resultData.task_type === 'malicious' && resultData.malicious_domains && resultData.malicious_domains.length > 0) ||
                (resultData.task_type === 'impersonation' && resultData.phishing_domains && resultData.phishing_domains.length > 0)"
          :title="resultData.task_type === 'impersonation' ? '钓鱼域名列表' : '恶意域名列表'"
          style="margin-bottom: 16px;"
        >
          <a-list
            :data-source="resultData.task_type === 'impersonation' ? resultData.phishing_domains : resultData.malicious_domains"
            :pagination="{ pageSize: 10, showSizeChanger: true }"
            size="large"
            bordered
          >
            <template #renderItem="{ item }">
              <a-list-item>
                <a-list-item-meta>
                  <template #title>
                    <span style="color: #cf1322; font-weight: bold;">
                      {{ resultData.task_type === 'impersonation' ? item.钓鱼域名 : item.域名 }}
                    </span>
                  </template>
                  <template v-if="resultData.task_type === 'impersonation'" #description>
                    <div>
                      <span>官方域名: {{ item.官方域名 || item.目标域名 }}</span><br>
                      <span>公司: {{ item.公司名称 }}</span> |
                      <span>相似度: {{ item.相似度 }}</span>
                    </div>
                  </template>
                  <template v-else #description>
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
                </a-list-item-meta>
              </a-list-item>
            </template>
          </a-list>
        </a-card>

        <!-- 操作按钮 -->
        <div style="margin-top: 16px; text-align: right;">
          <a-space>
            <a-button type="primary" @click="handleDownload">
              下载Excel
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
