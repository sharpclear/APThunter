<script setup lang="ts">
import { computed, ref, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { GlobalOutlined, SearchOutlined } from '@ant-design/icons-vue'
import { message, Modal } from 'ant-design-vue'
import type { DomainAttributes, DnsInfo, WhoisInfo, CertificateInfo, DnsRecord, DomainListItem, LookupResult } from '~/api/dashboard/attributes'
import { getDomainListApi, lookupDomainAllApi, queryDomainAttributesApi } from '~/api/dashboard/attributes'

defineOptions({ name: 'DashboardAttributes' })

// 域名输入
const domainInput = ref<string>('')
const loading = ref(false)
const route = useRoute()

const queryErrors = ref<string[]>([])  // 查询错误信息

// 域名列表
const domainList = ref<DomainListItem[]>([])
const domainListLoading = ref(false)
const currentPage = ref(1)
const pageSize = 30
const orgFilterName = ref<string>('')
const orgFilterId = ref<number | null>(null)
const appliedOrgFilterName = ref<string>('')

// 查询结果
const domainData = ref<DomainAttributes | null>(null)
const whoisInfo = ref<WhoisInfo | null>(null)
const dnsInfo = ref<DnsInfo | null>(null)
const certificateInfo = ref<CertificateInfo | null>(null)

function resetDomainDetail() {
  domainData.value = null
  whoisInfo.value = null
  dnsInfo.value = null
  certificateInfo.value = null
}

function applyDomainDetail(data: DomainAttributes, errors: string[] = []) {
  domainData.value = data
  whoisInfo.value = data.whois || null
  dnsInfo.value = data.dns || null
  certificateInfo.value = data.certificate || null
  queryErrors.value = errors
}

function extractErrorPayload(error: any) {
  return error?.response?.data as { code?: number; msg?: string; data?: any } | undefined
}

const sortedDomainList = computed<DomainListItem[]>(() => {
  return [...domainList.value].sort((a, b) => {
    const aHasOrganization = a.organizationId != null && Boolean(a.organizationName)
    const bHasOrganization = b.organizationId != null && Boolean(b.organizationName)
    const organizationPresenceDiff = Number(bHasOrganization) - Number(aHasOrganization)
    if (organizationPresenceDiff !== 0)
      return organizationPresenceDiff

    const maliciousDiff = Number(Boolean(b.isMalicious)) - Number(Boolean(a.isMalicious))
    if (maliciousDiff !== 0)
      return maliciousDiff

    if (aHasOrganization && bHasOrganization) {
      const organizationIdDiff = Number(a.organizationId) - Number(b.organizationId)
      if (organizationIdDiff !== 0)
        return organizationIdDiff
    }

    const timeA = a.createdAt ? new Date(a.createdAt).getTime() : 0
    const timeB = b.createdAt ? new Date(b.createdAt).getTime() : 0
    const timeDiff = timeB - timeA
    if (timeDiff !== 0)
      return timeDiff

    return a.domain.localeCompare(b.domain)
  })
})

const matchedOrganizationNames = computed(() => {
  if (!appliedOrgFilterName.value && orgFilterId.value == null)
    return []

  return Array.from(new Set(
    domainList.value
      .map(item => item.organizationName?.trim())
      .filter((name): name is string => Boolean(name)),
  ))
})

const pagedDomainList = computed<DomainListItem[]>(() => {
  const start = (currentPage.value - 1) * pageSize
  const end = start + pageSize
  return sortedDomainList.value.slice(start, end)
})

function toBool(value: unknown) {
  if (value === true || value === 1 || value === '1')
    return true
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase()
    return normalized === 'true' || normalized === 'yes'
  }
  return false
}

// 按完整域名查询属性；仅在用户点击具体域名或确认实时查询时调用
async function queryExactDomain(domainValue: string) {
  const domain = domainValue.trim()

  if (!domain) {
    message.warning('请输入要查询的域名')
    return
  }

  loading.value = true
  queryErrors.value = []
  try {
    const localResponse = await queryDomainAttributesApi({ domain })
    if (localResponse.code === 200 && localResponse.data) {
      applyDomainDetail(localResponse.data)
      message.success('查询成功')
      return
    }

    const response = await lookupDomainAllApi({
      domain,
      save: true,
    })

    if (response.code === 200 && response.data) {
      const result = response.data as LookupResult
      const hasDetails = !!(result.whois || result.dns || result.certificate)
      if (!hasDetails) {
        resetDomainDetail()
        message.error('未查询到域名详细信息')
        return
      }

      applyDomainDetail({
        domain: result.domain,
        whois: result.whois,
        dns: result.dns,
        certificate: result.certificate,
        queryTime: result.queryTime,
      }, result.errors || [])

      if (result.errors && result.errors.length > 0) {
        message.warning(`查询完成，但部分信息获取失败: ${result.errors.join(', ')}`)
      }
      else {
        message.success('查询成功')
      }

      if (result.saved) {
        await loadDomainList()
      }
    }
    else if (response.code === 404) {
      resetDomainDetail()
      message.error('所有查询均失败，请检查域名是否有效')
    }
    else {
      resetDomainDetail()
      message.error(response.msg || '查询失败')
    }
  }
  catch (error: any) {
    const payload = extractErrorPayload(error)
    if (payload?.code === 404) {
      resetDomainDetail()
      message.error(payload.msg || '所有查询均失败，请检查域名是否有效')
    }
    else if (payload?.msg) {
      resetDomainDetail()
      message.error(payload.msg)
    }
    else {
      resetDomainDetail()
      message.error('查询失败: ' + (error.message || '网络错误'))
    }
  }
  finally {
    loading.value = false
  }
}

// 域名关键词模糊搜索，不要求输入完整域名格式
async function handleQuery() {
  resetDomainDetail()
  queryErrors.value = []
  await loadDomainList()

  if (domainInput.value.trim() && domainList.value.length === 0)
    message.info('未找到匹配的域名')
}

function goBackToList() {
  resetDomainDetail()
  queryErrors.value = []
}

async function handleDatabaseQuery(domain: string) {
  loading.value = true
  queryErrors.value = []
  try {
    const response = await queryDomainAttributesApi({ domain })

    if (response.code === 200 && response.data) {
      applyDomainDetail(response.data)
      message.success('查询成功')
    }
    else if (response.code === 404) {
      resetDomainDetail()
      Modal.confirm({
        title: '未找到本地域名信息',
        content: response.msg || `域名 ${domain} 暂无本地 WHOIS/DNS/SSL 信息，是否发起实时查询？`,
        okText: '实时查询',
        cancelText: '取消',
        onOk: () => queryExactDomain(domain),
      })
    }
    else {
      resetDomainDetail()
      message.error(response.msg || '查询失败')
    }
  }
  catch (error: any) {
    const payload = extractErrorPayload(error)
    if (payload?.code === 404) {
      resetDomainDetail()
      Modal.confirm({
        title: '未找到本地域名信息',
        content: payload.msg || `域名 ${domain} 暂无本地 WHOIS/DNS/SSL 信息，是否发起实时查询？`,
        okText: '实时查询',
        cancelText: '取消',
        onOk: () => queryExactDomain(domain),
      })
    }
    else if (payload?.msg) {
      resetDomainDetail()
      message.error(payload.msg)
    }
    else {
      resetDomainDetail()
      message.error('查询失败: ' + (error.message || '网络错误'))
    }
  }
  finally {
    loading.value = false
  }
}

// 模拟数据（用于演示，实际项目中删除此函数）
function handleMockData(domain: string, showMessage = true) {
  domainData.value = {
    domain,
    queryTime: new Date().toISOString(),
    whois: {
      domain,
      registrar: '示例注册商',
      registrationDate: '2020-01-01',
      expirationDate: '2025-01-01',
      updatedDate: '2023-01-01',
      nameServers: ['ns1.example.com', 'ns2.example.com'],
      registrant: {
        name: '示例注册人',
        organization: '示例组织',
        email: 'example@example.com',
        country: 'CN',
      },
      status: ['clientTransferProhibited', 'clientDeleteProhibited'],
    },
    dns: {
      domain,
      records: [
        { type: 'A', name: domain, value: '192.0.2.1', ttl: 3600 },
        { type: 'AAAA', name: domain, value: '2001:db8::1', ttl: 3600 },
        { type: 'MX', name: domain, value: 'mail.example.com', priority: 10, ttl: 3600 },
        { type: 'TXT', name: domain, value: 'v=spf1 include:_spf.example.com ~all', ttl: 3600 },
      ],
    },
    certificate: {
      domain,
      issuer: {
        commonName: '示例 CA',
        organization: '示例证书机构',
      },
      subject: {
        commonName: domain,
        organization: '示例公司',
      },
      validity: {
        notBefore: '2024-01-01',
        notAfter: '2025-01-01',
        daysRemaining: 180,
      },
      algorithm: 'RSA',
      keySize: 2048,
      isExpired: false,
    },
  }
  whoisInfo.value = domainData.value.whois || null
  dnsInfo.value = domainData.value.dns || null
  certificateInfo.value = domainData.value.certificate || null
  
  if (showMessage) {
    message.info('已加载演示数据（后端接口未实现，请配置后端接口）', 5)
  }
}
void handleMockData

// 格式化日期
function formatDate(dateStr?: string): string {
  if (!dateStr)
    return '-'
  try {
    return new Date(dateStr).toLocaleString('zh-CN')
  }
  catch {
    return dateStr
  }
}

// 计算剩余天数
function getDaysRemaining(notAfter?: string): number {
  if (!notAfter)
    return 0
  try {
    const endDate = new Date(notAfter)
    const now = new Date()
    const diff = endDate.getTime() - now.getTime()
    return Math.ceil(diff / (1000 * 60 * 60 * 24))
  }
  catch {
    return 0
  }
}

// 加载域名列表
async function loadDomainList() {
  domainListLoading.value = true
  try {
    const response = await getDomainListApi({
      domainKeyword: domainInput.value.trim() || undefined,
      organizationId: orgFilterId.value ?? undefined,
      organizationName: orgFilterName.value?.trim() || undefined,
    })
    if (response.code === 200 && response.data) {
      domainList.value = response.data
      appliedOrgFilterName.value = orgFilterName.value.trim()
      currentPage.value = 1
    }
  }
  catch (error) {
    console.error('加载域名列表失败:', error)
  }
  finally {
    domainListLoading.value = false
  }
}

async function applyOrgFilter() {
  domainData.value = null
  const keyword = orgFilterName.value.trim()

  if (keyword)
    orgFilterId.value = null

  await loadDomainList()

  if (keyword && domainList.value.length === 0)
    message.info('未找到名称或别名匹配的组织域名')
}

function clearOrgFilter() {
  orgFilterId.value = null
  orgFilterName.value = ''
  appliedOrgFilterName.value = ''
  applyOrgFilter()
}

function syncOrgFilterFromRoute() {
  const queryOrgId = route.query.orgId
  const queryOrgName = route.query.orgName

  if (typeof queryOrgId === 'string' && queryOrgId.trim()) {
    const parsed = Number(queryOrgId)
    orgFilterId.value = Number.isNaN(parsed) ? null : parsed
  }
  else {
    orgFilterId.value = null
  }

  orgFilterName.value = typeof queryOrgName === 'string' ? queryOrgName : ''
}

async function syncPageFromRoute() {
  syncOrgFilterFromRoute()
  const queryDomain = route.query.domain
  const domain = typeof queryDomain === 'string' ? queryDomain.trim() : ''

  domainInput.value = domain
  resetDomainDetail()
  await loadDomainList()

  if (domain)
    await handleDatabaseQuery(domain)
}

// 点击域名项进行查询
function handleDomainClick(item: DomainListItem) {
  const hasLocalData = toBool(item.hasWhois) || toBool(item.hasDns) || toBool(item.hasSsl)
  if (hasLocalData) {
    handleDatabaseQuery(item.domain)
    return
  }

  Modal.confirm({
    title: '未找到本地域名信息',
    content: `域名 ${item.domain} 暂无本地 WHOIS/DNS/SSL 信息，是否继续发起实时查询并保存到数据库？`,
    okText: '继续查询',
    cancelText: '取消',
    onOk: () => queryExactDomain(item.domain),
  })
}

// 页面加载时获取域名列表
onMounted(() => {
  syncPageFromRoute()
})

watch(
  () => route.query,
  () => {
    syncPageFromRoute()
  },
)
</script>

<template>
  <page-container>
    <a-card :bordered="false" :style="{ marginBottom: '24px' }">
      <!-- 域名查询输入框 -->
      <a-space direction="vertical" :size="16" style="width: 100%;">
        <a-space :size="16" style="width: 100%;">
          <a-input
            v-model:value="domainInput"
            placeholder="请输入域名关键词（支持模糊搜索）"
            :style="{ flex: 1, minWidth: '300px' }"
            size="large"
            @press-enter="handleQuery"
          >
            <template #prefix>
              <GlobalOutlined />
            </template>
          </a-input>
          <a-button
            type="primary"
            size="large"
            :loading="domainListLoading || loading"
            @click="handleQuery"
          >
            <template #icon>
              <SearchOutlined />
            </template>
            查询
          </a-button>
        </a-space>
      </a-space>
    </a-card>

    <!-- 查询错误提示 -->
    <a-alert
      v-if="queryErrors.length > 0"
      :message="`部分查询失败: ${queryErrors.join(', ')}`"
      type="warning"
      show-icon
      closable
      :style="{ marginBottom: '24px' }"
    />

    <!-- 域名列表 -->
    <a-card
      v-if="!domainData"
      title="域名列表"
      :bordered="false"
      :style="{ marginBottom: '24px' }"
      :loading="domainListLoading"
    >
      <a-space :size="12" wrap style="margin-bottom: 16px; width: 100%;">
        <a-input
          v-model:value="orgFilterName"
          placeholder="按组织名称或别名模糊筛选"
          style="max-width: 320px;"
          @press-enter="applyOrgFilter"
        />
        <a-button type="primary" @click="applyOrgFilter">
          筛选
        </a-button>
        <a-button @click="clearOrgFilter">
          清除
        </a-button>
        <template v-if="matchedOrganizationNames.length > 0">
          <span>当前匹配组织：</span>
          <a-tag
            v-for="organizationName in matchedOrganizationNames"
            :key="organizationName"
            color="blue"
          >
            {{ organizationName }}
          </a-tag>
        </template>
      </a-space>
      <a-list
        :data-source="pagedDomainList"
        :grid="{ gutter: 16, xs: 1, sm: 2, md: 3, lg: 4, xl: 4, xxl: 6 }"
      >
        <template #renderItem="{ item }">
          <a-list-item>
            <a-card
              hoverable
              :style="{ cursor: 'pointer' }"
              :class="item.isMalicious ? 'domain-card-malicious' : 'domain-card-benign'"
              @click="handleDomainClick(item)"
            >
              <a-card-meta>
                <template #title>
                  <GlobalOutlined style="margin-right: 8px;" />
                  {{ item.domain }}
                </template>
                <template #description>
                  <div style="margin-bottom: 8px;">
                    <a-tag :color="item.isMalicious ? 'red' : 'green'" :style="{ fontSize: '11px', padding: '0 6px' }">
                      {{ item.isMalicious ? '恶意' : '良性' }}
                    </a-tag>
                  </div>
                  <div style="margin-bottom: 8px; font-size: 12px; color: #666;">
                    关联组织：{{ item.organizationName || '-' }}
                  </div>
                  <div style="margin-bottom: 8px;">
                    <a-space :size="4">
                      <a-tag
                        :color="toBool(item.hasWhois) ? 'blue' : 'default'"
                        :class="{ 'attr-tag-missing': !toBool(item.hasWhois) }"
                        :style="{ fontSize: '11px', padding: '0 4px' }"
                      >
                        WHOIS
                      </a-tag>
                      <a-tag
                        :color="toBool(item.hasDns) ? 'green' : 'default'"
                        :class="{ 'attr-tag-missing': !toBool(item.hasDns) }"
                        :style="{ fontSize: '11px', padding: '0 4px' }"
                      >
                        DNS
                      </a-tag>
                      <a-tag
                        :color="toBool(item.hasSsl) ? 'orange' : 'default'"
                        :class="{ 'attr-tag-missing': !toBool(item.hasSsl) }"
                        :style="{ fontSize: '11px', padding: '0 4px' }"
                      >
                        SSL
                      </a-tag>
                    </a-space>
                  </div>
                  <span v-if="item.createdAt" style="font-size: 12px; color: #999;">
                    添加于 {{ formatDate(item.createdAt) }}
                  </span>
                </template>
              </a-card-meta>
            </a-card>
          </a-list-item>
        </template>
      </a-list>
      <div style="display: flex; justify-content: flex-end; margin-top: 16px;">
        <a-pagination
          v-model:current="currentPage"
          :total="sortedDomainList.length"
          :page-size="pageSize"
          :show-size-changer="false"
          :show-quick-jumper="true"
          :show-total="(total:number) => `共 ${total} 条`"
        />
      </div>
    </a-card>

    <!-- 查询结果展示 -->
    <template v-if="domainData">
      <div class="detail-toolbar">
        <a-button type="primary" size="large" @click="goBackToList">
          返回
        </a-button>
      </div>

      <!-- WHOIS 信息 -->
      <a-card
        v-if="whoisInfo"
        title="WHOIS 信息"
        :bordered="false"
        :style="{ marginBottom: '24px' }"
      >
        <a-descriptions :column="{ xxl: 3, xl: 2, lg: 2, md: 1, sm: 1, xs: 1 }" bordered>
          <a-descriptions-item label="域名">
            {{ whoisInfo.domain }}
          </a-descriptions-item>
          <a-descriptions-item label="关联组织">
            {{ domainData?.organizationName || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="注册商">
            {{ whoisInfo.registrar || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="注册日期">
            {{ formatDate(whoisInfo.registrationDate) }}
          </a-descriptions-item>
          <a-descriptions-item label="过期日期">
            <a-tag :color="getDaysRemaining(whoisInfo.expirationDate) < 30 ? 'red' : 'green'">
              {{ formatDate(whoisInfo.expirationDate) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="更新日期">
            {{ formatDate(whoisInfo.updatedDate) }}
          </a-descriptions-item>
          <a-descriptions-item label="状态" :span="3">
            <a-space wrap>
              <a-tag
                v-for="(status, index) in whoisInfo.status"
                :key="index"
                color="blue"
              >
                {{ status }}
              </a-tag>
            </a-space>
          </a-descriptions-item>
          <a-descriptions-item label="名称服务器" :span="3">
            <a-space wrap>
              <a-tag
                v-for="(ns, index) in whoisInfo.nameServers"
                :key="index"
                color="cyan"
              >
                {{ ns }}
              </a-tag>
            </a-space>
          </a-descriptions-item>
          <template v-if="whoisInfo.registrant">
            <a-descriptions-item label="注册人信息" :span="3" />
            <a-descriptions-item label="姓名">
              {{ whoisInfo.registrant.name || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="组织">
              {{ whoisInfo.registrant.organization || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="邮箱">
              {{ whoisInfo.registrant.email || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="电话">
              {{ whoisInfo.registrant.phone || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="国家">
              {{ whoisInfo.registrant.country || '-' }}
            </a-descriptions-item>
          </template>
          <template v-if="whoisInfo.admin">
            <a-descriptions-item label="管理员信息" :span="3" />
            <a-descriptions-item label="姓名">
              {{ whoisInfo.admin.name || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="组织">
              {{ whoisInfo.admin.organization || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="邮箱">
              {{ whoisInfo.admin.email || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="电话">
              {{ whoisInfo.admin.phone || '-' }}
            </a-descriptions-item>
          </template>
          <template v-if="whoisInfo.tech">
            <a-descriptions-item label="技术联系人信息" :span="3" />
            <a-descriptions-item label="姓名">
              {{ whoisInfo.tech.name || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="组织">
              {{ whoisInfo.tech.organization || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="邮箱">
              {{ whoisInfo.tech.email || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="电话">
              {{ whoisInfo.tech.phone || '-' }}
            </a-descriptions-item>
          </template>
        </a-descriptions>
      </a-card>

      <!-- DNS 记录 -->
      <a-card
        v-if="dnsInfo"
        title="DNS 记录"
        :bordered="false"
        :style="{ marginBottom: '24px' }"
      >
        <a-table
          :columns="[
            { title: '类型', dataIndex: 'type', key: 'type', width: 100 },
            { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
            { title: '值', dataIndex: 'value', key: 'value', ellipsis: true },
            { title: '优先级', dataIndex: 'priority', key: 'priority', width: 100 },
            { title: 'TTL', dataIndex: 'ttl', key: 'ttl', width: 100 },
          ]"
          :data-source="dnsInfo.records"
          :pagination="false"
          :row-key="(record: DnsRecord, index?: number) => `${record.type}-${record.name}-${index ?? 0}`"
          size="middle"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'type'">
              <a-tag :color="getDnsTypeColor(record.type)">
                {{ record.type }}
              </a-tag>
            </template>
            <template v-if="column.key === 'priority'">
              {{ record.priority ?? '-' }}
            </template>
          </template>
        </a-table>
      </a-card>

      <!-- 证书信息 -->
      <a-card
        v-if="certificateInfo"
        title="SSL/TLS 证书信息"
        :bordered="false"
      >
        <a-descriptions :column="{ xxl: 3, xl: 2, lg: 2, md: 1, sm: 1, xs: 1 }" bordered>
          <a-descriptions-item label="域名">
            {{ certificateInfo.domain }}
          </a-descriptions-item>
          <a-descriptions-item label="证书状态">
            <a-tag :color="certificateInfo.isExpired ? 'red' : 'green'">
              {{ certificateInfo.isExpired ? '已过期' : '有效' }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="是否自签名">
            <a-tag :color="certificateInfo.isSelfSigned ? 'orange' : 'green'">
              {{ certificateInfo.isSelfSigned ? '是' : '否' }}
            </a-tag>
          </a-descriptions-item>
          <template v-if="certificateInfo.issuer">
            <a-descriptions-item label="颁发机构信息" :span="3" />
            <a-descriptions-item label="通用名称">
              {{ certificateInfo.issuer.commonName || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="组织">
              {{ certificateInfo.issuer.organization || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="国家">
              {{ certificateInfo.issuer.country || '-' }}
            </a-descriptions-item>
          </template>
          <template v-if="certificateInfo.subject">
            <a-descriptions-item label="主体信息" :span="3" />
            <a-descriptions-item label="通用名称">
              {{ certificateInfo.subject.commonName || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="组织">
              {{ certificateInfo.subject.organization || '-' }}
            </a-descriptions-item>
            <a-descriptions-item label="国家">
              {{ certificateInfo.subject.country || '-' }}
            </a-descriptions-item>
          </template>
          <template v-if="certificateInfo.validity">
            <a-descriptions-item label="有效期信息" :span="3" />
            <a-descriptions-item label="生效日期">
              {{ formatDate(certificateInfo.validity.notBefore) }}
            </a-descriptions-item>
            <a-descriptions-item label="到期日期">
              <a-tag :color="getDaysRemaining(certificateInfo.validity.notAfter) < 30 ? 'red' : 'green'">
                {{ formatDate(certificateInfo.validity.notAfter) }}
              </a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="剩余天数">
              <a-tag :color="getDaysRemaining(certificateInfo.validity.notAfter) < 30 ? 'red' : 'blue'">
                {{ certificateInfo.validity.daysRemaining ?? getDaysRemaining(certificateInfo.validity.notAfter) }} 天
              </a-tag>
            </a-descriptions-item>
          </template>
          <a-descriptions-item label="算法">
            {{ certificateInfo.algorithm || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="密钥长度">
            {{ certificateInfo.keySize ? `${certificateInfo.keySize} bits` : '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="序列号">
            {{ certificateInfo.serialNumber || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="指纹">
            <a-typography-text copyable :style="{ fontFamily: 'monospace', fontSize: '12px' }">
              {{ certificateInfo.fingerprint || '-' }}
            </a-typography-text>
          </a-descriptions-item>
          <a-descriptions-item v-if="certificateInfo.sanNames && certificateInfo.sanNames.length > 0" label="SAN 域名列表" :span="3">
            <a-space wrap>
              <a-tag
                v-for="(san, index) in certificateInfo.sanNames"
                :key="index"
                color="purple"
              >
                {{ san }}
              </a-tag>
            </a-space>
          </a-descriptions-item>
        </a-descriptions>
      </a-card>

      <!-- 查询时间 -->
      <a-card v-if="domainData.queryTime" :bordered="false" :style="{ marginTop: '24px' }">
        <a-typography-text type="secondary">
          查询时间：{{ formatDate(domainData.queryTime) }}
        </a-typography-text>
      </a-card>
    </template>

    <!-- 空状态 -->
    <a-empty
      v-else
      :style="{ marginTop: '100px' }"
      description="请输入域名进行查询"
    />
  </page-container>
</template>

<script lang="ts">
// DNS 类型颜色映射
function getDnsTypeColor(type: string): string {
  const colorMap: Record<string, string> = {
    A: 'blue',
    AAAA: 'cyan',
    CNAME: 'green',
    MX: 'orange',
    TXT: 'purple',
    NS: 'red',
    SOA: 'gold',
    PTR: 'magenta',
    SRV: 'lime',
  }
  return colorMap[type] || 'default'
}

export default {
  methods: {
    getDnsTypeColor,
  },
}
</script>

<style scoped lang="less">
h2 {
  margin: 0 0 16px 0;
}

.domain-card-malicious {
  border: 1px solid #ffccc7;
  background: #fff2f0;
}

.domain-card-benign {
  border: 1px solid #d9f7be;
  background: #f6ffed;
}

.detail-toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 16px;
}

.attr-tag-missing {
  opacity: 0.6;
  border-style: dashed;
}

:deep(.ant-descriptions-item-label) {
  font-weight: 600;
  width: 150px;
}

:deep(.ant-table) {
  .ant-table-thead > tr > th {
    font-weight: 600;
  }
}
</style>
