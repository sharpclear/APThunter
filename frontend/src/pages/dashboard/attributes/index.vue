<script setup lang="ts">
import { GlobalOutlined, SearchOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import type { DomainAttributes, DnsInfo, WhoisInfo, CertificateInfo, DnsRecord } from '~/api/dashboard/attributes'
import { queryDomainAttributesApi } from '~/api/dashboard/attributes'

defineOptions({ name: 'DashboardAttributes' })

// 域名输入
const domainInput = ref<string>('')
const loading = ref(false)

// 查询结果
const domainData = ref<DomainAttributes | null>(null)
const whoisInfo = ref<WhoisInfo | null>(null)
const dnsInfo = ref<DnsInfo | null>(null)
const certificateInfo = ref<CertificateInfo | null>(null)

// 验证域名格式
function isValidDomain(domain: string): boolean {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i
  return domainRegex.test(domain.trim())
}

// 查询域名属性
async function handleQuery() {
  const domain = domainInput.value.trim()
  
  if (!domain) {
    message.warning('请输入要查询的域名')
    return
  }

  if (!isValidDomain(domain)) {
    message.error('请输入有效的域名格式')
    return
  }

  loading.value = true
  try {
    const response = await queryDomainAttributesApi({ domain })
    
    if (response.code === 200 && response.data) {
      domainData.value = response.data
      whoisInfo.value = response.data.whois || null
      dnsInfo.value = response.data.dns || null
      certificateInfo.value = response.data.certificate || null
      message.success('查询成功')
    }
    else {
      message.error(response.msg || '查询失败')
    }
  }
  catch (error: any) {
    // 检查是否是接口不存在（404）或网络错误
    const status = error?.response?.status
    const isNotFound = status === 404
    const isNetworkError = !error?.response
    
    // 如果是接口不存在或网络错误，并且是在开发环境，则加载演示数据
    if ((isNotFound || isNetworkError) && import.meta.env.DEV) {
      // 不显示错误消息，直接加载演示数据（因为 errorHandler 已经显示了 notification）
      handleMockData(domain, false)
    }
    // 如果是其他错误（如 500），只显示错误消息，不加载模拟数据
    // errorHandler 已经在 request.ts 中显示了 notification，这里不需要重复显示
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
</script>

<template>
  <page-container>
    <a-card :bordered="false" :style="{ marginBottom: '24px' }">
      <!-- 域名查询输入框 -->
      <a-space :size="16" style="width: 100%;">
        <a-input
          v-model:value="domainInput"
          placeholder="请输入域名，例如：example.com"
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
          :loading="loading"
          @click="handleQuery"
        >
          <template #icon>
            <SearchOutlined />
          </template>
          查询
        </a-button>
      </a-space>
    </a-card>

    <!-- 查询结果展示 -->
    <template v-if="domainData">
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
