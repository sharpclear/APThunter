<script setup lang="ts">
import { Column, Pie } from '@antv/g2plot'
import {
  CloudServerOutlined,
  DatabaseOutlined,
  ExclamationCircleOutlined,
  FileProtectOutlined,
  SafetyCertificateOutlined,
  SecurityScanOutlined,
  TeamOutlined,
  WarningOutlined,
} from '@ant-design/icons-vue'

defineOptions({
  name: 'Monitor',
})

function convertNumber(number: number) {
  return number.toLocaleString()
}

// 生成随机数据
function generateRandomNumber(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

// APT统计数据
const stats = reactive({
  aptDomainTotal: generateRandomNumber(15000, 20000), // APT域名总量
  activeOrganizations: generateRandomNumber(2000, 3000), // 活跃组织数量
  latestThreats: generateRandomNumber(10000, 15000), // 最新威胁发现
  dnsTunnelDetection: generateRandomNumber(25000, 35000), // DNS隧道检测
  maliciousCertificates: generateRandomNumber(20000, 30000), // 恶意证书数量
  c2ServerDetection: generateRandomNumber(3000, 5000), // C2服务器检测
  dnsAnomalyDetection: generateRandomNumber(60000, 70000), // DNS异常检测
  threatBlockCount: generateRandomNumber(10, 20), // 威胁拦截次数
})

// 威胁类型分布数据
const threatTypeData = [
  { type: 'DNS隧道', value: generateRandomNumber(300, 500) },
  { type: 'DGA域名', value: generateRandomNumber(400, 600) },
  { type: '钓鱼域名', value: generateRandomNumber(200, 400) },
  { type: 'C2通信', value: generateRandomNumber(150, 300) },
  { type: '其他', value: generateRandomNumber(100, 200) },
]

// 攻击者地理位置TOP10
const attackSourceTop10 = [
  { country: '美国', count: generateRandomNumber(800, 1200) },
  { country: '俄罗斯', count: generateRandomNumber(600, 1000) },
  { country: '中国', count: generateRandomNumber(500, 900) },
  { country: '朝鲜', count: generateRandomNumber(400, 800) },
  { country: '伊朗', count: generateRandomNumber(300, 700) },
  { country: '印度', count: generateRandomNumber(250, 600) },
  { country: '巴西', count: generateRandomNumber(200, 500) },
  { country: '德国', count: generateRandomNumber(150, 400) },
  { country: '英国', count: generateRandomNumber(100, 350) },
  { country: '法国', count: generateRandomNumber(80, 300) },
]

// DGA域名TOP10
const dgaDomainTop10 = [
  { domain: 'm-dsvx-nss...', count: generateRandomNumber(15, 25) },
  { domain: 'www.bdcfu...', count: generateRandomNumber(12, 22) },
  { domain: 'xtq-r2hgu...', count: generateRandomNumber(10, 20) },
  { domain: 'n-dsvx-lgn...', count: generateRandomNumber(8, 18) },
  { domain: 'www.qdq.com', count: generateRandomNumber(7, 16) },
  { domain: 'abc-xyz.net...', count: generateRandomNumber(6, 15) },
  { domain: 'test-dom...', count: generateRandomNumber(5, 13) },
  { domain: 'evil-site...', count: generateRandomNumber(4, 12) },
  { domain: 'malware...', count: generateRandomNumber(3, 10) },
  { domain: 'phishing...', count: generateRandomNumber(2, 8) },
]

const pieContainer = ref()
const columnContainer = ref()
const dgaColumnContainer = ref()

onMounted(() => {
  // 威胁类型分布饼图
  new Pie(pieContainer.value, {
    data: threatTypeData,
    angleField: 'value',
    colorField: 'type',
    height: 280,
    radius: 0.8,
    innerRadius: 0.6,
    label: {
      type: 'spider',
      labelHeight: 28,
      content: '{name}\n{percentage}',
    },
    color: ['#5B8FF9', '#5AD8A6', '#5D7092', '#F6BD16', '#E86452'],
    interactions: [{ type: 'element-active' }],
    legend: {
      position: 'bottom',
    },
    statistic: {
      title: {
        content: '威胁总数',
        style: {
          fontSize: '14px',
        },
      },
      content: {
        style: {
          fontSize: '24px',
        },
        formatter: () => {
          const total = threatTypeData.reduce((sum, item) => sum + item.value, 0)
          return convertNumber(total)
        },
      },
    },
  }).render()

  // 攻击来源TOP10柱状图
  new Column(columnContainer.value, {
    data: attackSourceTop10,
    xField: 'country',
    yField: 'count',
    height: 280,
    color: '#5B8FF9',
    label: {
      position: 'top',
      style: {
        fill: '#000000',
        opacity: 0.6,
      },
    },
    xAxis: {
      label: {
        autoRotate: false,
      },
    },
    meta: {
      country: {
        alias: '国家',
      },
      count: {
        alias: '攻击次数',
      },
    },
  }).render()

  // DGA域名TOP10柱状图
  new Column(dgaColumnContainer.value, {
    data: dgaDomainTop10,
    xField: 'domain',
    yField: 'count',
    height: 280,
    color: '#5AD8A6',
    label: {
      position: 'top',
      style: {
        fill: '#000000',
        opacity: 0.6,
      },
    },
    xAxis: {
      label: {
        autoRotate: true,
        autoHide: false,
      },
    },
    meta: {
      domain: {
        alias: '域名',
      },
      count: {
        alias: '检测次数',
      },
    },
  }).render()
})
</script>

<template>
  <page-container>
    <!-- 顶部统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 24px">
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="APT域名总量"
            :value="convertNumber(stats.aptDomainTotal)"
            :value-style="{ color: '#3f8600' }"
          >
            <template #prefix>
              <DatabaseOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="活跃组织数量"
            :value="convertNumber(stats.activeOrganizations)"
            :value-style="{ color: '#cf1322' }"
          >
            <template #prefix>
              <TeamOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="最新威胁发现"
            :value="convertNumber(stats.latestThreats)"
            :value-style="{ color: '#ff9800' }"
          >
            <template #prefix>
              <WarningOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="DNS隧道检测"
            :value="convertNumber(stats.dnsTunnelDetection)"
            :value-style="{ color: '#1890ff' }"
          >
            <template #prefix>
              <SafetyCertificateOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
    </a-row>

    <!-- 第二行统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 24px">
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="恶意证书数量"
            :value="convertNumber(stats.maliciousCertificates)"
            :value-style="{ color: '#722ed1' }"
          >
            <template #prefix>
              <FileProtectOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="C2服务器检测"
            :value="convertNumber(stats.c2ServerDetection)"
            :value-style="{ color: '#eb2f96' }"
          >
            <template #prefix>
              <CloudServerOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="DNS异常检测"
            :value="convertNumber(stats.dnsAnomalyDetection)"
            :value-style="{ color: '#13c2c2' }"
          >
            <template #prefix>
              <ExclamationCircleOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6" :xl="6">
        <a-card :bordered="false" class="stat-card">
          <a-statistic
            title="威胁拦截次数"
            :value="convertNumber(stats.threatBlockCount)"
            :value-style="{ color: '#faad14' }"
          >
            <template #prefix>
              <SecurityScanOutlined />
            </template>
          </a-statistic>
        </a-card>
      </a-col>
    </a-row>

    <!-- 威胁类型分布和图表展示区 -->
    <a-row :gutter="24">
      <a-col :xl="8" :lg="24" :md="24" :sm="24" :xs="24" :style="{ marginBottom: '24px' }">
        <a-card title="威胁类型分布" :bordered="false">
          <div ref="pieContainer" />
        </a-card>
      </a-col>
      <a-col :xl="8" :lg="12" :md="12" :sm="24" :xs="24" :style="{ marginBottom: '24px' }">
        <a-card title="攻击来源 TOP10" :bordered="false">
          <div ref="columnContainer" />
        </a-card>
      </a-col>
      <a-col :xl="8" :lg="12" :md="12" :sm="24" :xs="24" :style="{ marginBottom: '24px' }">
        <a-card title="DGA域名 TOP10" :bordered="false">
          <div ref="dgaColumnContainer" />
        </a-card>
      </a-col>
    </a-row>
  </page-container>
</template>

<style scoped lang="less">
.stat-card {
  transition: all 0.3s ease;
  &:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    transform: translateY(-2px);
  }
}
</style>
