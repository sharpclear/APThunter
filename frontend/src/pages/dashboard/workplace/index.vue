<script setup lang="ts">
import { Pie } from '@antv/g2plot'
import dayjs from 'dayjs'
import { onMounted, nextTick, watch, computed } from 'vue'
import type { OrganizationProfile } from '~/api/dashboard/profile'
import AptTimeline, { type AptEvent } from '~/components/apt-timeline/index.vue'

defineOptions({
  name: 'Workplace',
})

// 选中的事件
const selectedEvent = ref<AptEvent | null>(null)
// 选中的组织
const selectedOrganization = ref<OrganizationProfile | null>(null)
const loading = ref(false)

// 组织列表
const organizationList = ref<OrganizationProfile[]>([])
const total = ref(0)

// 地区锚点（相对容器百分比定位）
type RegionKey = '东亚' | '南亚' | '东欧' | '中东' | '北美洲' | '南美洲' | '非洲' | '欧洲' | '大洋洲' | '东南亚' | '中亚' | '未知'
const regionAnchors: Record<RegionKey, { label: string; left: string; top: string }> = {
  '东亚': { label: '东亚', left: '76%', top: '42%' },
  '东南亚': { label: '东南亚', left: '68%', top: '60%' },
  '南亚': { label: '南亚', left: '66%', top: '59%' },
  '中亚': { label: '中亚', left: '58%', top: '42%' },
  '中东': { label: '中东', left: '54%', top: '50%' },
  '欧洲': { label: '欧洲', left: '46%', top: '38%' },
  '东欧': { label: '东欧', left: '50%', top: '38%' },
  '非洲': { label: '非洲', left: '50%', top: '62%' },
  '北美洲': { label: '北美洲', left: '20%', top: '37%' },
  '南美洲': { label: '南美洲', left: '30%', top: '72%' },
  '大洋洲': { label: '大洋洲', left: '80%', top: '75%' },
  '未知': { label: '未知区域', left: '5%', top: '5%' },
}

// 随机生成APT事件数据
function generateRandomEvents(): AptEvent[] {
  const organizations = ['mimo', '摩诃草', '蔓灵花', 'Gamaredon', 'Lazarus', '响尾蛇', '透明部落', 'TA585', 'UTG-Q-010', '赏眼鹰']
  const eventTypes = ['major', 'normal'] as const
  const eventTemplates = {
    major: [
      { title: '发现新的C2服务器', description: '检测到新的恶意域名和C2基础设施' },
      { title: '大规模攻击活动', description: '检测到针对多个目标的攻击活动' },
      { title: '重要攻击活动', description: '检测到针对特定地区的攻击' },
      { title: '重大安全威胁', description: '发现新的攻击向量和技术' },
      { title: '高级持续威胁', description: '检测到APT组织的持续攻击活动' },
      { title: '金融攻击事件', description: '检测到针对金融机构的攻击' },
      { title: '政府机构攻击', description: '检测到针对政府机构的攻击' },
      { title: '多目标攻击', description: '同时针对多个国家进行攻击' },
      { title: '新恶意软件变种', description: '发现新的恶意软件变种' },
      { title: '网络间谍活动', description: '检测到大规模网络间谍活动' },
    ],
    normal: [
      { title: '攻击活动活跃', description: '检测到大量DNS查询异常' },
      { title: '新域名注册', description: '发现新的恶意域名' },
      { title: 'C2通信活跃', description: '检测到大量C2通信流量' },
      { title: '钓鱼攻击', description: '检测到针对性鱼叉式网络钓鱼攻击' },
      { title: '新C2基础设施', description: '发现新的C2服务器' },
      { title: '网络钓鱼活动', description: '检测到大规模网络钓鱼活动' },
      { title: '域名发现', description: '发现大量恶意域名' },
      { title: 'C2活动', description: '检测到C2通信异常' },
      { title: '威胁检测', description: '检测到可疑网络活动' },
      { title: '攻击尝试', description: '检测到攻击尝试' },
    ],
  }

  const events: AptEvent[] = []
  const startDate = dayjs('2024-09-01')
  const endDate = dayjs('2025-12-31')
  const totalDays = endDate.diff(startDate, 'day')
  
  // 生成约30-40个事件
  const eventCount = 35
  const usedDates = new Set<string>()
  
  for (let i = 0; i < eventCount; i++) {
    let randomDay = Math.floor(Math.random() * totalDays)
    let eventDate = startDate.add(randomDay, 'day')
    let dateStr = eventDate.format('YYYY-MM-DD')
    
    // 确保日期不重复，如果重复则向后推一天
    while (usedDates.has(dateStr) && randomDay < totalDays - 1) {
      randomDay++
      eventDate = startDate.add(randomDay, 'day')
      dateStr = eventDate.format('YYYY-MM-DD')
    }
    usedDates.add(dateStr)
    
    const type = eventTypes[Math.floor(Math.random() * eventTypes.length)]
    const templates = eventTemplates[type]
    const template = templates[Math.floor(Math.random() * templates.length)]
    const organization = organizations[Math.floor(Math.random() * organizations.length)]
    
    events.push({
      id: `event-${i + 1}`,
      date: dateStr,
      title: template.title,
      description: template.description,
      type,
      organization,
    })
  }
  
  // 按日期排序
  return events.sort((a, b) => dayjs(a.date).valueOf() - dayjs(b.date).valueOf())
}

// 所有APT事件
const allAptEvents = ref<AptEvent[]>([])

// 事件到组织的映射
const eventToOrganizations = computed<Record<string, OrganizationProfile[]>>(() => {
  const map: Record<string, OrganizationProfile[]> = {}
  allAptEvents.value.forEach(event => {
    if (event.organization) {
      if (!map[event.id]) {
        map[event.id] = []
      }
      const org = mockOrganizations.find(o => o.name === event.organization)
      if (org && !map[event.id].find(o => o.id === org.id)) {
        map[event.id].push(org)
      }
    }
  })
  return map
})

// 处理事件点击
function handleEventClick(event: AptEvent) {
  selectedEvent.value = event
  selectedOrganization.value = null
  // 根据事件筛选相关组织
  const relatedOrgs = eventToOrganizations.value[event.id] || []
  organizationList.value = relatedOrgs
  total.value = relatedOrgs.length
}

// 重点组织数据（与 profile 页面同步）
const mockOrganizations: OrganizationProfile[] = [
  {
    id: 1,
    name: 'mimo',
    alias: [],
    description: 'mimo是一个活跃的威胁组织，其活动主要通过特定域名进行传播。',
    iocCount: 50,
    eventCount: 10,
    updateTime: '2025-07-30',
    region: '北美洲',
    origin: undefined,
    targetCountries: [],
    targetIndustries: [],
    previousDomains: [
      'ice.theinnovationfactory.it',
      'bpp.theinnovationfactory.it',
    ],
    vpsProviders: [
      { provider: 'OVH', count: 25, percentage: 50.0 },
      { provider: 'Hetzner', count: 15, percentage: 30.0 },
      { provider: '其他', count: 10, percentage: 20.0 },
    ],
  },
  {
    id: 2,
    name: '摩诃草',
    alias: ['Moha Grass'],
    description: '摩诃草是一个长期活跃的APT组织，主要针对南亚地区，利用多种域名进行攻击活动。',
    iocCount: 320,
    eventCount: 45,
    updateTime: '2025-08-08',
    region: '南亚',
    origin: undefined,
    targetCountries: ['巴基斯坦', '印度'],
    targetIndustries: ['政府', '军事'],
    previousDomains: [
      'datamero.org',
      'caapakistaan.com',
      'd11d6t6zpljvtm.cloudfront.net',
      'zebydigital.org',
    ],
    vpsProviders: [
      { provider: 'DigitalOcean', count: 120, percentage: 37.5 },
      { provider: 'Vultr', count: 80, percentage: 25.0 },
      { provider: 'Linode', count: 60, percentage: 18.8 },
      { provider: '其他', count: 60, percentage: 18.8 },
    ],
  },
  {
    id: 3,
    name: '赏眼鹰',
    alias: [],
    description: '赏眼鹰是一个通过特定域名进行恶意活动的组织。',
    iocCount: 25,
    eventCount: 5,
    updateTime: '2025-08-13',
    region: '北美洲',
    origin: undefined,
    targetCountries: [],
    targetIndustries: [],
    previousDomains: [
      'envio16-05.duckdns.org',
    ],
    vpsProviders: [
      { provider: 'Hetzner', count: 15, percentage: 60.0 },
      { provider: 'DigitalOcean', count: 10, percentage: 40.0 },
    ],
  },
  {
    id: 4,
    name: '蔓灵花',
    alias: ['BITTER', 'APT-C-08'],
    description: '蔓灵花是一个主要针对巴基斯坦、中国和孟加拉国等南亚国家的APT组织。该组织以其使用自定义恶意软件和针对性鱼叉式网络钓鱼攻击而闻名。',
    iocCount: 580,
    eventCount: 95,
    updateTime: '2025-08-15',
    region: '南亚',
    origin: undefined,
    targetCountries: ['巴基斯坦', '中国', '孟加拉国'],
    targetIndustries: ['政府', '军事', '能源'],
    previousDomains: [
      'pololiberty.com',
      'keeferbeautytrends.com',
      'koliwooclients.com',
      'esanojinjasvc.com',
    ],
    vpsProviders: [
      { provider: 'DigitalOcean', count: 220, percentage: 37.9 },
      { provider: 'Linode', count: 150, percentage: 25.9 },
      { provider: 'Vultr', count: 120, percentage: 20.7 },
      { provider: '其他', count: 90, percentage: 15.5 },
    ],
  },
  {
    id: 5,
    name: 'Gamaredon',
    alias: ['Primitive Bear', 'ACTINIUM'],
    description: 'Gamaredon是一个与俄罗斯相关联的APT组织，主要针对乌克兰政府和军事实体，以其大规模的鱼叉式网络钓鱼活动和使用合法服务进行C2通信而闻名。',
    iocCount: 850,
    eventCount: 120,
    updateTime: '2025-08-28',
    region: '东欧',
    origin: undefined,
    targetCountries: ['乌克兰', '波兰', '格鲁吉亚'],
    targetIndustries: ['政府', '军事'],
    previousDomains: [
      'litanq.ru',
      'fulagam.ru',
      'bulam.ru',
      'euw.devtunnels.ms',
      'dvofiuao.3150wild.workers.dev',
      'tskqbu.bronzevere.workers.dev',
      'bdslmtlqh.bronzevere.workers.dev',
      'jqrwbrbj.bronzevere.workers.dev',
      'khycpsgbu.previoussusanna.workers.dev',
      'oexvrm.embarrassed3627.workers.dev',
      'xuwj.goldjan.workers.dev',
      'gohiz.griercrimson.workers.dev',
    ],
    vpsProviders: [
      { provider: 'Contabo', count: 280, percentage: 32.9 },
      { provider: 'OVH', count: 220, percentage: 25.9 },
      { provider: 'Hetzner', count: 180, percentage: 21.2 },
      { provider: '其他', count: 170, percentage: 20.0 },
    ],
  },
  {
    id: 6,
    name: 'Lazarus',
    alias: ['Hidden Cobra', 'Guardians of Peace'],
    description: 'Lazarus Group是一个与朝鲜政府关联的APT组织，自2009年开始活跃。该组织主要针对金融机构和加密货币交易所进行攻击，以获取经济利益。同时也进行网络间谍活动。',
    iocCount: 2450,
    eventCount: 180,
    updateTime: '2025-09-01',
    region: '东亚',
    origin: undefined,
    targetCountries: ['韩国', '美国', '日本', '印度'],
    targetIndustries: ['金融', '加密货币', '政府'],
    previousDomains: [
      'driverservices.store',
      'block-digital.online',
    ],
    vpsProviders: [
      { provider: 'Choopa', count: 980, percentage: 40.0 },
      { provider: 'LeaseWeb', count: 610, percentage: 24.9 },
      { provider: 'OVH', count: 490, percentage: 20.0 },
      { provider: '其他', count: 370, percentage: 15.1 },
    ],
  },
  {
    id: 7,
    name: 'UTG-Q-010',
    alias: [],
    description: 'UTG-Q-010是一个通过特定域名进行活动的威胁组织。',
    iocCount: 45,
    eventCount: 8,
    updateTime: '2025-09-04',
    region: '南美洲',
    origin: undefined,
    targetCountries: [],
    targetIndustries: [],
    previousDomains: [
      'cloudcenter.top',
    ],
    vpsProviders: [
      { provider: 'Amazon AWS', count: 25, percentage: 55.6 },
      { provider: 'DigitalOcean', count: 15, percentage: 33.3 },
      { provider: '其他', count: 5, percentage: 11.1 },
    ],
  },
  {
    id: 8,
    name: '响尾蛇',
    alias: ['Rattlesnake', 'Sidewinder'],
    description: '响尾蛇是一个活跃的威胁组织，主要通过大量域名进行恶意活动，可能与南亚地区相关，主要针对军事和政府目标。',
    iocCount: 680,
    eventCount: 85,
    updateTime: '2025-09-11',
    region: '南亚',
    origin: undefined,
    targetCountries: ['尼泊尔', '巴基斯坦', '印度'],
    targetIndustries: ['政府', '军事'],
    previousDomains: [
      'dteofmediapsyops.army-lk.com',
      'dtecyber.nepalarmy-milnp.info',
      'mailnepalarmymil.mods.email',
      'dntnavymil.mofw.pro',
      'lk.aliyumm.pro',
      'sudden.nepalarmy-milnp.info',
      'downloads.masarh.live',
      'mailafdgovbd.163inc.org',
      'policy.mail163cn.info',
    ],
    vpsProviders: [
      { provider: 'DigitalOcean', count: 250, percentage: 36.8 },
      { provider: 'Linode', count: 180, percentage: 26.5 },
      { provider: 'Vultr', count: 150, percentage: 22.1 },
      { provider: '其他', count: 100, percentage: 14.7 },
    ],
  },
  {
    id: 9,
    name: '透明部落',
    alias: ['Transparent Tribe', 'APT36'],
    description: '透明部落是一个主要针对南亚地区，特别是巴基斯坦和印度的APT组织，以其针对军事和政府实体的攻击而闻名。',
    iocCount: 420,
    eventCount: 65,
    updateTime: '2025-10-17',
    region: '南亚',
    origin: undefined,
    targetCountries: ['巴基斯坦', '印度', '阿富汗'],
    targetIndustries: ['军事', '政府'],
    previousDomains: [
      'sinjita.store',
      'modindia.serveminecraft.net',
    ],
    vpsProviders: [
      { provider: 'OVH', count: 160, percentage: 38.1 },
      { provider: 'Hetzner', count: 110, percentage: 26.2 },
      { provider: 'DigitalOcean', count: 100, percentage: 23.8 },
      { provider: '其他', count: 50, percentage: 11.9 },
    ],
  },
  {
    id: 10,
    name: 'TA585',
    alias: [],
    description: 'TA585是一个活跃的威胁组织，通过特定域名进行恶意活动。',
    iocCount: 65,
    eventCount: 12,
    updateTime: '2025-10-23',
    region: '南美洲',
    origin: undefined,
    targetCountries: [],
    targetIndustries: [],
    previousDomains: [
      'intlspring.com',
    ],
    vpsProviders: [
      { provider: 'DigitalOcean', count: 35, percentage: 53.8 },
      { provider: 'Vultr', count: 20, percentage: 30.8 },
      { provider: '其他', count: 10, percentage: 15.4 },
    ],
  },
]

// 初始化数据
onMounted(() => {
  // 生成随机事件
  allAptEvents.value = generateRandomEvents()
  // 初始化显示所有组织
  organizationList.value = [...mockOrganizations]
  total.value = mockOrganizations.length
})


// 重置筛选
function resetFilter() {
  selectedEvent.value = null
  selectedOrganization.value = null
  organizationList.value = [...mockOrganizations]
  total.value = mockOrganizations.length
}

// 处理组织点击
function handleOrganizationClick(org: OrganizationProfile) {
  selectedOrganization.value = org
  selectedEvent.value = null
  organizationList.value = [org]
  total.value = 1
}

// 根据选中的组织过滤事件
const filteredEvents = computed<AptEvent[]>(() => {
  if (selectedOrganization.value) {
    // 如果选中了组织，只显示该组织的事件
    return allAptEvents.value.filter(event => 
      event.organization === selectedOrganization.value?.name
    )
  }
  // 如果没有选中组织，显示所有事件
  return allAptEvents.value
})

// 分区分组（无查询时用于地图标签展示）
const groupedByRegion = computed<Record<RegionKey, OrganizationProfile[]>>(() => {
  const groups: Record<RegionKey, OrganizationProfile[]> = {
    '东亚': [], '南亚': [], '东欧': [], '中东': [], '北美洲': [], '南美洲': [], '非洲': [], '欧洲': [], '大洋洲': [], '东南亚': [], '中亚': [], '未知': [],
  }
  mockOrganizations.forEach(org => {
    const key = (org.region as RegionKey) || '未知'
    if (groups[key])
      groups[key].push(org)
    else
      groups['未知'].push(org)
  })
  return groups
})

function getGroupByRegionKey(key: string): OrganizationProfile[] {
  return (groupedByRegion.value as Record<string, OrganizationProfile[]>)[key] ?? []
}

// 初始化VPS分布图表
function initVpsChart(containerId: string, data: { provider: string; count: number; percentage: number }[]) {
  nextTick(() => {
    const container = document.getElementById(containerId)
    if (!container)
      return
    
    // 清除之前的内容
    container.innerHTML = ''
    
    const chartData = data.map(item => ({
      type: item.provider,
      value: item.percentage,
    }))
    
    const pie = new Pie(container, {
      data: chartData,
      angleField: 'value',
      colorField: 'type',
      radius: 0.8,
      innerRadius: 0.5,
      label: {
        type: 'inner',
        offset: '-50%',
        content: '{value}%',
        style: {
          textAlign: 'center',
          fontSize: 12,
        },
      },
      interactions: [{ type: 'element-active' }],
      statistic: {
        title: false,
        content: {
          style: {
            whiteSpace: 'pre-wrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          },
          content: 'VPS分布',
        },
      },
    })
    
    pie.render()
  })
}

// 格式化日期
function formatDate(dateStr?: string): string {
  if (!dateStr)
    return '-'
  return dayjs(dateStr).format('YYYY-MM-DD')
}

// 监听组织列表变化，初始化图表
watch(
  organizationList,
  (newList) => {
    nextTick(() => {
      newList.forEach((org) => {
        if (org.vpsProviders && org.vpsProviders.length > 0) {
          initVpsChart(`vps-chart-${org.id}`, org.vpsProviders)
        }
      })
    })
  },
  { deep: true, immediate: true },
)

// 监听单个详情的渲染，补充渲染饼图
watch(
  () => selectedOrganization.value,
  (org) => {
    if (!org) return
    nextTick(() => {
      if (org.vpsProviders && org.vpsProviders.length > 0)
        initVpsChart(`vps-chart-${org.id}`, org.vpsProviders)
    })
  },
  { immediate: true },
)
</script>

<template>
  <page-container>
    <!-- 无选中事件时：地图分区视图 -->
    <a-card v-if="!selectedEvent && !selectedOrganization" :bordered="false" :style="{ marginBottom: '24px' }">
      <template #title>
        <a-typography-title :level="5" style="margin: 0;">APT组织地理分布</a-typography-title>
      </template>
      <div class="map-wrapper">
        <div class="map-canvas">
        <template v-for="(anchor, key) in regionAnchors" :key="key as string">
          <div
            v-if="key !== '未知' && getGroupByRegionKey(key as string).length > 0"
            class="region-anchor"
            :class="{ 'east-asia-anchor': key === '东亚' }"
            :style="{ left: (anchor as any).left, top: (anchor as any).top }"
          >
            <div class="anchor-title">{{ (anchor as any).label }}</div>
            <!-- 东亚区域：组织名显示在定位点上方 -->
            <template v-if="key === '东亚'">
              <div class="anchor-orgs-above">
                <a-tag
                  v-for="org in getGroupByRegionKey(key as string)"
                  :key="org.id"
                  color="cyan"
                  class="clickable org-tag"
                  @click="handleOrganizationClick(org)"
                >
                  {{ org.name }}
                </a-tag>
              </div>
            </template>
            <div class="anchor-dot" />
            <!-- 其他区域：组织名显示在定位点下方 -->
            <div v-if="key !== '东亚'" class="anchor-panel">
              <a-tag
                v-for="org in getGroupByRegionKey(key as string)"
                :key="org.id"
                color="cyan"
                class="clickable org-tag"
                @click="handleOrganizationClick(org)"
              >
                {{ org.name }}
              </a-tag>
            </div>
          </div>
        </template>
        </div>
      </div>
    </a-card>

    <!-- APT事件时间轴 -->
    <a-card :bordered="false" :style="{ marginBottom: '24px' }">
      <template #title>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span>APT事件时间轴</span>
          <a-button v-if="selectedEvent || selectedOrganization" type="link" size="small" @click="resetFilter">
            清除筛选
          </a-button>
        </div>
      </template>
      <AptTimeline :events="filteredEvents" @event-click="handleEventClick" />
      <div v-if="selectedEvent" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #f0f0f0;">
        <a-space direction="vertical" style="width: 100%;" :size="8">
          <div>
            <a-typography-text strong>选中事件：</a-typography-text>
            <a-tag color="blue" style="margin-left: 8px;">{{ selectedEvent.title }}</a-tag>
          </div>
          <div>
            <a-typography-text type="secondary">日期：</a-typography-text>
            <a-typography-text style="margin-left: 8px;">{{ formatDate(selectedEvent.date) }}</a-typography-text>
          </div>
          <div v-if="selectedEvent.organization">
            <a-typography-text type="secondary">相关组织：</a-typography-text>
            <a-tag color="green" style="margin-left: 8px;">{{ selectedEvent.organization }}</a-tag>
          </div>
          <div v-if="selectedEvent.description">
            <a-typography-text type="secondary">描述：</a-typography-text>
            <a-typography-text style="margin-left: 8px;">{{ selectedEvent.description }}</a-typography-text>
          </div>
          <div>
            <a-typography-text type="secondary">相关组织数量：</a-typography-text>
            <a-typography-text strong style="margin-left: 8px;">{{ total }} 个</a-typography-text>
          </div>
        </a-space>
      </div>
      <div v-else-if="selectedOrganization" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #f0f0f0;">
        <a-space direction="vertical" style="width: 100%;" :size="8">
          <div>
            <a-typography-text strong>选中组织：</a-typography-text>
            <a-tag color="green" style="margin-left: 8px;">{{ selectedOrganization.name }}</a-tag>
          </div>
          <div>
            <a-typography-text type="secondary">相关事件数量：</a-typography-text>
            <a-typography-text strong style="margin-left: 8px;">{{ filteredEvents.length }} 个</a-typography-text>
          </div>
        </a-space>
      </div>
    </a-card>

    <!-- 有选中事件或组织时：显示相关组织列表 -->
    <a-spin v-if="selectedEvent || selectedOrganization" :spinning="loading">
      <template v-if="organizationList.length > 0">
        <a-row :gutter="[16, 16]">
          <a-col
            v-for="org in organizationList"
            :key="org.id"
            :xs="24"
            :sm="24"
            :md="selectedOrganization ? 24 : 12"
            :lg="selectedOrganization ? 24 : 8"
            :xl="selectedOrganization ? 24 : 8"
          >
            <a-card
              class="organization-card"
              :bordered="false"
              :hoverable="true"
              :style="{ height: '100%' }"
            >
              <template #title>
                <div class="org-header">
                  <a-tag color="green" style="margin-right: 8px;">
                    APT
                  </a-tag>
                  <a-typography-title :level="4" style="margin: 0; display: inline;">
                    {{ org.name }}
                  </a-typography-title>
                </div>
              </template>
              
              <div class="org-content">
                <!-- 别名 -->
                <div v-if="org.alias && org.alias.length > 0" class="org-section">
                  <a-typography-text type="secondary" strong>
                    别名：
                  </a-typography-text>
                  <a-space wrap style="margin-top: 4px;">
                    <a-tag
                      v-for="(alias, index) in org.alias"
                      :key="index"
                      color="blue"
                    >
                      {{ alias }}
                    </a-tag>
                  </a-space>
                </div>
                
                <!-- 描述 -->
                <div class="org-section">
                  <a-typography-paragraph
                    :ellipsis="{ rows: 3, expandable: false }"
                    :style="{ marginBottom: 0 }"
                  >
                    {{ org.description }}
                  </a-typography-paragraph>
                </div>
                
                <!-- 统计信息 -->
                <div class="org-section">
                  <a-space :size="24">
                    <span>
                      <a-typography-text type="secondary">
                        关联IOC：
                      </a-typography-text>
                      <a-typography-text strong>
                        {{ org.iocCount ?? 0 }} 个
                      </a-typography-text>
                    </span>
                    <span>
                      <a-typography-text type="secondary">
                        关联事件：
                      </a-typography-text>
                      <a-typography-text strong>
                        {{ org.eventCount ?? 0 }} 个
                      </a-typography-text>
                    </span>
                  </a-space>
                </div>
                
                <!-- 区域和来源 -->
                <div class="org-section">
                  <a-space wrap>
                    <a-tag v-if="org.region" color="cyan">
                      区域：{{ org.region }}
                    </a-tag>
                    <a-tag v-if="org.origin" color="orange">
                      来源：{{ org.origin }}
                    </a-tag>
                  </a-space>
                </div>
                
                <!-- 曾用域名 -->
                <div v-if="org.previousDomains && org.previousDomains.length > 0" class="org-section">
                  <a-typography-text type="secondary" strong>
                    曾用域名：
                  </a-typography-text>
                  <div style="margin-top: 8px;">
                    <a-space wrap>
                      <a-tag
                        v-for="(domain, index) in org.previousDomains"
                        :key="index"
                        color="purple"
                        style="font-family: monospace; font-size: 11px;"
                      >
                        {{ domain }}
                      </a-tag>
                    </a-space>
                  </div>
                </div>
                
                <!-- VPS分布 -->
                <div v-if="org.vpsProviders && org.vpsProviders.length > 0" class="org-section">
                  <a-typography-text type="secondary" strong>
                    VPS分布：各组织的VPS服务商使用偏好
                  </a-typography-text>
                  <div style="margin-top: 8px;">
                    <!-- VPS分布图表 -->
                    <div :id="`vps-chart-${org.id}`" style="height: 200px; margin-bottom: 8px;" />
                    
                    <!-- VPS服务商列表 -->
                    <a-list
                      :data-source="org.vpsProviders"
                      :pagination="false"
                      size="small"
                      :bordered="true"
                    >
                      <template #renderItem="{ item }">
                        <a-list-item>
                          <a-row style="width: 100%;" :gutter="8">
                            <a-col :span="12">
                              <a-typography-text strong>
                                {{ item.provider }}
                              </a-typography-text>
                            </a-col>
                            <a-col :span="6" style="text-align: right;">
                              <a-typography-text type="secondary">
                                {{ item.count }} 个
                              </a-typography-text>
                            </a-col>
                            <a-col :span="6" style="text-align: right;">
                              <a-tag color="blue">
                                {{ item.percentage }}%
                              </a-tag>
                            </a-col>
                          </a-row>
                        </a-list-item>
                      </template>
                    </a-list>
                  </div>
                </div>
                
                <!-- 更新时间 -->
                <div class="org-section" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #f0f0f0;">
                  <a-typography-text type="secondary" style="font-size: 12px;">
                    更新时间：{{ formatDate(org.updateTime) }}
                  </a-typography-text>
                </div>
              </div>
            </a-card>
          </a-col>
        </a-row>
      </template>
      <a-empty v-else-if="!loading" description="暂无相关组织数据" :style="{ marginTop: '50px' }" />
    </a-spin>
    
  </page-container>
</template>

<style scoped lang="less">
.organization-card {
  transition: all 0.3s;
  
  &:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    transform: translateY(-2px);
  }
  
  :deep(.ant-card-head-title) {
    padding: 16px 0 8px 0;
  }
  
  :deep(.ant-card-body) {
    padding: 0 24px 24px 24px;
  }
}

.org-header {
  display: flex;
  align-items: center;
}

.org-content {
  .org-section {
    margin-bottom: 16px;
    
    &:last-child {
      margin-bottom: 0;
    }
  }
}

.map-wrapper {
  background: #ffffff;
  border-radius: 4px;
  padding: 12px;
}

.map-canvas {
  position: relative;
  height: 560px;
  background-color: #ffffff;
  background-image:
    linear-gradient(rgba(0, 0, 0, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 0, 0, 0.03) 1px, transparent 1px),
    url('@/assets/world-map.png');
  background-size: 40px 40px, 40px 40px, contain;
  background-repeat: repeat, repeat, no-repeat;
  background-position: left top, left top, center center;
  overflow: visible;
}

.region-anchor {
  position: absolute;
  transform: translate(-30%, -20%);
  color: #1890ff;
  min-width: 140px;
  z-index: 10;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.anchor-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #1890ff;
  box-shadow: 0 0 8px rgba(24, 144, 255, 0.6);
  margin: 4px auto 6px auto;
  flex-shrink: 0;
}

.anchor-title {
  text-align: center;
  font-weight: 600;
  margin-bottom: 0;
  color: #1890ff;
  font-size: 14px;
  white-space: nowrap;
  order: -1;
}

.anchor-panel {
  background: rgba(210, 180, 140, 0.85);
  border: 1px solid rgba(139, 115, 85, 0.5);
  border-radius: 8px;
  padding: 10px 12px;
  max-width: 300px;
  min-width: 120px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(4px);
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 4px;
}

.anchor-orgs-above {
  background: rgba(210, 180, 140, 0.85);
  border: 1px solid rgba(139, 115, 85, 0.5);
  border-radius: 8px;
  padding: 8px 10px;
  margin-bottom: 6px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(4px);
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 4px;
}

.org-tag {
  margin: 0 !important;
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 4px;
  white-space: nowrap;
  display: inline-block;
  line-height: 1.4;
}

.clickable {
  cursor: pointer;
  transition: all 0.2s;
  
  &:hover {
    transform: scale(1.05);
    box-shadow: 0 2px 8px rgba(24, 144, 255, 0.4);
  }
}


:deep(.ant-list-item) {
  padding: 8px 12px;
}

:deep(.ant-typography-paragraph) {
  margin-bottom: 0;
  color: rgba(0, 0, 0, 0.85);
  line-height: 1.8;
}
</style>
