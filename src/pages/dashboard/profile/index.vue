<script setup lang="ts">
import { Pie } from '@antv/g2plot'
import { SearchOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import { onMounted, nextTick, watch } from 'vue'
import type { OrganizationProfile } from '~/api/dashboard/profile'

defineOptions({ name: 'DashboardProfile' })

// 搜索关键词
const searchKeyword = ref<string>('')
const loading = ref(false)

// 组织列表
const organizationList = ref<OrganizationProfile[]>([])
const total = ref(0)

// 重点组织数据（演示数据）
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
  loadMockData()
})

// 加载演示数据
function loadMockData() {
  loading.value = true
  setTimeout(() => {
    // 如果有搜索关键词，进行筛选；否则显示所有组织
    if (searchKeyword.value && searchKeyword.value.trim()) {
      const keyword = searchKeyword.value.trim().toLowerCase()
      const filteredData = mockOrganizations.filter(org =>
        org.name.toLowerCase().includes(keyword),
      )
      organizationList.value = filteredData
      total.value = filteredData.length
    } else {
      // 没有搜索关键词时，显示所有组织
      organizationList.value = [...mockOrganizations]
      total.value = mockOrganizations.length
    }
    loading.value = false
  }, 300)
}

// 搜索防抖定时器
let searchTimer: ReturnType<typeof setTimeout> | null = null

// 搜索
function handleSearch() {
  // 清除之前的定时器
  if (searchTimer) {
    clearTimeout(searchTimer)
  }
  // 设置新的定时器，300ms后执行搜索
  searchTimer = setTimeout(() => {
    loadMockData()
  }, 300)
}

// 监听搜索关键词变化，实时搜索
watch(
  searchKeyword,
  () => {
    handleSearch()
  },
)


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

</script>

<template>
  <page-container>
    <!-- 搜索区域 -->
    <a-card :bordered="false" :style="{ marginBottom: '24px' }">
      <a-space :size="16" style="width: 100%;">
        <a-input
          v-model:value="searchKeyword"
          placeholder="请输入APT组织名称"
          style="flex: 1"
          size="large"
          @press-enter="handleSearch"
        >
          <template #prefix>
            <SearchOutlined />
          </template>
        </a-input>
        <a-button
          type="primary"
          size="large"
          @click="handleSearch"
        >
          <template #icon>
            <SearchOutlined />
          </template>
          搜索
        </a-button>
      </a-space>
      <a-divider v-if="searchKeyword" style="margin: 12px 0;" />
      <a-typography-text v-if="searchKeyword" type="secondary">
        共 {{ total }} 个筛选结果
      </a-typography-text>
    </a-card>

    <!-- 组织列表 -->
    <a-spin :spinning="loading">
      <template v-if="organizationList.length > 0">
        <a-row :gutter="[16, 16]">
          <a-col
            v-for="org in organizationList"
            :key="org.id"
          :xs="24"
          :sm="24"
          :md="12"
          :lg="8"
          :xl="8"
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
      
      <!-- 空状态 -->
      <a-empty
        v-else-if="!loading"
        :description="searchKeyword && searchKeyword.trim() ? '未找到匹配的组织' : '暂无组织数据'"
        :style="{ marginTop: '50px' }"
      />
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
  border-radius: 8px;
  padding: 12px;
  border: 1px solid #e8e8e8;
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
