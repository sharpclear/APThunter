<script setup lang="ts">
// 组织画像的mock数据，后续可由接口动态替换
const orgInfo = {
  name: 'APT28 (Fancy Bear)',
  code: 'APT28',
  country: '俄罗斯',
  period: '2007-至今',
  threatLevel: '高',
  target: '政府、军方、能源、电信',
  description: 'APT28 又名 Fancy Bear，是活跃于东欧的高级持续性威胁组织，主要针对欧亚大陆政府发起APT网络攻击。',
}
const usedDomains = [
  'mail-login-upd.com',
  'gov-update-portal.net',
  'secure-analytics.top',
  'office365-supportc.com',
  'mailbox-verify.org',
]
const vpsStats = [
  { vendor: 'Vultr', percent: 0.48 },
  { vendor: 'Linode', percent: 0.22 },
  { vendor: '腾讯云', percent: 0.18 },
  { vendor: 'DigitalOcean', percent: 0.12 },
]
const attackChain = [
  { step: '鱼叉邮件(钓鱼)', object: 'mail-login-upd.com', desc: '伪装官方邮箱诱导收件人访问' },
  { step: 'C2通信', object: 'secure-analytics.top', desc: '后门通信域名' },
  { step: '数据投递', object: 'office365-supportc.com', desc: '窃取凭证传递' },
]
const activityArea = [
  { area: '乌克兰', count: 57 },
  { area: '德国', count: 39 },
  { area: '法国', count: 29 },
  { area: '中国', count: 21 },
]
const activityTimeline = [
  { month: '2024-06', count: 32 },
  { month: '2024-07', count: 44 },
  { month: '2024-08', count: 28 },
  { month: '2024-09', count: 54 },
]

// ...其他接口/数据占位...
</script>

<template>
  <page-container>
    <a-row gutter="24">
      <a-col :md="8" :xs="24">
        <a-card bordered shadow>
          <h3>组织信息</h3>
          <ul>
            <li><b>组织名称：</b>{{ orgInfo.name }}</li>
            <li><b>组织代号：</b>{{ orgInfo.code }}</li>
            <li><b>活跃时期：</b>{{ orgInfo.period }}</li>
            <li><b>归属地：</b>{{ orgInfo.country }}</li>
            <li><b>主要攻击目标：</b>{{ orgInfo.target }}</li>
            <li><b>威胁评级：</b>{{ orgInfo.threatLevel }}</li>
          </ul>
          <div class="desc">
            简介：{{ orgInfo.description }}
          </div>
        </a-card>
        <a-card bordered style="margin-top: 16px">
          <h3>VPS服务商分布</h3>
          <div v-for="item in vpsStats" :key="item.vendor" style="margin:4px 0">
            <span>{{ item.vendor }}</span>
            <a-progress :percent="item.percent * 100" style="width:70%" :show-info="false" status="active" />
          </div>
        </a-card>
      </a-col>
      <a-col :md="16" :xs="24">
        <a-card bordered>
          <h3>活跃地域分布</h3>
          <a-table
            :pagination="false" size="small" :data-source="activityArea" :columns="[
              { title: '地域', dataIndex: 'area' },
              { title: '活跃次数', dataIndex: 'count' },
            ]" row-key="area"
          />
        </a-card>
        <a-card style="margin-top: 16px" bordered>
          <h3>活动时间分布</h3>
          <a-table
            :pagination="false" size="small" :data-source="activityTimeline" :columns="[
              { title: '月份', dataIndex: 'month' },
              { title: '活跃次数', dataIndex: 'count' },
            ]" row-key="month"
          />
        </a-card>
        <a-card style="margin-top: 16px" bordered>
          <h3>主要攻击链</h3>
          <a-table
            :pagination="false" size="small" :data-source="attackChain" :columns="[
              { title: '步骤', dataIndex: 'step' },
              { title: '相关对象', dataIndex: 'object' },
              { title: '说明', dataIndex: 'desc' },
            ]" row-key="object"
          />
        </a-card>
        <a-card style="margin-top: 16px" bordered>
          <h3>曾用域名</h3>
          <ul>
            <li v-for="d in usedDomains" :key="d">
              {{ d }}
            </li>
          </ul>
        </a-card>
      </a-col>
    </a-row>
  </page-container>
</template>

<style scoped>
h3 {
  margin: 0 0 12px 0;
}
ul {
  padding-left: 18px;
}
.desc {
  color: #777;
  margin-top: 10px;
  font-size: 13px;
}
</style>
