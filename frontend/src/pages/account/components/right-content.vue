<script setup lang="ts">
import { ref } from 'vue'
import applicationTab from './application-tab.vue'
import articleTab from './article-tab.vue'
import proTab from './pro-tab.vue'

const { t } = useI18n()

const activeKey = ref()

interface IDataItem {
  title: string
  tags: string[]
  content: string
}

const data = ref<IDataItem[]>([
  {
    title: 'APTHunter',
    tags: ['Ant Design Vue', '中后台', '自动化'],
    content: 'APTHunter 是面向恶意域名检测、模型管理、订阅预警和态势展示的安全分析平台，前端基于 Vue 3、Vite、Ant Design Vue、Pinia 和 UnoCSS 构建。',
  },
])

const dataSource = computed(() => {
  const arr = []
  for (let i = 0; i < 10; i++)
    arr.push(...data.value)

  return arr
})
</script>

<template>
  <a-card :borderer="false">
    <a-tabs v-model:active-key="activeKey">
      <a-tab-pane key="1" :tab="t('account.center.article')">
        <article-tab :data-source="dataSource" />
      </a-tab-pane>
      <a-tab-pane key="2" :tab="t('account.center.application')" force-render>
        <application-tab />
      </a-tab-pane>
      <a-tab-pane key="3" :tab="t('account.center.project')">
        <pro-tab />
      </a-tab-pane>
    </a-tabs>
  </a-card>
</template>

<style scoped lang="less">
:deep(.ant-list-item) {
  flex-direction: column !important;
  align-items: normal !important;
}
:deep(.ant-btn) {
  padding-left: 0;
}
</style>
