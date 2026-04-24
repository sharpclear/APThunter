<script setup lang="ts">
import { ref } from 'vue'
import MaliciousDetectionForm from './malicious-detection-form.vue'
import ImpersonationDetectionForm from './impersonation-detection-form.vue'

defineOptions({
  name: 'CreateTask',
})

const activeTab = ref('malicious')
</script>

<template>
  <page-container>
    <a-tabs v-model:activeKey="activeTab" style="max-width:1200px;margin:0 auto;">
      <a-tab-pane key="malicious" tab="恶意性检测">
        <MaliciousDetectionForm />
      </a-tab-pane>
      <a-tab-pane key="impersonation" tab="仿冒域名检测">
        <ImpersonationDetectionForm />
      </a-tab-pane>
    </a-tabs>
  </page-container>
</template>

<style scoped>
:deep(.ant-tabs-content) {
  padding-top: 24px;
}
</style>
