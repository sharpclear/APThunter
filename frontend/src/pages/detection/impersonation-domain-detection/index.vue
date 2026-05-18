<script setup lang="ts">
import ImpersonationDetectionForm from '../malicious-detection/impersonation-detection-form.vue'

defineOptions({
  name: 'ImpersonationDomainDetection',
})
</script>

<template>
  <page-container class="detection-form-page">
    <ImpersonationDetectionForm />
  </page-container>
</template>

<style scoped>
:deep(.ant-pro-page-container-children-content) {
  background: #f5f7fb;
}

.detection-form-page {
  padding-bottom: 8px;
}
</style>
