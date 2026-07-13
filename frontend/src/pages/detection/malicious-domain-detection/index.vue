<script setup lang="ts">
import UnifiedMaliciousDomainDetectionForm from '../malicious-detection/unified-malicious-domain-detection-form.vue'

defineOptions({
  name: 'MaliciousDomainDetection',
})
</script>

<template>
  <page-container class="detection-form-page">
    <UnifiedMaliciousDomainDetectionForm />
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
