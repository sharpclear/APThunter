<script setup lang="ts">
import MaliciousDetectionForm from '../malicious-detection/malicious-detection-form.vue'

defineOptions({
  name: 'MaliciousDomainDetection',
})
</script>

<template>
  <page-container class="detection-form-page">
    <MaliciousDetectionForm />
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
