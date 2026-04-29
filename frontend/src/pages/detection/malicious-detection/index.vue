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
  <page-container class="task-center-page">
    <a-card class="hero-card" :bordered="false">
      <div class="hero-main">
        <div class="hero-left">
          <div class="hero-title">
            智能检测任务中心
          </div>
          <div class="hero-desc">
            支持恶意性检测与仿冒域名检测。请选择检测模型和数据来源，提交后可在「我的任务」中查看进度与结果。
          </div>
        </div>
        <div class="hero-right">
          <div class="hero-metric">
            <div class="metric-label">
              支持文件
            </div>
            <div class="metric-value">
              CSV / TXT / XLSX
            </div>
          </div>
          <div class="hero-metric">
            <div class="metric-label">
              单文件限制
            </div>
            <div class="metric-value">
              ≤ 5MB
            </div>
          </div>
          <div class="hero-metric">
            <div class="metric-label">
              联动能力
            </div>
            <div class="metric-value">
              支持订阅预警
            </div>
          </div>
        </div>
      </div>
    </a-card>

    <a-tabs v-model:activeKey="activeTab" class="task-tabs">
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
:deep(.ant-pro-page-container-children-content) {
  background: #f5f7fb;
}

:deep(.ant-tabs-nav) {
  margin-bottom: 20px;
}

:deep(.ant-tabs-tab-active .ant-tabs-tab-btn) {
  color: #1677ff;
  font-weight: 600;
}

:deep(.ant-tabs-content) {
  padding-top: 8px;
}

.task-center-page {
  padding-bottom: 8px;
}

.hero-card {
  max-width: 1160px;
  margin: 0 auto 18px;
  border-radius: 16px;
  box-shadow: 0 8px 24px rgba(15, 35, 80, 0.06);
  border: 1px solid rgba(220, 226, 235, 0.9);
  background: linear-gradient(135deg, #f8fbff 0%, #eef5ff 100%);
}

.hero-main {
  display: flex;
  gap: 20px;
  justify-content: space-between;
  align-items: stretch;
}

.task-tabs {
  max-width: 1160px;
  margin: 0 auto;
}

.hero-left {
  flex: 1;
  min-width: 0;
}

.hero-title {
  font-size: 24px;
  font-weight: 700;
  color: #1f2937;
  margin-bottom: 10px;
}

.hero-desc {
  color: #667085;
  line-height: 1.75;
}

.hero-right {
  width: 320px;
  max-width: 45%;
  display: grid;
  grid-template-columns: 1fr;
  gap: 10px;
}

.hero-metric {
  border-radius: 10px;
  border: 1px solid #dbe7ff;
  background: rgba(255, 255, 255, 0.8);
  padding: 10px 12px;
}

.metric-label {
  font-size: 12px;
  color: #667085;
  margin-bottom: 4px;
}

.metric-value {
  font-size: 14px;
  color: #1f2937;
  font-weight: 600;
}

@media (max-width: 1024px) {
  .hero-main {
    flex-direction: column;
  }

  .hero-right {
    width: 100%;
    max-width: none;
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 768px) {
  .hero-right {
    grid-template-columns: 1fr;
  }
}
</style>
