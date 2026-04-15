<script setup lang="ts">
import { getLatestThreatsApi, type LatestThreat } from '~/api/dashboard/statistics'

const loading = ref(false)
const threats = ref<LatestThreat[]>([])
const pagination = ref({
  current: 1,
  pageSize: 10,
  total: 0,
})

const threatLevelMap = {
  high: { text: '高危', color: '#ff4d4f' },
  medium: { text: '中危', color: '#faad14' },
  low: { text: '低危', color: '#52c41a' },
}

async function loadThreats() {
  loading.value = true
  try {
    const res = await getLatestThreatsApi({
      page: pagination.value.current,
      pageSize: pagination.value.pageSize,
    })
    if (res && res.data) {
      threats.value = res.data.list || []
      pagination.value.total = res.data.total || 0
    }
  }
  catch (error) {
    console.error('加载威胁数据失败:', error)
  }
  finally {
    loading.value = false
  }
}

function formatTime(time: string) {
  const date = new Date(time)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)

  if (days > 0)
    return `${days}天前`
  if (hours > 0)
    return `${hours}小时前`
  if (minutes > 0)
    return `${minutes}分钟前`
  return '刚刚'
}

onMounted(() => {
  loadThreats()
  // 每30秒刷新一次
  const timer = setInterval(() => {
    loadThreats()
  }, 30000)
  onBeforeUnmount(() => {
    clearInterval(timer)
  })
})
</script>

<template>
  <div class="latest-threats">
    <a-list
      :loading="loading"
      :data-source="threats"
      :pagination="{
        ...pagination,
        size: 'small',
        showSizeChanger: false,
        showTotal: (total) => `共 ${total} 条`,
        onChange: (page) => {
          pagination.current = page
          loadThreats()
        },
      }"
    >
      <template #renderItem="{ item }">
        <a-list-item>
          <a-list-item-meta>
            <template #title>
              <div class="threat-item">
                <a-tag :color="threatLevelMap[item.threatLevel].color" class="threat-level">
                  {{ threatLevelMap[item.threatLevel].text }}
                </a-tag>
                <span class="domain">{{ item.domain }}</span>
                <span class="organization">{{ item.organization }}</span>
              </div>
            </template>
            <template #description>
              <div class="threat-desc">
                <span v-if="item.description" class="desc-text">{{ item.description }}</span>
                <span class="time">{{ formatTime(item.discoveryTime) }}</span>
              </div>
              <div v-if="item.tags && item.tags.length > 0" class="threat-tags">
                <a-tag v-for="tag in item.tags" :key="tag" size="small">{{ tag }}</a-tag>
              </div>
            </template>
          </a-list-item-meta>
        </a-list-item>
      </template>
    </a-list>
  </div>
</template>

<style scoped lang="less">
.latest-threats {
  .threat-item {
    display: flex;
    align-items: center;
    gap: 8px;

    .threat-level {
      flex-shrink: 0;
    }

    .domain {
      font-weight: 500;
      color: var(--ant-color-text);
    }

    .organization {
      color: var(--ant-color-text-secondary);
      font-size: 12px;
    }
  }

  .threat-desc {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 4px;

    .desc-text {
      color: var(--ant-color-text-secondary);
      font-size: 12px;
    }

    .time {
      color: var(--ant-color-text-tertiary);
      font-size: 12px;
    }
  }

  .threat-tags {
    margin-top: 8px;
  }
}
</style>

