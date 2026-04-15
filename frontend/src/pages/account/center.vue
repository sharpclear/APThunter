<script setup lang="ts">
import { message } from 'ant-design-vue'
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import RightContent from './components/right-content.vue'

const API_BASE = 'http://localhost'
const token = useAuthorization()
const userId = useUserId()
const router = useRouter()
const loading = ref(false)

interface UserProfile {
  email: string
  name: string
  bio: string
}

interface RecentTask {
  task_id: string
  task_type: string
  task_type_label: string
  status: string
  status_label: string
  model_name: string
  created_at: string
}

interface StatsData {
  task_count: number
  model_count: number
  sub_count: number
  created_at: string | null
  recent_tasks: RecentTask[]
}

const userProfile = ref<UserProfile>({ email: '', name: '', bio: '' })
const stats = ref<StatsData>({
  task_count: 0,
  model_count: 0,
  sub_count: 0,
  created_at: null,
  recent_tasks: [],
})

// 根据用户名生成头像背景色
const avatarBgColor = computed(() => {
  const colors = ['#1677ff', '#52c41a', '#fa8c16', '#eb2f96', '#722ed1', '#13c2c2']
  const name = userProfile.value.name || 'U'
  return colors[name.charCodeAt(0) % colors.length]
})

// 头像首字母
const avatarLetter = computed(() => {
  return (userProfile.value.name || 'U').charAt(0).toUpperCase()
})

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

async function loadData() {
  loading.value = true
  try {
    const [profileResp, statsResp] = await Promise.all([
      fetch(`${API_BASE}/api/account/profile`, { headers: buildHeaders() }),
      fetch(`${API_BASE}/api/account/stats`, { headers: buildHeaders() }),
    ])

    if (profileResp.status === 401) {
      message.error('未认证或token已过期，请重新登录')
      return
    }
    if (profileResp.ok) {
      const json = await profileResp.json()
      if (json.code === 0 && json.data)
        userProfile.value = { email: json.data.email || '', name: json.data.name || '', bio: json.data.bio || '' }
    }

    if (statsResp.ok) {
      const json = await statsResp.json()
      if (json.code === 0 && json.data)
        stats.value = json.data
    }
  }
  catch (e: any) {
    message.error(`加载用户信息失败：${e?.message || '未知错误'}`)
  }
  finally {
    loading.value = false
  }
}

const quickActions = [
  { icon: 'i-ant-design:thunderbolt-outlined', label: '创建检测', desc: '上传文件开始检测', color: '#1677ff', bg: '#e8f4ff', path: '/list/task' },
  { icon: 'i-ant-design:experiment-outlined',  label: '模型训练', desc: '训练自定义模型',   color: '#722ed1', bg: '#f5f0ff', path: '/list/training' },
  { icon: 'i-ant-design:setting-outlined',     label: '账号设置', desc: '修改个人信息',     color: '#13c2c2', bg: '#e6fffb', path: '/account/settings' },
  { icon: 'i-ant-design:lock-outlined',        label: '修改密码', desc: '更新登录密码',     color: '#fa8c16', bg: '#fff7e6', path: '/account/settings' },
]

onMounted(() => loadData())
</script>

<template>
  <a-row :gutter="[24, 24]" class="profile-row">
    <!-- 左侧：个人信息 -->
    <a-col :xs="24" :sm="24" :md="8" class="col-flex">
      <a-spin :spinning="loading" class="spin-flex">
        <a-card :body-style="{ padding: 0 }" class="profile-card overflow-hidden card-fill">
          <!-- 渐变横幅 -->
          <div
            class="profile-banner"
            :style="{ background: `linear-gradient(135deg, ${avatarBgColor}cc 0%, ${avatarBgColor}66 100%)` }"
          />

          <!-- 头像区域（悬浮在横幅上） -->
          <div class="flex flex-col items-center px-6" style="margin-top: -44px;">
            <a-avatar
              :size="88"
              :style="{
                backgroundColor: avatarBgColor,
                fontSize: '36px',
                fontWeight: '700',
                border: '3px solid #fff',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                flexShrink: 0,
              }"
            >
              {{ avatarLetter }}
            </a-avatar>

            <div class="mt-3 font-bold text-18px text-center leading-snug text-gray-800">
              {{ userProfile.name || '未设置用户名' }}
            </div>
            <a-tag color="blue" class="mt-2" style="margin: 0;">
              普通用户
            </a-tag>
            <div class="mt-2 text-gray-400 text-13px text-center px-2 leading-snug min-h-10">
              {{ userProfile.bio || '这个人很懒，什么都没留下～' }}
            </div>
          </div>

          <!-- 统计数据 -->
          <div class="mx-5 mt-4 rounded-xl overflow-hidden stats-row">
            <a-row :gutter="0">
              <a-col :span="8" class="stat-item stat-item--blue">
                <div class="stat-num">{{ stats.task_count }}</div>
                <div class="stat-label">检测任务</div>
              </a-col>
              <a-col :span="8" class="stat-item stat-item--purple">
                <div class="stat-num">{{ stats.model_count }}</div>
                <div class="stat-label">使用模型</div>
              </a-col>
              <a-col :span="8" class="stat-item stat-item--cyan">
                <div class="stat-num">{{ stats.sub_count }}</div>
                <div class="stat-label">订阅任务</div>
              </a-col>
            </a-row>
          </div>

          <!-- 详细信息 -->
          <div class="px-5 mt-5 pb-1">
            <div class="info-item">
              <span class="i-ant-design:mail-outlined info-icon" />
              <span class="info-text break-all">{{ userProfile.email || '未设置邮箱' }}</span>
            </div>
            <div v-if="stats.created_at" class="info-item">
              <span class="i-ant-design:calendar-outlined info-icon" />
              <span class="info-text">注册于 {{ stats.created_at.slice(0, 10) }}</span>
            </div>
            <div class="info-item">
              <span class="i-ant-design:safety-certificate-outlined info-icon" />
              <span class="info-text text-green-600">账号安全状态良好</span>
            </div>
          </div>

          <a-divider class="mx-5" style="margin-left:20px; margin-right:20px; min-width:auto; width:auto;" />

          <!-- 编辑资料按钮 -->
          <div class="px-5 pb-5">
            <a-button type="primary" block ghost @click="router.push('/account/settings')">
              <template #icon>
                <span class="i-ant-design:edit-outlined" />
              </template>
              编辑资料
            </a-button>
          </div>
        </a-card>
      </a-spin>
    </a-col>

    <!-- 中间：近期检测任务 -->
    <a-col :xs="24" :sm="12" :md="8" class="col-flex">
      <RightContent :recent-tasks="stats.recent_tasks" :loading="loading" />
    </a-col>

    <!-- 右侧：快捷入口 -->
    <a-col :xs="24" :sm="12" :md="8" class="col-flex">
      <a-card class="quick-card card-fill" :body-style="{ padding: '20px' }">
        <template #title>
          <span><span class="i-ant-design:appstore-outlined mr-2" />快捷入口</span>
        </template>
        <a-row :gutter="[12, 12]">
          <a-col v-for="action in quickActions" :key="action.label" :span="12">
            <div class="action-card" @click="router.push(action.path)">
              <div class="action-icon-wrap" :style="{ background: action.bg }">
                <span :class="action.icon" :style="{ color: action.color, fontSize: '24px' }" />
              </div>
              <div class="mt-3 font-semibold text-14px text-gray-800">{{ action.label }}</div>
              <div class="text-12px text-gray-400 mt-1">{{ action.desc }}</div>
            </div>
          </a-col>
        </a-row>
        <div class="security-banner">
          <span class="i-ant-design:check-circle-filled text-green-500 text-18px flex-shrink-0" />
          <div>
            <div class="text-13px font-medium text-gray-700">账号安全状态良好</div>
            <div class="text-12px text-gray-400">密码已设置，登录保护已开启</div>
          </div>
        </div>
      </a-card>
    </a-col>
  </a-row>
</template>

<style scoped lang="less">
/* ---- 等高三列布局 ---- */
.profile-row {
  :deep(.ant-row) { align-items: stretch; }
}

.col-flex {
  display: flex !important;
  flex-direction: column;
}

.spin-flex {
  flex: 1;
  display: flex;
  flex-direction: column;
  :deep(.ant-spin-nested-loading),
  :deep(.ant-spin-container) {
    flex: 1;
    display: flex;
    flex-direction: column;
  }
}

.card-fill {
  flex: 1;
  display: flex;
  flex-direction: column;
  :deep(.ant-card-body) {
    flex: 1;
    display: flex;
    flex-direction: column;
  }
}

/* ---- 个人信息卡片 ---- */
.profile-card {
  border-radius: 12px;
}

.profile-banner {
  height: 96px;
  width: 100%;
}

.stats-row {
  border: 1px solid #f0f0f0;
  border-radius: 12px;
  overflow: hidden;
}

.stat-item {
  padding: 12px 0;
  text-align: center;
  position: relative;
  &::after {
    content: '';
    position: absolute;
    right: 0;
    top: 20%;
    height: 60%;
    width: 1px;
    background: #f0f0f0;
  }
  &:last-child::after { display: none; }

  &--blue  { background: #e8f4ff; }
  &--purple { background: #f5f0ff; }
  &--cyan  { background: #e6fffb; }

  .stat-num {
    font-size: 22px;
    font-weight: 700;
    line-height: 1.2;
    color: #1677ff;
  }
  &--purple .stat-num { color: #722ed1; }
  &--cyan   .stat-num { color: #13c2c2; }

  .stat-label {
    font-size: 12px;
    color: #8c8c8c;
    margin-top: 2px;
  }
}

.info-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 0;
  font-size: 13px;
  border-bottom: 1px dashed #f5f5f5;
  &:last-child { border-bottom: none; }
}
.info-icon {
  font-size: 15px;
  color: #bfbfbf;
  flex-shrink: 0;
}
.info-text {
  color: #595959;
}

/* ---- 快捷入口卡片 ---- */
.quick-card {
  border-radius: 12px;
}

.action-card {
  background: #fff;
  border: 1px solid #f0f0f0;
  border-radius: 12px;
  padding: 16px 12px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  height: 100%;
  &:hover {
    border-color: #1677ff;
    box-shadow: 0 4px 16px rgba(22, 119, 255, 0.12);
    transform: translateY(-2px);
  }
}

.action-icon-wrap {
  width: 48px;
  height: 48px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto;
}

.security-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #f6ffed;
  border: 1px solid #b7eb8f;
  border-radius: 8px;
  padding: 12px 16px;
  margin-top: auto;
  padding-top: 16px;
}
</style>
