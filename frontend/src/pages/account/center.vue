<script setup lang="ts">
import { message } from 'ant-design-vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'
import { onMounted, ref } from 'vue'

const API_BASE = 'http://localhost'
const token = useAuthorization()
const userId = useUserId()
const loading = ref(false)

interface UserProfile {
  email: string
  name: string
  bio: string
}

const userProfile = ref<UserProfile>({
  email: '',
  name: '',
  bio: '',
})

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

// 加载用户信息
async function loadProfile() {
  loading.value = true
  try {
    const resp = await fetch(`${API_BASE}/api/account/profile`, {
      method: 'GET',
      headers: buildHeaders(),
    })
    
    if (!resp.ok) {
      if (resp.status === 401) {
        message.error('未认证或token已过期，请重新登录')
        return
      }
      const errorText = await resp.text()
      throw new Error(errorText)
    }
    
    const json = await resp.json()
    if (json.code === 0 && json.data) {
      userProfile.value = {
        email: json.data.email || '',
        name: json.data.name || '',
        bio: json.data.bio || '',
      }
    }
    else {
      throw new Error(json.message || '获取用户信息失败')
    }
  }
  catch (e: any) {
    message.error(`加载用户信息失败：${e?.message || '未知错误'}`)
  }
  finally {
    loading.value = false
  }
}

// 页面加载时获取用户信息
onMounted(() => {
  loadProfile()
})
</script>

<template>
  <div class="gutter-example">
    <a-spin :spinning="loading">
      <a-card>
        <div class="flex justify-center">
          <a-avatar :size="86">
            <template #icon>
              <img src="https://gw.alipayobjects.com/zos/rmsportal/BiazfanxmamNRoxxVxka.png" alt="">
            </template>
          </a-avatar>
        </div>
        <div class="flex flex-col items-center justify-center mt-5">
          <span class="font-bold text-16px">{{ userProfile.name || '未设置用户名' }}</span>
        </div>
        <div class="p-8">
          <p class="mb-4">
            <span class="font-semibold mr-2">邮箱：</span>
            <span>{{ userProfile.email || '未设置邮箱' }}</span>
          </p>
          <p>
            <span class="font-semibold mr-2">个人简介：</span>
            <span>{{ userProfile.bio || '暂无简介' }}</span>
          </p>
        </div>
      </a-card>
    </a-spin>
  </div>
</template>

<style scoped lang="less">

</style>
