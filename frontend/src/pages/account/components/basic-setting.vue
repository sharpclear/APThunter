<script setup lang="ts">
import type { UnwrapRef } from 'vue'
import { message } from 'ant-design-vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'

interface FormState {
  email: string
  name: string
  desc: string
}

const { t } = useI18n()
const API_BASE = 'http://localhost'
const token = useAuthorization()
const userId = useUserId()
const loading = ref(false)

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra, 'Content-Type': 'application/json' }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

const formRef = ref()
const labelCol = { span: 0 }
const wrapperCol = { span: 13 }
const formState: UnwrapRef<FormState> = reactive({
  email: '',
  name: '',
  desc: '',
})
const rules: any = computed(() => {
  return {
    name: [
      { required: true, message: t('account.settings.form-rule-name'), trigger: 'change' },
    ],
    email: [
      { required: true, message: t('account.settings.form-rule-email'), trigger: 'change' },
      { type: 'email', message: '请输入有效的邮箱地址', trigger: 'change' },
    ],
    // 个人简介不是必填项，不添加required规则
  }
})

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
      formState.email = json.data.email || ''
      formState.name = json.data.name || ''
      formState.desc = json.data.bio || ''
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

async function onSubmit() {
  formRef.value
    .validate()
    .then(async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/account/profile`, {
          method: 'PUT',
          headers: buildHeaders(),
          body: JSON.stringify({
            email: formState.email,
            name: formState.name,
            bio: formState.desc,
          }),
        })
        
        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({ message: '更新失败' }))
          throw new Error(errorData.message || errorData.detail || '更新失败')
        }
        
        const json = await resp.json()
        if (json.code === 0) {
          message.success('更新成功')
        }
        else {
          throw new Error(json.message || '更新失败')
        }
      }
      catch (e: any) {
        message.error(`更新失败：${e?.message || '未知错误'}`)
      }
    })
    .catch((error: any) => {
      console.log('validation error', error)
    })
}

// 页面加载时获取用户信息
onMounted(() => {
  loadProfile()
})

</script>

<template>
  <a-card :title="t('account.settings.basic-setting')" :bordered="false">
    <a-row>
      <a-col :span="12">
        <a-spin :spinning="loading">
          <a-form
            ref="formRef"
            :model="formState"
            :rules="rules"
            :label-col="labelCol"
            :wrapper-col="wrapperCol"
          >
            <a-form-item :label-col="{ span: 24 }" :label="t('account.settings.form-email')" name="email">
              <a-input v-model:value="formState.email" :placeholder="t('account.settings.form-input-plac')" style="width: 320px;" />
            </a-form-item>
            <a-form-item :label-col="{ span: 24 }" :label="t('account.settings.form-name')" name="name">
              <a-input v-model:value="formState.name" :placeholder="t('account.settings.form-input-plac')" style="width: 320px;" />
            </a-form-item>
            <a-form-item name="desc" :label="t('account.settings.form-desc')" :label-col="{ span: 24 }">
              <a-textarea v-model:value="formState.desc" :placeholder="t('account.settings.form-input-plac')" :rows="4" />
            </a-form-item>
            <a-form-item>
              <a-button type="primary" @click="onSubmit">
                {{ t('account.settings.form-submit') }}
              </a-button>
            </a-form-item>
          </a-form>
        </a-spin>
      </a-col>
    </a-row>
  </a-card>
</template>
