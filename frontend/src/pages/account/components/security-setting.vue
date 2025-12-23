<script setup lang="ts">
import type { UnwrapRef } from 'vue'
import { message } from 'ant-design-vue'
import { useAuthorization } from '~/composables/authorization'
import { useUserId } from '~/composables/user-id'

interface FormState {
  oldPassword: string
  newPassword: string
  confirmPassword: string
}

const { t } = useI18n()
const API_BASE = 'http://localhost'
const token = useAuthorization()
const userId = useUserId()

function buildHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra, 'Content-Type': 'application/json' }
  if (userId.value)
    headers['X-User-Id'] = userId.value
  if (token.value)
    headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

const formRef = ref()
const labelCol = { span: 4 }
const wrapperCol = { span: 16 }
const formState: UnwrapRef<FormState> = reactive({
  oldPassword: '',
  newPassword: '',
  confirmPassword: '',
})

const rules: any = computed(() => {
  return {
    oldPassword: [
      { required: true, message: '请输入当前密码', trigger: 'blur' },
    ],
    newPassword: [
      { required: true, message: '请输入新密码', trigger: 'blur' },
      { min: 4, message: '密码长度至少4位', trigger: 'blur' },
    ],
    confirmPassword: [
      { required: true, message: '请确认新密码', trigger: 'blur' },
      {
        validator: (_rule: any, value: string) => {
          if (value !== formState.newPassword) {
            return Promise.reject('两次输入的密码不一致')
          }
          return Promise.resolve()
        },
        trigger: 'blur',
      },
    ],
  }
})

async function onSubmit() {
  formRef.value
    .validate()
    .then(async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/account/password`, {
          method: 'PUT',
          headers: buildHeaders(),
          body: JSON.stringify({
            old_password: formState.oldPassword,
            new_password: formState.newPassword,
          }),
        })
        
        if (!resp.ok) {
          const errorData = await resp.json().catch(() => ({ message: '修改密码失败' }))
          throw new Error(errorData.message || errorData.detail || '修改密码失败')
        }
        
        const json = await resp.json()
        if (json.code === 0) {
          message.success('密码修改成功')
          // 重置表单
          formState.oldPassword = ''
          formState.newPassword = ''
          formState.confirmPassword = ''
          formRef.value?.resetFields()
        }
        else {
          throw new Error(json.message || '修改密码失败')
        }
      }
      catch (e: any) {
        message.error(`修改密码失败：${e?.message || '未知错误'}`)
      }
    })
    .catch((error: any) => {
      console.log('validation error', error)
    })
}
</script>

<template>
  <a-card :title="t('account.settings.security-setting')" :bordered="false">
    <a-form
      ref="formRef"
      :model="formState"
      :rules="rules"
      :label-col="labelCol"
      :wrapper-col="wrapperCol"
    >
      <a-form-item label="当前密码" name="oldPassword">
        <a-input-password v-model:value="formState.oldPassword" placeholder="请输入当前密码" style="width: 320px;" />
      </a-form-item>
      <a-form-item label="新密码" name="newPassword">
        <a-input-password v-model:value="formState.newPassword" placeholder="请输入新密码（至少4位）" style="width: 320px;" />
      </a-form-item>
      <a-form-item label="确认新密码" name="confirmPassword">
        <a-input-password v-model:value="formState.confirmPassword" placeholder="请再次输入新密码" style="width: 320px;" />
      </a-form-item>
      <a-form-item>
        <a-button type="primary" @click="onSubmit">
          {{ t('account.settings.modify') }}
        </a-button>
      </a-form-item>
    </a-form>
  </a-card>
</template>

<style scoped lang="less">
:deep(.ant-card-body) {
  padding-left: 0 !important;
}
</style>
