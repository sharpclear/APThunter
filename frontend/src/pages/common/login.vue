<script setup lang="ts">
import type { LoginParams } from '~@/api/common/login'
import { LockOutlined, UserOutlined } from '@ant-design/icons-vue'
import { delayTimer } from '@v-c/utils'
import { AxiosError } from 'axios'
import { onBeforeUnmount, onMounted, reactive, ref, shallowRef, unref } from 'vue'
import { useRouter } from 'vue-router'
import pageBubble from '@/utils/page-bubble'
import { loginApi } from '~/api/common/login'
import GlobalLayoutFooter from '~/layouts/components/global-footer/index.vue'
import { getQueryParam } from '~/utils/tools'
import { useUserId } from '~/composables/user-id'

const message = useMessage()
const notification = useNotification()
const appStore = useAppStore()
const { layoutSetting } = storeToRefs(appStore)
const router = useRouter()
const token = useAuthorization()
const userId = useUserId()

// 登录表单
const loginModel = reactive({
  username: undefined as string | undefined,
  password: undefined as string | undefined,
  type: 'account',
  remember: true,
})
const loginFormRef = shallowRef()

// 注册表单
const registerModel = reactive({
  username: '',
  password: '',
  confirm: '',
  email: '',
})
const registerFormRef = shallowRef()
const registerLoading = shallowRef(false)

const { t } = useI18nLocale()

const submitLoading = shallowRef(false)
const errorAlert = shallowRef(false)

const bubbleCanvas = ref<HTMLCanvasElement>()
onMounted(async () => {
  await delayTimer(300)
  pageBubble.init(unref(bubbleCanvas)!)
})
onBeforeUnmount(() => {
  pageBubble.removeListeners()
})

// 登录提交（保持原有逻辑）
async function submit() {
  submitLoading.value = true
  try {
    await loginFormRef.value?.validate()
    const params = {
      username: loginModel.username,
      password: loginModel.password,
    } as unknown as LoginParams
    const { data } = await loginApi(params)
    token.value = data?.token
    // 保存用户ID
    if (data?.user?.userid) {
      userId.value = String(data.user.userid)
    }
    notification.success({
      message: '登录成功',
      description: '欢迎回来！',
      duration: 3,
    })
    const redirect = getQueryParam('redirect', '/')
    router.push({ path: redirect, replace: true })
  }
  catch (e) {
    if (e instanceof AxiosError)
      errorAlert.value = true
    submitLoading.value = false
  }
}

// 验证规则（Antd 兼容）
const usernameRules = [
  { required: true, message: '用户名为必填项' },
  { min: 3, max: 20, message: '用户名长度需在 3 到 20 个字符' },
  { pattern: /^\w+$/, message: '仅允许字母、数字和下划线' },
]
const passwordRules = [
  { required: true, message: '密码为必填项' },
]
const confirmRules = [
  { required: true, message: '请确认密码' },
  {
    validator(_: any, value: string) {
      if (value !== registerModel.password)
        return Promise.reject(new Error('两次输入的密码不一致'))
      return Promise.resolve()
    },
  },
]
const emailRules = [
  {
    validator(_: any, value: string) {
      if (!value)
        return Promise.resolve()
      // 简单邮箱正则
      const re = /^[^\s@]+@[^\s@][^\s.@]*\.[^\s@]+$/
      if (!re.test(value))
        return Promise.reject(new Error('请输入有效的邮箱地址'))
      return Promise.resolve()
    },
  },
]

// 注册提交（调用 /api/register 模拟接口）
async function submitRegister() {
  registerLoading.value = true
  try {
    // 表单校验（若使用 a-form 的 validate 方法）
    await registerFormRef.value?.validate()

    const resp = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: registerModel.username,
        password: registerModel.password,
        email: registerModel.email || undefined,
      }),
    })

    // 尝试解析后端返回的 JSON（兼容不同返回格式）
    const json = await resp.json().catch(() => null)

    if (resp.ok && (json?.success === true || json?.code === 0)) {
      const okMsg = json?.message || json?.msg || '注册成功，已为您跳转到登录页面'
      message.success(okMsg)

      // 自动填充登录用户名并切回登录 tab
      loginModel.username = registerModel.username
      loginModel.type = 'account'

      // 清空注册表单
      registerModel.username = ''
      registerModel.password = ''
      registerModel.confirm = ''
      registerModel.email = ''
    }
    else {
      // 兼容后端不同字段名的错误信息
      const errMsg = json?.message || json?.msg || json?.detail || `注册失败${resp.status ? `（${resp.status}）` : ''}`
      message.error(errMsg)
    }
  }
  catch (e: any) {
    const errMsg = (e?.message) || '注册失败'
    message.error(errMsg)
  }
  finally {
    registerLoading.value = false
  }
}
</script>

<template>
  <div class="login-container">
    <div h-screen w-screen absolute z-10>
      <canvas ref="bubbleCanvas" />
    </div>
    <div class="login-content flex-center">
      <div class="ant-pro-form-login-main rounded">
        <!-- 登录头部 -->
        <div class="flex-between h-15 px-4 mb-[2px]">
          <div class="flex-end">
            <span class="ant-pro-form-login-logo">
              <img w-full h-full object-cover src="/logo.svg">
            </span>
            <span class="ant-pro-form-login-title">APThunter</span>
            <span class="ant-pro-form-login-desc">{{ t("pages.layouts.userLayout.title") }}</span>
          </div>
          <div class="login-lang flex-center relative z-11">
            <span class="flex-center cursor-pointer text-16px" @click="appStore.toggleTheme(layoutSetting.theme === 'dark' ? 'light' : 'dark')">
              <template v-if="layoutSetting.theme === 'light'">
                <carbon-moon />
              </template>
              <template v-else>
                <carbon-sun />
              </template>
            </span>
            <SelectLang />
          </div>
        </div>
        <a-divider m-0 />
        <!-- 登录主体 -->
        <div class="box-border flex min-h-[520px]">
          <!-- 登录框左侧 -->
          <div class="ant-pro-form-login-main-left min-h-[520px] flex-center bg-[var(--bg-color-container)]">
            <img src="@/assets/images/login-left.png" class="h-5/6 w-5/6">
          </div>
          <a-divider m-0 type="vertical" class="ant-pro-login-divider  min-h-[520px]" />
          <!-- 登录框右侧 -->
          <div class="ant-pro-form-login-main-right px-5 w-[335px] flex-center flex-col relative z-11">
            <div class="text-center py-6 text-2xl">
              {{ t('pages.login.tips') }}
            </div>

            <!-- Tabs: 登录 / 注册 -->
            <a-form v-if="loginModel.type === 'account'" ref="loginFormRef" :model="loginModel">
              <a-tabs v-model:active-key="loginModel.type" centered>
                <a-tab-pane key="account" tab="登录" />
                <a-tab-pane key="register" tab="注册" />
              </a-tabs>

              <a-alert v-if="errorAlert" mb-24px :message="t('pages.login.accountLogin.errorMessage')" type="error" show-icon />

              <!-- 登录表单 -->
              <a-form-item name="username" :rules="[{ required: true, message: '请输入用户名' }]">
                <a-input v-model:value="loginModel.username" allow-clear autocomplete="off" placeholder="用户名" size="large" @press-enter="submit">
                  <template #prefix>
                    <UserOutlined />
                  </template>
                </a-input>
              </a-form-item>

              <a-form-item name="password" :rules="[{ required: true, message: '请输入密码' }]">
                <a-input-password v-model:value="loginModel.password" allow-clear placeholder="密码" size="large" @press-enter="submit">
                  <template #prefix>
                    <LockOutlined />
                  </template>
                </a-input-password>
              </a-form-item>

              <div class="mb-24px flex-between">
                <a-checkbox v-model:checked="loginModel.remember">
                  记住我
                </a-checkbox>
                <a>忘记密码</a>
              </div>

              <a-button type="primary" block :loading="submitLoading" size="large" @click="submit">
                登录
              </a-button>
              <div class="mt-12px text-right">
                <a @click="loginModel.type = 'register'">没有账号？去注册</a>
              </div>
            </a-form>

            <!-- 注册表单 -->
            <a-form v-else ref="registerFormRef" :model="registerModel">
              <a-tabs v-model:active-key="loginModel.type" centered>
                <a-tab-pane key="account" tab="登录" />
                <a-tab-pane key="register" tab="注册" />
              </a-tabs>

              <a-form-item name="username" :rules="usernameRules">
                <a-input v-model:value="registerModel.username" allow-clear autocomplete="off" placeholder="用户名（3-20，支持字母数字下划线）" size="large">
                  <template #prefix>
                    <UserOutlined />
                  </template>
                </a-input>
              </a-form-item>

              <a-form-item name="password" :rules="passwordRules">
                <a-input-password v-model:value="registerModel.password" allow-clear placeholder="密码" size="large" />
              </a-form-item>

              <!-- 密码强度显示已移除 -->

              <a-form-item name="confirm" :rules="confirmRules">
                <a-input-password v-model:value="registerModel.confirm" allow-clear placeholder="确认密码" size="large" />
              </a-form-item>

              <a-form-item name="email" :rules="emailRules">
                <a-input v-model:value="registerModel.email" allow-clear placeholder="邮箱（选填，如需预警功能，请填写有效邮箱）" size="large" />
              </a-form-item>

              <div class="mb-12px text-right">
                <small>已有账号？ <a @click="loginModel.type = 'account'">去登录</a></small>
              </div>

              <a-button type="primary" block :loading="registerLoading" size="large" @click="submitRegister">
                注册
              </a-button>
            </a-form>
          </div>
        </div>
      </div>
    </div>

    <div py-24px px-50px fixed bottom-0 z-11 w-screen :data-theme="layoutSetting.theme" text-14px>
      <GlobalLayoutFooter :copyright="layoutSetting.copyright">
      </GlobalLayoutFooter>
    </div>
  </div>
</template>

<style lang="less" scoped>
/* 保持原有样式，新增小调整 */
.login-container {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: auto;
  background: var(--bg-color-container);
}
.login-lang {
  height: 40px;
  line-height: 44px;
}
.login-content {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
}
.ant-pro-form-login-main {
  box-shadow: var(--c-shadow);
}
.icon {
  margin-left: 8px;
  color: var(--text-color-2);
  font-size: 24px;
  cursor: pointer;
  transition: color 0.3s;
}
.icon:hover {
  color: var(--pro-ant-color-primary);
}
</style>
