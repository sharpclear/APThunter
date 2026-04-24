import type { UserInfo } from '~@/api/common/user'
import type { MenuData } from '~@/layouts/basic-layout/typing'
import { logoutApi } from '~@/api/common/login'
import { getRouteMenusApi } from '~@/api/common/menu'
import { getUserInfoApi } from '~@/api/common/user'
import { rootRoute } from '~@/router/constant'
import { generateFlatRoutes, generateRoutes, generateTreeRoutes } from '~@/router/generate-route'
import { DYNAMIC_LOAD_WAY, DynamicLoadEnum } from '~@/utils/constant'
import { useUserId } from '~/composables/user-id'

export const useUserStore = defineStore('user', () => {
  const routerData = shallowRef()
  const menuData = shallowRef<MenuData>([])
  const userInfo = shallowRef<UserInfo>()
  const token = useAuthorization()
  const userId = useUserId()
  const avatar = computed(() => userInfo.value?.avatar)
  const nickname = computed(() => userInfo.value?.nickname ?? userInfo.value?.username)
  const roles = computed(() => userInfo.value?.roles)

  const getMenuRoutes = async () => {
    const { data } = await getRouteMenusApi()
    return generateTreeRoutes(data ?? [])
  }

  const generateDynamicRoutes = async () => {
    const dynamicLoadWay = DYNAMIC_LOAD_WAY === DynamicLoadEnum.BACKEND ? getMenuRoutes : generateRoutes
    const { menuData: treeMenuData, routeData } = await dynamicLoadWay()

    menuData.value = treeMenuData

    routerData.value = {
      ...rootRoute,
      children: generateFlatRoutes(routeData),
    }
    return routerData.value
  }

  // 获取用户信息
  const getUserInfo = async () => {
    // 获取用户信息
    const response = await getUserInfoApi()
    // useGet返回的是ResponseBody，data字段是UserInfo
    const data = response.data
    // 确保nickname有值，如果没有则使用username
    if (data) {
      // 如果username看起来像JWT token，尝试清理它
      let cleanUsername = data.username || ''
      if (cleanUsername && (cleanUsername.includes('alg') || cleanUsername.includes('JWT') || cleanUsername.includes('sub'))) {
        // username字段被错误地存储了token，尝试从nickname获取，或者使用默认值
        cleanUsername = data.nickname || '用户'
        console.warn('检测到username字段包含token，使用nickname:', cleanUsername)
      }
      
      userInfo.value = {
        id: data.id || data.userid || '',
        username: cleanUsername,
        nickname: data.nickname || cleanUsername || '用户',
        avatar: data.avatar || '',
        roles: data.roles || [],
      }
      // 调试日志
      console.log('用户信息已更新:', userInfo.value)
    }
  }

  const logout = async () => {
    // 退出登录
    // 1. 清空用户信息
    try {
      await logoutApi()
    }
    finally {
      token.value = null
      userId.value = null
      userInfo.value = undefined
      routerData.value = undefined
      menuData.value = []
    }
  }

  return {
    userInfo,
    roles,
    getUserInfo,
    logout,
    routerData,
    menuData,
    generateDynamicRoutes,
    avatar,
    nickname,
  }
})
