import { AxiosError } from 'axios'
import { setRouteEmitter } from '~@/utils/route-listener'
import { isAuthorizationExpired } from '~/composables/authorization'
import { useMetaTitle } from '~/composables/meta-title'
import router from '~/router'

const allowList = ['/login', '/error', '/401', '/404', '/403']
const loginPath = '/login'

router.beforeEach(async (to, _, next) => {
  setRouteEmitter(to)
  // 获取
  const userStore = useUserStore()
  const token = useAuthorization()
  if (isAuthorizationExpired(token.value)) {
    userStore.clearLocalSession()
  }

  if (!token.value) {
    //  如果token不存在就跳转到登录页面
    if (!allowList.includes(to.path) && !to.path.startsWith('/redirect')) {
      next({
        path: loginPath,
        query: {
          redirect: encodeURIComponent(to.fullPath),
        },
      })
      return
    }
  }
  else {
    if (!userStore.userInfo && !allowList.includes(to.path) && !to.path.startsWith('/redirect')) {
      try {
        // 获取用户信息
        await userStore.getUserInfo()
        // 获取路由菜单的信息
        const currentRoute = await userStore.generateDynamicRoutes()
        router.addRoute(currentRoute)
        next({
          ...to,
          replace: true,
        })
        return
      }
      catch (e) {
        if (e instanceof AxiosError && e?.response?.status === 401) {
          // token 已失效时直接清理本地会话并回到登录页，避免首次访问先落到 401 页面
          userStore.clearLocalSession()
          next({
            path: loginPath,
            query: {
              redirect: encodeURIComponent(to.fullPath),
            },
          })
          return
        }
      }
    }
    else {
      // 如果当前是登录页面就跳转到首页
      if (to.path === loginPath) {
        next({
          path: '/',
        })
        return
      }
    }
  }
  next()
})

router.afterEach((to) => {
  useMetaTitle(to)
  useLoadingCheck()
  useScrollToTop()
})
