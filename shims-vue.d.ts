// env.d.ts 或 shims-vue.d.ts
declare module '*.vue' {
  import type { DefineComponent } from 'vue'

  const component: DefineComponent<object, object, any>
  export default component
}

declare module 'vue' {
  export * from 'vue/dist/vue'
}
