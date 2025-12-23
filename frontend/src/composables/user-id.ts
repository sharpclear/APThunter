export const STORAGE_USER_ID_KEY = 'UserId'

export const useUserId = createGlobalState(() => useStorage<null | string>(STORAGE_USER_ID_KEY, null))

