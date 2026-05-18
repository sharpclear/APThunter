export const STORAGE_AUTHORIZE_KEY = 'Authorization'

export const useAuthorization = createGlobalState(() => useStorage<null | string>(STORAGE_AUTHORIZE_KEY, null))

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split('.')[1]
    if (!payload)
      return null

    const normalizedPayload = payload.replace(/-/g, '+').replace(/_/g, '/')
    const padding = '='.repeat((4 - normalizedPayload.length % 4) % 4)
    return JSON.parse(atob(`${normalizedPayload}${padding}`))
  }
  catch {
    return null
  }
}

export function isAuthorizationExpired(token: string | null | undefined): boolean {
  if (!token)
    return false

  const payload = decodeJwtPayload(token)
  const expiresAt = payload?.exp
  if (typeof expiresAt !== 'number')
    return false

  return expiresAt * 1000 <= Date.now()
}
