import type {
  ApiErrorBody,
  ConntrackResponse,
  LoginResponse,
  NatResponse,
  Session,
  StatusResponse,
} from './types'

export class ApiError extends Error {
  status: number
  code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function request<T>(
  path: string,
  init?: RequestInit,
  notifyUnauthorized = true,
): Promise<T> {
  const headers = new Headers(init?.headers)
  if (init?.body) headers.set('content-type', 'application/json')

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
  })

  let body: unknown = null
  try {
    body = await response.json()
  } catch {
    body = null
  }

  if (!response.ok) {
    if (response.status === 401 && notifyUnauthorized) {
      window.dispatchEvent(new Event('vrouter:unauthorized'))
    }
    const errorBody = (body ?? {}) as ApiErrorBody
    throw new ApiError(
      response.status,
      errorBody.code ?? 'request_failed',
      errorBody.message ?? `Request failed with status ${response.status}.`,
    )
  }

  return body as T
}

export function getSession() {
  return request<Session>('/api/session', undefined, false)
}

export function login(password: string) {
  return request<LoginResponse>(
    '/api/login',
    { method: 'POST', body: JSON.stringify({ password }) },
    false,
  )
}

export function logout(csrf: string) {
  return request<{ ok: boolean }>(
    '/api/logout',
    { method: 'POST', body: JSON.stringify({ csrf }) },
    false,
  )
}

export function getStatus() {
  return request<StatusResponse>('/api/status')
}

export function getNat() {
  return request<NatResponse>('/api/nat')
}

export function getConntrack() {
  return request<ConntrackResponse>('/api/conntrack')
}
