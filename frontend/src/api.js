// Thin fetch wrapper. The JWT lives in sessionStorage and is cleared on 401.
const KEY = 'vapt_token'

export function getToken() {
  try { return sessionStorage.getItem(KEY) } catch { return null }
}
export function setToken(t) {
  try { t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY) } catch { /* ignore */ }
}

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status }
}

export async function api(path, { method = 'GET', body, form, raw } = {}) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  let payload
  if (form) payload = form
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body) }

  const res = await fetch(path, { method, headers, body: payload })
  if (res.status === 401 && path !== '/api/auth/login') {
    setToken(null)
    window.location.assign('/login')
    throw new ApiError(401, 'Session expired')
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`
    try {
      const data = await res.json()
      if (typeof data.detail === 'string') msg = data.detail
      else if (Array.isArray(data.detail)) msg = data.detail.map(d => d.msg).join('; ')
    } catch { /* not json */ }
    throw new ApiError(res.status, msg)
  }
  if (raw) return res
  if (res.status === 204) return null
  return res.json()
}
