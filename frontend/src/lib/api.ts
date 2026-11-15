const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const TOKEN_KEY = 'vulnscan_access_token'

export function getAccessToken() { return sessionStorage.getItem(TOKEN_KEY) }
function authHeaders() {
  const token = getAccessToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function authenticate(email: string, password: string, mode: 'login' | 'register') {
  const response = await fetch(`${API_URL}/api/auth/${mode}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Não foi possível autenticar.')
  sessionStorage.setItem(TOKEN_KEY, payload.access_token)
  return payload.user as { id: string; email: string }
}

export async function logout() {
  try { await fetch(`${API_URL}/api/auth/logout`, { method: 'POST', headers: authHeaders() }) }
  finally { sessionStorage.removeItem(TOKEN_KEY) }
}

export async function uploadSourceZip(file: File) {
  const body = new FormData()
  body.append('file', file)
  const response = await fetch(`${API_URL}/api/analysis/source-zip`, {
    method: 'POST', headers: authHeaders(), body,
  })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Falha ao analisar o arquivo.')
  return payload
}

export type AuditHistoryItem = {
  id: string
  analysis_type: string
  target: string
  status: string
  finding_count: number
  created_at: string
}

export async function fetchAuditHistory(): Promise<AuditHistoryItem[]> {
  const response = await fetch(`${API_URL}/api/history?limit=20&offset=0`, { headers: authHeaders() })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Falha ao carregar o histórico.')
  return payload.items ?? []
}
