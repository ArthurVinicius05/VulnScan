
const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

function csrfHeaders(): Record<string, string> {
  const cookie = document.cookie.split('; ').find(item => item.startsWith('vulnscan_csrf='))
  const token = cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : ''
  return token ? { 'X-CSRF-Token': token } : {}
}

export async function checkSession(): Promise<boolean> {
  const response = await fetch(`${API_URL}/api/auth/me`, { credentials: 'include' })
  return response.ok
}

export async function authenticate(email: string, password: string, mode: 'login' | 'register') {
  const response = await fetch(`${API_URL}/api/auth/${mode}`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Não foi possível autenticar.')
  return payload.user as { id: string; email: string }
}

export async function logout() {
  try {
    await fetch(`${API_URL}/api/auth/logout`, {
      method: 'POST', credentials: 'include', headers: csrfHeaders(),
    })
  } finally {
    // Cookies are cleared by the API; JavaScript cannot clear the HttpOnly session cookie.
  }
}

export async function uploadSourceZip(file: File) {
  const body = new FormData()
  body.append('file', file)
  const response = await fetch(`${API_URL}/api/analysis/source-zip`, {
    method: 'POST', credentials: 'include', headers: csrfHeaders(), body,
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

export type AuditDetail = AuditHistoryItem & {
  result: {
    findings?: { rule_id?: string; title?: string; severity?: string; file?: string; url?: string; line?: number | null; evidence?: string; recommendation?: string }[]
    [key: string]: unknown
  }
}

export async function fetchAuditDetail(id: string): Promise<AuditDetail> {
  const response = await fetch(`${API_URL}/api/history/${encodeURIComponent(id)}`, { credentials: 'include' })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Falha ao carregar o relatório.')
  return payload as AuditDetail
}

export async function fetchAuditHistory(): Promise<AuditHistoryItem[]> {
  const response = await fetch(`${API_URL}/api/history?limit=20&offset=0`, { credentials: 'include' })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Falha ao carregar o histórico.')
  return payload.items ?? []
}
