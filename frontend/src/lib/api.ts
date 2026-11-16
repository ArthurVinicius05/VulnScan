export type SecurityScore = {
  value: number
  rating: string
  model_version: string
  raw_value: number
  score_cap: number
  is_capped: boolean
  cap_reasons: string[]
  confidence: string
  finding_count: number
  severity_counts: Record<string, number>
  deductions: Record<string, number>
  methodology: string
  disclaimer: string
}

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

type ApiPayload = {
  detail?: string
  message?: string
  user?: { id: string; email: string }
  items?: AuditHistoryItem[]
  [key: string]: unknown
}

async function readPayload(response: Response): Promise<ApiPayload> {
  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    try { return await response.json() as ApiPayload }
    catch { return { detail: 'A API retornou uma resposta JSON inválida.' } }
  }
  const text = await response.text().catch(() => '')
  return { detail: text.trim().slice(0, 300) || `A API retornou uma resposta inesperada (HTTP ${response.status}).` }
}

function ensureSuccess(response: Response, payload: ApiPayload, fallback: string): void {
  if (!response.ok) {
    const detail = typeof payload.detail === 'string' ? payload.detail : fallback
    throw new ApiError(detail, response.status)
  }
}

function csrfHeaders(): Record<string, string> {
  const cookie = document.cookie.split('; ').find(item => item.startsWith('vulnscan_csrf='))
  const token = cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : ''
  return token ? { 'X-CSRF-Token': token } : {}
}

export async function checkSession(): Promise<boolean> {
  try { return (await fetch(`${API_URL}/api/auth/me`, { credentials: 'include', cache: 'no-store' })).ok }
  catch { return false }
}

export type AccountInfo = {
  id: string
  email: string
  email_verified: boolean
  mfa_enabled: boolean
}

export async function fetchAccountInfo(): Promise<AccountInfo> {
  const response = await fetch(`${API_URL}/api/auth/me`, { credentials: 'include', cache: 'no-store' })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível consultar os dados da conta.')
  if (typeof payload.id !== 'string' || typeof payload.email !== 'string') {
    throw new ApiError('A API retornou dados de conta inválidos.', 502)
  }
  return {
    id: payload.id,
    email: payload.email,
    email_verified: payload.email_verified === true,
    mfa_enabled: payload.mfa_enabled === true,
  }
}

export async function authenticate(email: string, password: string, mode: 'login' | 'register') {
  const response = await fetch(`${API_URL}/api/auth/${mode}`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível autenticar.')
  return payload
}

export async function logout() {
  const response = await fetch(`${API_URL}/api/auth/logout`, {
    method: 'POST', credentials: 'include', headers: csrfHeaders(),
  })
  if (!response.ok && response.status !== 401) {
    const payload = await readPayload(response)
    ensureSuccess(response, payload, 'Não foi possível encerrar a sessão.')
  }
}

export async function uploadSourceZip(file: File, onJobCreated?: (jobId: string) => void, onStatus?: (status: string) => void) {
  const body = new FormData()
  body.append('file', file)
  const response = await fetch(`${API_URL}/api/analysis/source-zip`, {
    method: 'POST', credentials: 'include', headers: csrfHeaders(), body,
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Falha ao adicionar o arquivo à fila.')
  if (typeof payload.job_id !== 'string') throw new ApiError('A API não retornou o identificador da análise.', 502)
  onJobCreated?.(payload.job_id)
  onStatus?.(typeof payload.status === 'string' ? payload.status : 'queued')
  const deadline = Date.now() + 10 * 60 * 1000
  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 1500))
    const statusResponse = await fetch(`${API_URL}/api/analysis/jobs/${encodeURIComponent(payload.job_id)}`, { credentials: 'include', cache: 'no-store' })
    const statusPayload = await readPayload(statusResponse)
    ensureSuccess(statusResponse, statusPayload, 'Falha ao consultar o status da análise.')
    if (statusPayload.status === 'completed' && statusPayload.result && typeof statusPayload.result === 'object') {
      return statusPayload.result as ApiPayload
    }
    if (typeof statusPayload.status === 'string') onStatus?.(statusPayload.status)
    if (statusPayload.status === 'cancelled') throw new ApiError('Análise cancelada; o upload temporário foi removido.', 409)
    if (statusPayload.status === 'failed') {
      throw new ApiError(typeof statusPayload.error === 'string' ? statusPayload.error : 'A análise falhou após as tentativas permitidas.', 500)
    }
  }
  throw new ApiError('A análise continua na fila. Atualize o histórico em instantes para verificar o resultado.', 408)
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
    security_score?: SecurityScore

    findings?: { rule_id?: string; title?: string; severity?: string; confidence?: string; file?: string; url?: string; line?: number | null; evidence?: string; recommendation?: string; verified?: boolean; aliases?: string[]; references?: string[]; package?: { name: string; version: string; ecosystem: string } }[]
    [key: string]: unknown
  }
}

export async function fetchAuditDetail(id: string): Promise<AuditDetail> {
  const response = await fetch(`${API_URL}/api/history/${encodeURIComponent(id)}`, { credentials: 'include', cache: 'no-store' })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Falha ao carregar o relatório.')
  return payload as AuditDetail
}

export async function fetchAuditHistory(): Promise<AuditHistoryItem[]> {
  const response = await fetch(`${API_URL}/api/history?limit=20&offset=0`, { credentials: 'include', cache: 'no-store' })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Falha ao carregar o histórico.')
  return Array.isArray(payload.items) ? payload.items : []
}

export async function requestPasswordReset(email: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/auth/request-password-reset`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível solicitar a redefinição.')
  return typeof payload.message === 'string' ? payload.message : 'Solicitação recebida.'
}

export async function resetPassword(token: string, password: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/auth/reset-password`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Link inválido ou expirado.')
  return typeof payload.message === 'string' ? payload.message : 'Senha redefinida.'
}

export async function verifyEmail(token: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/auth/verify-email`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível confirmar o e-mail.')
  return typeof payload.message === 'string' ? payload.message : 'E-mail confirmado.'
}

export async function resendVerification(email: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/auth/resend-verification`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível reenviar.')
  return typeof payload.message === 'string' ? payload.message : 'Solicitação recebida.'
}

export async function completeMfaLogin(challengeToken: string, code: string) {
  const response = await fetch(`${API_URL}/api/auth/mfa/challenge`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_token: challengeToken, code }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível validar o segundo fator.')
  return payload.user
}

export async function beginMfaSetup(): Promise<{ secret: string; otpauth_url: string }> {
  const response = await fetch(`${API_URL}/api/auth/mfa/setup`, {
    method: 'POST', credentials: 'include', headers: csrfHeaders(),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível iniciar a configuração de MFA.')
  if (typeof payload.secret !== 'string' || typeof payload.otpauth_url !== 'string') {
    throw new ApiError('A API não retornou os dados de configuração MFA.', 502)
  }
  return { secret: payload.secret, otpauth_url: payload.otpauth_url }
}

export async function confirmMfaSetup(code: string): Promise<string[]> {
  const response = await fetch(`${API_URL}/api/auth/mfa/enable`, {
    method: 'POST', credentials: 'include', headers: { ...csrfHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível ativar MFA.')
  return Array.isArray(payload.recovery_codes) ? payload.recovery_codes.filter((item): item is string => typeof item === 'string') : []
}

export async function disableMfa(code: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/auth/mfa/disable`, {
    method: 'POST', credentials: 'include', headers: { ...csrfHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível desativar MFA.')
  return typeof payload.message === 'string' ? payload.message : 'MFA desativado.'
}

export async function deleteAccount(password: string, mfaCode?: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/auth/me`, {
    method: 'DELETE', credentials: 'include',
    headers: { ...csrfHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ password, mfa_code: mfaCode || null }),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível excluir a conta.')
  return typeof payload.message === 'string' ? payload.message : 'Conta excluída.'
}

export async function cancelAnalysisJob(jobId: string): Promise<string> {
  const response = await fetch(`${API_URL}/api/analysis/jobs/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST', credentials: 'include', headers: csrfHeaders(),
  })
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível cancelar a análise.')
  return typeof payload.message === 'string' ? payload.message : 'Análise cancelada.'
}


export type AuditComparison = {
  baseline: { id: string; target: string; created_at: string }
  candidate: { id: string; target: string; created_at: string }
  findings: { details_available: boolean; added: number; resolved: number; unchanged: number; baseline_total: number; candidate_total: number }
  severity_delta: Record<string, { baseline: number; candidate: number; delta: number }>
  score: { comparable: boolean; baseline: number | null; candidate: number | null; delta: number | null; model_version: string | null }
}

export async function compareAudits(baselineId: string, candidateId: string): Promise<AuditComparison> {
  const response = await fetch(
    \`\${API_URL}/api/history/compare/\${encodeURIComponent(baselineId)}/\${encodeURIComponent(candidateId)}\`,
    { credentials: 'include', cache: 'no-store' },
  )
  const payload = await readPayload(response)
  ensureSuccess(response, payload, 'Não foi possível comparar as auditorias.')
  return payload as AuditComparison
}
