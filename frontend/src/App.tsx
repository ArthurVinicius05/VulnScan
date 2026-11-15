import { useEffect, useState, type FormEvent } from 'react'
import AccountRecovery from './AccountRecovery'
import { ShieldCheck, LayoutDashboard, Globe, FolderCode, History, Settings, Bell, Search, UploadCloud, FileArchive, Activity, ChevronRight, LockKeyhole, ScanSearch, AlertTriangle } from 'lucide-react'
import { ApiError, authenticate, checkSession, completeMfaLogin, fetchMfaStatus, beginMfaSetup, confirmMfaSetup, disableMfa, fetchAuditDetail, fetchAuditHistory, deleteAccount, logout, uploadSourceZip, type AuditHistoryItem, type AuditDetail } from './lib/api'

type Finding = {
  rule_id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown'
  confidence: string
  file: string
  line: number | null
  evidence: string
  recommendation: string
  verified: boolean
  aliases?: string[]
  references?: string[]
  package?: { name: string; version: string; ecosystem: string }
  cvss_vector?: string | null
}
type Result = {
  status: 'completed' | 'partial' | 'failed'
  coverage?: {
    overall: string
    heuristics?: { candidate_files: number; files_over_file_limit: number; files_over_total_limit: number; findings_returned: number; possibly_truncated_by_finding_limit: boolean }
    python_tools?: { python_files_available?: number; python_files_scanned?: number; truncated?: boolean }
  }
  file_count: number
  detected_technologies: string[]
  sample_paths: string[]
  notice: string
  finding_count: number
  findings: Finding[]
  scanner_tools?: { status: string; tools: { name: string; status: string; files_scanned?: number; files_available?: number }[]; security_tools?: { name: string; status: string; reason?: string; coverage?: { files_scanned?: number; truncated?: boolean; findings_truncated?: boolean } }[] }
  dependencies?: { manifest_count: number; manifests: { file: string; ecosystem: string; status: string; dependency_count: number | null }[]; notice: string; network_access: boolean; packages_installed: boolean }
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [history, setHistory] = useState<AuditHistoryItem[]>([])
  const [historyError, setHistoryError] = useState('')
  const [selectedAudit, setSelectedAudit] = useState<AuditDetail | null>(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [authenticated, setAuthenticated] = useState(false)
  const [authChecking, setAuthChecking] = useState(true)
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [authError, setAuthError] = useState('')
  const [authNotice, setAuthNotice] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [showRecovery, setShowRecovery] = useState(false)
  const [mfaChallenge, setMfaChallenge] = useState('')
  const [mfaLoginCode, setMfaLoginCode] = useState('')
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState<string[]>([])
  const [mfaActionCode, setMfaActionCode] = useState('')
  const [mfaMessage, setMfaMessage] = useState('')
  const [mfaError, setMfaError] = useState('')
  const [deleteAccountOpen, setDeleteAccountOpen] = useState(false)
  const [deletePassword, setDeletePassword] = useState('')
  const [deleteMfaCode, setDeleteMfaCode] = useState('')

  async function refreshHistory() {
    try { setHistory(await fetchAuditHistory()); setHistoryError('') }
    catch (e) { if (e instanceof ApiError && e.status === 401) { setAuthenticated(false); setHistory([]); return } setHistoryError(e instanceof Error ? e.message : 'Falha ao carregar histórico.') }
  }

  async function openAudit(id: string) {
    setDetailBusy(true); setHistoryError('')
    try { setSelectedAudit(await fetchAuditDetail(id)) }
    catch (e) { if (e instanceof ApiError && e.status === 401) { setAuthenticated(false); setSelectedAudit(null); return } setHistoryError(e instanceof Error ? e.message : 'Falha ao carregar relatório.') }
    finally { setDetailBusy(false) }
  }

  useEffect(() => {
    void checkSession().then(setAuthenticated).catch(() => setAuthenticated(false)).finally(() => setAuthChecking(false))
  }, [])
  useEffect(() => { if (authenticated) { void refreshHistory(); void fetchMfaStatus().then(setMfaEnabled).catch(() => setMfaError('Não foi possível consultar o status de MFA.')) } }, [authenticated])

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setAuthBusy(true); setAuthError('')
    try {
      const authResult = await authenticate(email, password, authMode)
      setPassword('')
      if (authResult?.mfa_required === true && typeof authResult.challenge_token === 'string') {
        setMfaChallenge(authResult.challenge_token)
        setAuthNotice('')
      } else if (authResult?.user) {
        setAuthenticated(true)
        setAuthNotice('')
      } else {
        setAuthNotice(typeof authResult?.message === 'string' ? authResult.message : 'Conta criada. Verifique seu e-mail para ativá-la antes de entrar.')
      }
    } catch (e) { setAuthError(e instanceof Error ? e.message : 'Falha na autenticação.') }
    finally { setAuthBusy(false) }
  }

  async function submitMfaLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!mfaChallenge) return
    setAuthBusy(true); setAuthError('')
    try {
      await completeMfaLogin(mfaChallenge, mfaLoginCode)
      setMfaChallenge(''); setMfaLoginCode(''); setAuthenticated(true)
    } catch (e) { setAuthError(e instanceof Error ? e.message : 'Não foi possível validar MFA.') }
    finally { setAuthBusy(false) }
  }

  async function startMfaSetup() {
    setMfaError(''); setMfaMessage(''); setMfaRecoveryCodes([])
    try { setMfaSetup(await beginMfaSetup()) }
    catch (e) { setMfaError(e instanceof Error ? e.message : 'Não foi possível iniciar MFA.') }
  }

  async function activateMfa() {
    setMfaError(''); setMfaMessage('')
    try {
      const codes = await confirmMfaSetup(mfaActionCode)
      setMfaEnabled(true); setMfaSetup(null); setMfaActionCode('')
      setMfaRecoveryCodes(codes)
      setMfaMessage('MFA ativado. Salve os códigos de recuperação em local seguro.')
    } catch (e) { setMfaError(e instanceof Error ? e.message : 'Não foi possível ativar MFA.') }
  }

  async function deactivateMfa() {
    setMfaError(''); setMfaMessage('')
    try {
      const message = await disableMfa(mfaActionCode)
      setMfaEnabled(false); setAuthenticated(false); setHistory([]); setResult(null)
      setMfaActionCode(''); setMfaRecoveryCodes([]); setMfaMessage(message)
    } catch (e) { setMfaError(e instanceof Error ? e.message : 'Não foi possível desativar MFA.') }
  }

  async function removeAccount() {
    setMfaError(''); setMfaMessage('')
    try {
      const message = await deleteAccount(deletePassword, deleteMfaCode)
      setAuthenticated(false); setHistory([]); setResult(null); setMfaEnabled(false)
      setDeleteAccountOpen(false); setDeletePassword(''); setDeleteMfaCode('')
      setAuthNotice(message)
    } catch (e) { setMfaError(e instanceof Error ? e.message : 'Não foi possível excluir a conta.') }
  }

  async function endSession() { await logout(); setAuthenticated(false); setHistory([]); setResult(null) }

  if (authChecking) return <div className="auth-screen"><p>Verificando sessão…</p></div>
  if (!authenticated && (showRecovery || new URLSearchParams(window.location.hash.replace(/^#/, '')).has('verify') || new URLSearchParams(window.location.hash.replace(/^#/, '')).has('reset'))) return <AccountRecovery onBack={() => { setShowRecovery(false); window.history.replaceState({}, '', window.location.pathname) }} />
  if (!authenticated && mfaChallenge) return <div className="auth-screen"><form className="auth-card" onSubmit={submitMfaLogin}>
    <div className="brand-mark"><ShieldCheck size={24}/></div><h1>Verificação em duas etapas</h1>
    <p>Digite o código do seu aplicativo autenticador ou um código de recuperação.</p>
    <label>Código MFA<input inputMode="text" autoComplete="one-time-code" required minLength={6} maxLength={64} value={mfaLoginCode} onChange={e=>setMfaLoginCode(e.target.value)}/></label>
    {authError && <div className="error">{authError}</div>}
    <button className="primary-btn" disabled={authBusy}>{authBusy ? 'Validando…' : 'Confirmar código'}</button>
    <button type="button" className="auth-switch" onClick={()=>{setMfaChallenge('');setMfaLoginCode('');setAuthError('')}}>Voltar ao login</button>
  </form></div>
  if (!authenticated) return <div className="auth-screen"><form className="auth-card" onSubmit={submitAuth}>
    <div className="brand-mark"><ShieldCheck size={24}/></div><h1>VulnScan Pro</h1>
    <p>{authMode === 'login' ? 'Entre na sua conta para acessar suas auditorias.' : 'Crie sua conta para manter seu histórico privado.'}</p>
    <label>E-mail<input type="email" autoComplete="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)}/></label>
    <label>Senha<input type="password" autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} required minLength={12} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)}/></label>
    {authMode === 'register' && <small>A senha deve ter pelo menos 12 caracteres.</small>}
    {authError && <div className="error">{authError}</div>}
    {authNotice && <div className="success">{authNotice}</div>}
    {authMode === 'login' && <button type="button" className="auth-switch" onClick={() => setShowRecovery(true)}>Esqueci minha senha / confirmar e-mail</button>}
    <button className="primary-btn" disabled={authBusy}>{authBusy ? 'Aguarde…' : authMode === 'login' ? 'Entrar' : 'Criar conta'}</button>
    <button type="button" className="auth-switch" onClick={()=>{setAuthMode(authMode === 'login' ? 'register' : 'login');setAuthError('')}}>{authMode === 'login' ? 'Ainda não tem conta? Cadastre-se' : 'Já tem conta? Entrar'}</button>
  </form></div>

  async function runAnalysis() {
    if (!file) return
    setBusy(true); setError(''); setResult(null)
    try { setResult(await uploadSourceZip(file) as Result); await refreshHistory() }
    catch (e) { if (e instanceof ApiError && e.status === 401) { setAuthenticated(false); setResult(null); setError('Sua sessão expirou. Entre novamente para continuar.') } else setError(e instanceof Error ? e.message : 'Erro inesperado.') }
    finally { setBusy(false) }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={22}/></div><div><strong>VulnScan<span> Pro</span></strong><small>SECURITY INTELLIGENCE</small></div></div>
      <div className="nav-label">WORKSPACE</div>
      <nav>
        <a className="active"><LayoutDashboard size={18}/> Overview</a>
        <a><Globe size={18}/> Website Scanner <span className="soon">SOON</span></a>
        <a><FolderCode size={18}/> Code Analyzer</a>
        <a href="#audit-history"><History size={18}/> Audit History</a>
      </nav>
      <div className="sidebar-bottom"><a><Settings size={18}/> Settings</a><div className="profile"><div className="avatar">AV</div><div><b>Workspace</b><small>Local environment</small></div></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb">Workspace <ChevronRight size={14}/> <b>Overview</b></div><div className="top-actions"><button className="auth-logout" onClick={()=>void endSession()}>Sair</button><button className="icon-btn"><Search size={18}/></button><button className="icon-btn"><Bell size={18}/></button><div className="avatar">AV</div></div></header>
      <section className="content">
        <div className="welcome"><div><div className="eyebrow"><span className="live-dot"/> SECURITY WORKSPACE</div><h1>Security overview</h1><p>Find weaknesses before attackers do. Audit only codebases and websites you are authorized to test.</p></div><div className="date-chip"><Activity size={15}/> SYSTEM READY</div></div>
        <div className="stats">
          <div className="stat-card"><div className="stat-top"><span>Audits performed</span><ScanSearch size={18}/></div><strong>{history.length}</strong><small>Saved audits in this workspace</small></div>
          <div className="stat-card"><div className="stat-top"><span>Issues detected</span><LockKeyhole size={18}/></div><strong>{result?.finding_count ?? '—'}</strong><small>{result ? 'Current archive' : 'Run your first audit'}</small></div>
          <div className="stat-card"><div className="stat-top"><span>Security score</span><ShieldCheck size={18}/></div><strong>—</strong><small>Scoring not implemented</small></div>
        </div>
        <section className="panel account-security" id="account-security">
          <div className="section-heading"><div><h2>Account security</h2><p>Protect your account with an authenticator app and one-time recovery codes.</p></div><span className={mfaEnabled ? 'available' : 'coming'}>{mfaEnabled ? 'MFA ENABLED' : 'MFA NOT ENABLED'}</span></div>
          {mfaEnabled ? <div>
            <p>Multi-factor authentication is active for this account.</p>
            <label>Authenticator code or recovery code<input value={mfaActionCode} onChange={e=>setMfaActionCode(e.target.value)} maxLength={64} placeholder="6-digit code or recovery code"/></label>
            <button className="secondary-btn" disabled={!mfaActionCode} onClick={()=>void deactivateMfa()}>Disable MFA and sign out all sessions</button>
          </div> : <div>
            {!mfaSetup ? <button className="primary-btn" onClick={()=>void startMfaSetup()}>Set up MFA</button> : <div>
              <p>In your authenticator app, add an account manually with this secret:</p>
              <pre>{mfaSetup.secret}</pre>
              <small>Provisioning URI: {mfaSetup.otpauth_url}</small>
              <label>Enter the current 6-digit code<input inputMode="numeric" autoComplete="one-time-code" value={mfaActionCode} onChange={e=>setMfaActionCode(e.target.value)} maxLength={6} placeholder="123456"/></label>
              <button className="primary-btn" disabled={mfaActionCode.length !== 6} onClick={()=>void activateMfa()}>Confirm and enable MFA</button>
            </div>}
          </div>}
          {mfaError && <div className="error">{mfaError}</div>}
          {mfaMessage && <div className="success">{mfaMessage}</div>}
          {mfaRecoveryCodes.length > 0 && <details open><summary>Recovery codes — save them now</summary><ul>{mfaRecoveryCodes.map(code=><li key={code}><code>{code}</code></li>)}</ul><small>Each code can be used once. They will not be shown again.</small></details>}
          <div className="account-danger-zone">
            {!deleteAccountOpen ? <button className="secondary-btn" onClick={()=>setDeleteAccountOpen(true)}>Delete account and audit data</button> : <div>
              <p>This permanently removes your account, queued jobs and saved audit reports. Running analyses must finish first. Encrypted backups may retain copies until their configured retention period expires.</p>
              <label>Current password<input type="password" autoComplete="current-password" value={deletePassword} onChange={e=>setDeletePassword(e.target.value)} maxLength={128}/></label>
              {mfaEnabled && <label>Authenticator or recovery code<input value={deleteMfaCode} onChange={e=>setDeleteMfaCode(e.target.value)} maxLength={64}/></label>}
              <button className="secondary-btn" disabled={deletePassword.length < 12 || (mfaEnabled && deleteMfaCode.length < 6)} onClick={()=>void removeAccount()}>Permanently delete account</button>
              <button className="auth-switch" onClick={()=>{setDeleteAccountOpen(false);setDeletePassword('');setDeleteMfaCode('')}}>Cancel</button>
            </div>}
          </div>
        </section>
        <div className="section-heading"><div><h2>Start an assessment</h2><p>Choose a target type to begin your security review.</p></div></div>
        <div className="scan-grid">
          <section className="panel"><div className="panel-icon purple"><FolderCode size={21}/></div><div className="panel-title"><h3>Source code analysis</h3><span className="available">AVAILABLE · PHASE 2</span></div><p>Inspect project structure and run bounded static checks for common insecure coding patterns. Uploaded code is never executed.</p>
            <label className="dropzone"><UploadCloud size={26}/><b>{file ? file.name : 'Drop your ZIP file here'}</b><span>{file ? (file.size / 1024 / 1024).toFixed(2) + ' MB' : 'or click to browse · max 25 MB'}</span><input type="file" accept=".zip,application/zip" onChange={e => {setFile(e.target.files?.[0] ?? null);setResult(null);setError('')}} /></label>
            <button className="primary-btn" disabled={!file || busy} onClick={runAnalysis}>{busy ? 'Waiting for analysis…' : 'Analyze source archive'} <ChevronRight size={17}/></button>
            {error && <div className="error">{error}</div>}
            {result && <div className="result"><b><FileArchive size={16}/> {result.status === 'partial' ? 'Analysis partially completed' : result.status === 'failed' ? 'Analysis failed' : 'Analysis completed'}</b>{result.status === 'partial' && <div className="error">Cobertura parcial: alguns arquivos ou ferramentas foram limitados, desativados ou ficaram indisponíveis. Consulte os detalhes dos scanners antes de interpretar a ausência de achados.</div>}<p>{result.file_count} files · {result.detected_technologies.join(', ') || 'No known stack markers detected'}</p><small>{result.notice}</small>
              <div className="findings-summary"><AlertTriangle size={16}/> {result.finding_count} potential finding(s)</div>
              {result.scanner_tools && <div className="tool-status"><b>Static tools</b>{result.scanner_tools.tools.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {tool.status}{tool.files_scanned !== undefined ? ' · ' + tool.files_scanned + '/' + (tool.files_available ?? tool.files_scanned) + ' files' : ''}</span>)}{result.scanner_tools.security_tools?.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {tool.status}{tool.coverage?.truncated ? ' · coverage limited' : ''}{tool.reason ? ' · ' + tool.reason : ''}</span>)}</div>}
              {result.coverage && <div className="dependency-inventory"><b>Analysis coverage</b><span>Heuristics: {result.coverage.heuristics?.candidate_files ?? 0} candidate files · {result.coverage.heuristics?.files_over_file_limit ?? 0} above per-file limit · {result.coverage.heuristics?.files_over_total_limit ?? 0} above total limit</span>{result.coverage.python_tools && <span>Python scanners: {result.coverage.python_tools.python_files_scanned ?? 0}/{result.coverage.python_tools.python_files_available ?? 0} files</span>}</div>}
              {result.dependencies && <div className="dependency-inventory">
                <b>Dependency manifests · {result.dependencies.manifest_count}</b>
                <small>{result.dependencies.notice}</small>
                {result.dependencies.manifests.map(item => <span key={item.file}>{item.file} · {item.ecosystem}{item.dependency_count !== null ? ' · ' + item.dependency_count + ' dependencies' : ''}</span>)}
              </div>}
              {result.findings.map((finding, index) => <article className="finding" key={finding.rule_id + finding.file + finding.line + index}>
                <div className="finding-heading"><b>{finding.title}</b><span className={'severity ' + finding.severity}>{finding.severity.toUpperCase()}</span></div>
                <small>{finding.rule_id} · {finding.file}:{finding.line ?? '—'} · confidence: {finding.confidence} · not verified</small>
                {finding.package && <small>{finding.package.ecosystem}:{finding.package.name}@{finding.package.version}</small>}
                {finding.aliases?.length ? <small>Aliases: {finding.aliases.join(', ')}</small> : null}
                {finding.references?.map(url => <small key={url}><a href={url} target="_blank" rel="noreferrer">Advisory reference</a></small>)}
                <pre>{finding.evidence}</pre><p>{finding.recommendation}</p>
              </article>)}
              <details><summary>Inspected paths ({result.sample_paths.length} shown)</summary><ul>{result.sample_paths.slice(0,20).map(p=><li key={p}>{p}</li>)}</ul></details>
            </div>}
          </section>
          <section className="panel"><div className="panel-icon cyan"><Globe size={21}/></div><div className="panel-title"><h3>Website scanner</h3><span className="coming">COMING IN PHASE 3</span></div><p>Review HTTPS configuration, security headers, cookie attributes, and exposed information on authorized targets.</p><div className="disabled-input"><Globe size={17}/><span>https://your-authorized-domain.com</span><LockKeyhole size={15}/></div><button className="secondary-btn" disabled>Website scanning is not enabled yet</button><div className="safety-note"><LockKeyhole size={15}/> Active checks will require explicit authorization and safe scope controls.</div></section>
        </div>
        <section className="panel audit-history" id="audit-history"><div className="section-heading"><div><h2>Audit history</h2><p>Latest completed assessments saved in this workspace.</p></div><button className="secondary-btn" onClick={() => void refreshHistory()}>Refresh</button></div>{historyError && <div className="error">{historyError}</div>}{history.length === 0 && !historyError ? <p>No saved audits yet.</p> : <div className="history-list">{history.map(item => <article className="history-item" key={item.id}><div><b>{item.target}</b><small>{item.analysis_type.replaceAll("_", " ")} · {new Date(item.created_at).toLocaleString()}</small></div><span className="findings-summary">{item.finding_count} finding(s)</span><button className="history-view" onClick={() => void openAudit(item.id)}>Ver relatório</button></article>)}</div>}{detailBusy && <p>Carregando relatório…</p>}{selectedAudit && <div className="audit-detail"><div className="audit-detail-heading"><div><h3>{selectedAudit.target}</h3><small>{selectedAudit.analysis_type.replaceAll('_', ' ')} · {new Date(selectedAudit.created_at).toLocaleString()}</small></div><button className="history-view" onClick={() => setSelectedAudit(null)}>Fechar</button></div><p>{selectedAudit.finding_count} achado(s) registrado(s)</p>{selectedAudit.result.findings?.length ? selectedAudit.result.findings.map((finding, index) => <article className="finding" key={(finding.rule_id ?? 'finding') + index}><div className="finding-heading"><b>{finding.title ?? finding.rule_id ?? 'Achado de segurança'}</b><span className={'severity ' + (finding.severity ?? 'unknown')}>{(finding.severity ?? 'unknown').toUpperCase()}</span></div><small>{finding.rule_id ?? '—'} · {finding.file ?? finding.url ?? '—'}{finding.line ? ':' + finding.line : ''}</small>{finding.evidence && <pre>{finding.evidence}</pre>}{finding.recommendation && <p>{finding.recommendation}</p>}</article>) : <p>Nenhum detalhe de achado foi armazenado neste registro.</p>}</div>}</section>
        <div className="bottom-note"><ShieldCheck size={17}/><span><b>Built with security in mind.</b> Uploaded code is treated as untrusted input and is never executed by this service.</span></div>
        <footer>VULNSCAN PRO · STATIC ANALYSIS BUILD 0.2.0 · FOR AUTHORIZED SECURITY TESTING</footer>
      </section>
    </main>
  </div>
}
