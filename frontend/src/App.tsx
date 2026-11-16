import { useEffect, useState, type FormEvent } from 'react'
import AccountRecovery from './AccountRecovery'
import LanguageToggle from './LanguageToggle'
import { getInitialLanguage, translate, type Language, type TranslationKey } from './i18n'
import { ShieldCheck, LayoutDashboard, Globe, FolderCode, History, Settings, UploadCloud, FileArchive, Activity, ChevronRight, LockKeyhole, ScanSearch, AlertTriangle } from 'lucide-react'
import { ApiError, authenticate, checkSession, completeMfaLogin, fetchAccountInfo, beginMfaSetup, confirmMfaSetup, disableMfa, fetchAuditDetail, fetchAuditHistory, cancelAnalysisJob, deleteAccount, logout, uploadSourceZip, type AuditHistoryItem, type AuditDetail } from './lib/api'

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
  const [language, setLanguage] = useState<Language>(getInitialLanguage)
  const t = (key: TranslationKey) => translate(language, key)
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [analysisStatus, setAnalysisStatus] = useState('')
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
  const [accountEmail, setAccountEmail] = useState('')
  const [emailVerified, setEmailVerified] = useState(false)
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState<string[]>([])
  const [mfaActionCode, setMfaActionCode] = useState('')
  const [mfaMessage, setMfaMessage] = useState('')
  const [mfaError, setMfaError] = useState('')
  const [deleteAccountOpen, setDeleteAccountOpen] = useState(false)
  const [deletePassword, setDeletePassword] = useState('')
  const [deleteMfaCode, setDeleteMfaCode] = useState('')

  function clearWorkspaceState() {
    setHistory([])
    setHistoryError('')
    setSelectedAudit(null)
    setDetailBusy(false)
    setResult(null)
    setFile(null)
    setActiveJobId(null)
    setBusy(false)
    setAnalysisStatus('')
    setMfaEnabled(false)
    setAccountEmail('')
    setEmailVerified(false)
    setMfaSetup(null)
    setMfaRecoveryCodes([])
    setMfaActionCode('')
    setMfaMessage('')
    setMfaError('')
    setDeleteAccountOpen(false)
    setDeletePassword('')
    setDeleteMfaCode('')
  }

  async function refreshHistory() {
    try { setHistory(await fetchAuditHistory()); setHistoryError('') }
    catch (e) { if (e instanceof ApiError && e.status === 401) { clearWorkspaceState(); setAuthenticated(false); return } setHistoryError(e instanceof Error ? e.message : t('historyLoadFailed')) }
  }

  async function openAudit(id: string) {
    setDetailBusy(true); setHistoryError('')
    try { setSelectedAudit(await fetchAuditDetail(id)) }
    catch (e) { if (e instanceof ApiError && e.status === 401) { clearWorkspaceState(); setAuthenticated(false); return } setHistoryError(e instanceof Error ? e.message : t('reportLoadFailed')) }
    finally { setDetailBusy(false) }
  }

  useEffect(() => {
    document.documentElement.lang = language
    try { window.localStorage.setItem('vulnscan-language', language) } catch { /* Storage may be unavailable. */ }
  }, [language])

  useEffect(() => {
    void checkSession().then(setAuthenticated).catch(() => setAuthenticated(false)).finally(() => setAuthChecking(false))
  }, [])
  useEffect(() => {
    if (!authenticated) return
    void refreshHistory()
    void fetchAccountInfo().then(account => {
      setAccountEmail(account.email)
      setEmailVerified(account.email_verified)
      setMfaEnabled(account.mfa_enabled)
    }).catch(e => {
      if (e instanceof ApiError && e.status === 401) {
        clearWorkspaceState()
        setAuthenticated(false)
      } else {
        setMfaError(e instanceof Error ? e.message : t('accountLoadFailed'))
      }
    })
  }, [authenticated])

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setAuthBusy(true); setAuthError('')
    try {
      const authResult = await authenticate(email, password, authMode)
      setPassword('')
      if (authResult?.mfa_required === true && typeof authResult.challenge_token === 'string') {
        setMfaChallenge(authResult.challenge_token)
        setAuthNotice('')
      } else if (authResult?.user) {
        clearWorkspaceState()
        setAuthenticated(true)
        setAuthNotice('')
      } else {
        setAuthNotice(typeof authResult?.message === 'string' ? authResult.message : 'Conta criada. Verifique seu e-mail para ativá-la antes de entrar.')
      }
    } catch (e) { setAuthError(e instanceof Error ? e.message : t('authFailed')) }
    finally { setAuthBusy(false) }
  }

  async function submitMfaLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!mfaChallenge) return
    setAuthBusy(true); setAuthError('')
    try {
      await completeMfaLogin(mfaChallenge, mfaLoginCode)
      setMfaChallenge(''); setMfaLoginCode('')
      clearWorkspaceState()
      setAuthenticated(true)
    } catch (e) { setAuthError(e instanceof Error ? e.message : t('mfaFailed')) }
    finally { setAuthBusy(false) }
  }

  async function startMfaSetup() {
    setMfaError(''); setMfaMessage(''); setMfaRecoveryCodes([])
    try { setMfaSetup(await beginMfaSetup()) }
    catch (e) { setMfaError(e instanceof Error ? e.message : t('mfaSetupFailed')) }
  }

  async function activateMfa() {
    setMfaError(''); setMfaMessage('')
    try {
      const codes = await confirmMfaSetup(mfaActionCode)
      setMfaEnabled(true); setMfaSetup(null); setMfaActionCode('')
      setMfaRecoveryCodes(codes)
      setMfaMessage('MFA ativado. Salve os códigos de recuperação em local seguro.')
    } catch (e) { setMfaError(e instanceof Error ? e.message : t('mfaEnableFailed')) }
  }

  async function deactivateMfa() {
    setMfaError(''); setMfaMessage('')
    try {
      const message = await disableMfa(mfaActionCode)
      clearWorkspaceState(); setAuthenticated(false)
      setMfaMessage(message)
    } catch (e) { setMfaError(e instanceof Error ? e.message : t('mfaDisableFailed')) }
  }

  async function removeAccount() {
    setMfaError(''); setMfaMessage('')
    try {
      const message = await deleteAccount(deletePassword, deleteMfaCode)
      clearWorkspaceState(); setAuthenticated(false)
      setAuthNotice(message)
    } catch (e) { setMfaError(e instanceof Error ? e.message : t('accountDeleteFailed')) }
  }

  async function endSession() { let logoutFailed = false; try { await logout() } catch { logoutFailed = true } finally { clearWorkspaceState(); setAuthenticated(false) } if (logoutFailed) setAuthNotice(t('logoutUnconfirmed')) }

  if (authChecking) return <div className="auth-screen"><div className="auth-language"><LanguageToggle language={language} onChange={setLanguage}/></div><p>{t('checkingSession')}</p></div>
  if (!authenticated && (showRecovery || new URLSearchParams(window.location.hash.replace(/^#/, '')).has('verify') || new URLSearchParams(window.location.hash.replace(/^#/, '')).has('reset'))) return <AccountRecovery language={language} onLanguageChange={setLanguage} onBack={() => { setShowRecovery(false); window.history.replaceState({}, '', window.location.pathname) }} />
  if (!authenticated && mfaChallenge) return <div className="auth-screen"><div className="auth-language"><LanguageToggle language={language} onChange={setLanguage}/></div><form className="auth-card" onSubmit={submitMfaLogin}>
    <div className="brand-mark"><ShieldCheck size={24}/></div><h1>{t('mfaLoginTitle')}</h1>
    <p>{t('mfaLoginDescription')}</p>
    <label>{t('mfaCode')}<input inputMode="text" autoComplete="one-time-code" required minLength={6} maxLength={64} value={mfaLoginCode} onChange={e=>setMfaLoginCode(e.target.value)}/></label>
    {authError && <div className="error">{authError}</div>}
    <button className="primary-btn" disabled={authBusy}>{authBusy ? t('validating') : t('confirmCode')}</button>
    <button type="button" className="auth-switch" onClick={()=>{setMfaChallenge('');setMfaLoginCode('');setAuthError('')}}>{t('backToLogin')}</button>
  </form></div>
  if (!authenticated) return <div className="auth-screen"><div className="auth-language"><LanguageToggle language={language} onChange={setLanguage}/></div><form className="auth-card" onSubmit={submitAuth}>
    <div className="brand-mark"><ShieldCheck size={24}/></div><h1>VulnScan</h1>
    <p>{authMode === 'login' ? t('loginDescription') : t('registerDescription')}</p>
    <label>{t('email')}<input type="email" autoComplete="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)}/></label>
    <label>{t('password')}<input type="password" autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} required minLength={12} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)}/></label>
    {authMode === 'register' && <small>{t('passwordMin')}</small>}
    {authError && <div className="error">{authError}</div>}
    {authNotice && <div className="success">{authNotice}</div>}
    {authMode === 'login' && <button type="button" className="auth-switch" onClick={() => setShowRecovery(true)}>{t('forgotPassword')}</button>}
    <button className="primary-btn" disabled={authBusy}>{authBusy ? t('pleaseWait') : authMode === 'login' ? t('signIn') : t('createAccount')}</button>
    <button type="button" className="auth-switch" onClick={()=>{setAuthMode(authMode === 'login' ? 'register' : 'login');setAuthError('')}}>{authMode === 'login' ? t('noAccount') : t('haveAccount')}</button>
  </form></div>

  async function runAnalysis() {
    if (!file) return
    setBusy(true); setError(''); setResult(null); setActiveJobId(null); setAnalysisStatus('uploading')
    try { setResult(await uploadSourceZip(file, setActiveJobId, setAnalysisStatus) as Result); await refreshHistory() }
    catch (e) { if (e instanceof ApiError && e.status === 401) { clearWorkspaceState(); setAuthenticated(false); setError(t('sessionExpired')) } else setError(e instanceof Error ? e.message : t('unexpectedError')) }
    finally { setBusy(false); setActiveJobId(null); setAnalysisStatus('') }
  }

  async function cancelQueuedJob() {
    if (!activeJobId) return
    try {
      const message = await cancelAnalysisJob(activeJobId)
      setAnalysisStatus('cancelled')
      setError(message)
    } catch (e) {
      setError(e instanceof Error ? e.message : t('analysisCancelled'))
    }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={22}/></div><div><strong>VulnScan</strong><small>SECURITY INTELLIGENCE</small></div></div>
      <div className="nav-label">{t('workspace').toUpperCase()}</div>
      <nav>
        <a className="active" href="#overview"><LayoutDashboard size={18}/> {t('overview')}</a>
        <a><Globe size={18}/> {t('websiteScanner')} <span className="soon">{t('soon')}</span></a>
        <a href="#code-analyzer"><FolderCode size={18}/> {t('codeAnalyzer')}</a>
        <a href="#audit-history"><History size={18}/> {t('auditHistory')}</a>
      </nav>
      <div className="sidebar-bottom"><a href="#account-security"><Settings size={18}/> {t('settings')}</a><div className="profile"><div className="avatar">{accountEmail ? accountEmail.slice(0, 2).toUpperCase() : "AV"}</div><div><b>{accountEmail || t('account')}</b><small>{emailVerified ? t('verifiedEmail') : t('unverifiedEmail')}</small></div></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb">{t('workspace')} <ChevronRight size={14}/> <b>{t('overview')}</b></div><div className="top-actions"><LanguageToggle language={language} onChange={setLanguage}/><details className="profile-menu"><summary><div className="avatar">{accountEmail ? accountEmail.slice(0, 2).toUpperCase() : "AV"}</div><span>{t('account')}</span></summary><div className="profile-menu-content"><b>{accountEmail || t('account')}</b><small>{emailVerified ? t('verifiedEmail') : t('unverifiedEmail')}</small><a href="#account-security">{t('securitySettings')}</a><button type="button" onClick={()=>void endSession()}>{t('signOut')}</button></div></details></div></header>
      <section className="content">
        <div className="welcome" id="overview"><div><div className="eyebrow"><span className="live-dot"/> {t('securityWorkspace')}</div><h1>{t('securityOverview')}</h1><p>{t('overviewDescription')}</p></div><div className="date-chip"><Activity size={15}/> {t('codeAnalyzerReady')}</div></div>
        <div className="stats">
          <div className="stat-card"><div className="stat-top"><span>{t('auditsPerformed')}</span><ScanSearch size={18}/></div><strong>{history.length}</strong><small>{t('savedAudits')}</small></div>
          <div className="stat-card"><div className="stat-top"><span>{t('issuesDetected')}</span><LockKeyhole size={18}/></div><strong>{result?.finding_count ?? '—'}</strong><small>{result ? t('currentArchive') : t('runFirstAudit')}</small></div>
          <div className="stat-card"><div className="stat-top"><span>{t('securityScore')}</span><ShieldCheck size={18}/></div><strong>—</strong><small>{t('scoringNotImplemented')}</small></div>
        </div>
        <section className="panel account-security" id="account-security">
          <div className="section-heading"><div><h2>{t('accountSecurity')}</h2><p>{t('accountSecurityDescription')}</p></div><span className={mfaEnabled ? 'available' : 'coming'}>{mfaEnabled ? t('mfaEnabled') : t('mfaNotEnabled')}</span></div>
          {mfaEnabled ? <div>
            <p>{t('mfaActive')}</p>
            <label>{t('authenticatorOrRecovery')}<input value={mfaActionCode} onChange={e=>setMfaActionCode(e.target.value)} maxLength={64} placeholder={t('codePlaceholder')}/></label>
            <button className="secondary-btn" disabled={!mfaActionCode} onClick={()=>void deactivateMfa()}>{t('disableMfa')}</button>
          </div> : <div>
            {!mfaSetup ? <button className="primary-btn" onClick={()=>void startMfaSetup()}>{t('setupMfa')}</button> : <div>
              <p>{t('addSecretManually')}</p>
              <pre>{mfaSetup.secret}</pre>
              <small>{t('provisioningUri')}: {mfaSetup.otpauth_url}</small>
              <label>{t('currentSixDigitCode')}<input inputMode="numeric" autoComplete="one-time-code" value={mfaActionCode} onChange={e=>setMfaActionCode(e.target.value)} maxLength={6} placeholder="123456"/></label>
              <button className="primary-btn" disabled={mfaActionCode.length !== 6} onClick={()=>void activateMfa()}>{t('confirmEnableMfa')}</button>
            </div>}
          </div>}
          {mfaError && <div className="error">{mfaError}</div>}
          {mfaMessage && <div className="success">{mfaMessage}</div>}
          {mfaRecoveryCodes.length > 0 && <details open><summary>{t('recoveryCodesSave')}</summary><ul>{mfaRecoveryCodes.map(code=><li key={code}><code>{code}</code></li>)}</ul><small>{t('recoveryCodesOneTime')}</small></details>}
          <div className="account-danger-zone">
            {!deleteAccountOpen ? <button className="secondary-btn" onClick={()=>setDeleteAccountOpen(true)}>{t('deleteAccount')}</button> : <div>
              <p>{t('deleteAccountWarning')}</p>
              <label>{t('currentPassword')}<input type="password" autoComplete="current-password" value={deletePassword} onChange={e=>setDeletePassword(e.target.value)} maxLength={128}/></label>
              {mfaEnabled && <label>Authenticator or recovery code<input value={deleteMfaCode} onChange={e=>setDeleteMfaCode(e.target.value)} maxLength={64}/></label>}
              <button className="secondary-btn" disabled={deletePassword.length < 12 || (mfaEnabled && deleteMfaCode.length < 6)} onClick={()=>void removeAccount()}>{t('permanentlyDelete')}</button>
              <button className="auth-switch" onClick={()=>{setDeleteAccountOpen(false);setDeletePassword('');setDeleteMfaCode('')}}>{t('cancel')}</button>
            </div>}
          </div>
        </section>
        <div className="section-heading"><div><h2>{t('startAssessment')}</h2><p>{t('chooseTarget')}</p></div></div>
        <div className="scan-grid">
          <section className="panel" id="code-analyzer"><div className="panel-icon purple"><FolderCode size={21}/></div><div className="panel-title"><h3>{t('sourceAnalysis')}</h3><span className="available">{t('available')}</span></div><p>{t('sourceDescription')}</p>
            <label className="dropzone"><UploadCloud size={26}/><b>{file ? file.name : t('dropZip')}</b><span>{file ? (file.size / 1024 / 1024).toFixed(2) + ' MB' : t('browseZip')}</span><input type="file" accept=".zip,application/zip" onChange={e => {const selected=e.target.files?.[0] ?? null;setResult(null);if(selected && selected.size > 50 * 1024 * 1024){setFile(null);setError(t('fileTooLarge'));return}setFile(selected);setError('')}} /></label>
            <button className="primary-btn" disabled={!file || busy} onClick={runAnalysis}>{busy ? t('waitingAnalysis') : (language === 'pt-BR' ? 'Analisar arquivo-fonte' : 'Analyze source archive')} <ChevronRight size={17}/></button>
            {busy && <div className="analysis-progress"><span>{analysisStatus === 'queued' ? t('queuedStatus') : analysisStatus === 'running' ? t('runningStatus') : t('uploadingStatus')}</span>{analysisStatus === 'queued' && activeJobId && <button className="auth-switch" onClick={()=>void cancelQueuedJob()}>{t('cancelQueued')}</button>}</div>}
            {error && <div className="error">{error}</div>}
            {result && <div className="result"><b><FileArchive size={16}/> {result.status === 'partial' ? t('partialAnalysis') : result.status === 'failed' ? t('failedAnalysis') : t('completedAnalysis')}</b>{result.status === 'partial' && <div className="error">{t('partialCoverage')}</div>}<p>{result.file_count} {t('files')} · {result.detected_technologies.join(', ') || t('noStackMarkers')}</p><small>{result.notice}</small>
              <div className="findings-summary"><AlertTriangle size={16}/> {result.finding_count} {t('potentialFindings')}</div>
              {result.scanner_tools && <div className="tool-status"><b>{t('staticTools')}</b>{result.scanner_tools.tools.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {tool.status}{tool.files_scanned !== undefined ? ' · ' + tool.files_scanned + '/' + (tool.files_available ?? tool.files_scanned) + ' files' : ''}</span>)}{result.scanner_tools.security_tools?.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {tool.status}{tool.coverage?.truncated ? ' · {t('limitedCoverage')}' : ''}{tool.reason ? ' · ' + tool.reason : ''}</span>)}</div>}
              {result.coverage && <div className="dependency-inventory"><b>{t('coverage')}</b><span>{t('heuristics')}:  {result.coverage.heuristics?.candidate_files ?? 0} candidate files · {result.coverage.heuristics?.files_over_file_limit ?? 0} {t('overFileLimit')} · {result.coverage.heuristics?.files_over_total_limit ?? 0} {t('overTotalLimit')}</span>{result.coverage.python_tools && <span>{t('pythonScanners')}:  {result.coverage.python_tools.python_files_scanned ?? 0}/{result.coverage.python_tools.python_files_available ?? 0} files</span>}</div>}
              {result.dependencies && <div className="dependency-inventory">
                <b>{t('dependencyManifests')} · {result.dependencies.manifest_count}</b>
                <small>{result.dependencies.notice}</small>
                {result.dependencies.manifests.map(item => <span key={item.file}>{item.file} · {item.ecosystem}{item.dependency_count !== null ? ' · ' + item.dependency_count + ' ' + t('dependencies') : ''}</span>)}
              </div>}
              {result.findings.map((finding, index) => <article className="finding" key={finding.rule_id + finding.file + finding.line + index}>
                <div className="finding-heading"><b>{finding.title}</b><span className={'severity ' + finding.severity}>{finding.severity.toUpperCase()}</span></div>
                <small>{finding.rule_id} · {finding.file}:{finding.line ?? '—'} · {t('confidence')}: {finding.confidence} · {t('notVerified')}</small>
                {finding.package && <small>{finding.package.ecosystem}:{finding.package.name}@{finding.package.version}</small>}
                {finding.aliases?.length ? <small>Aliases: {finding.aliases.join(', ')}</small> : null}
                {finding.references?.map(url => <small key={url}><a href={url} target="_blank" rel="noreferrer">{t('advisoryReference')}</a></small>)}
                <pre>{finding.evidence}</pre><p>{finding.recommendation}</p>
              </article>)}
              <details><summary>{t('inspectedPaths')} ({result.sample_paths.length} {t('shown')})</summary><ul>{result.sample_paths.slice(0,20).map(p=><li key={p}>{p}</li>)}</ul></details>
            </div>}
          </section>
          <section className="panel"><div className="panel-icon cyan"><Globe size={21}/></div><div className="panel-title"><h3>{t('websiteScanner')}</h3><span className="coming">{t('soon')}</span></div><p>{t('websiteDescription')}</p><div className="disabled-input"><Globe size={17}/><span>https://your-authorized-domain.com</span><LockKeyhole size={15}/></div><button className="secondary-btn" disabled>{t('websiteNotEnabled')}</button><div className="safety-note"><LockKeyhole size={15}/> {t('websiteSafety')}</div></section>
        </div>
        <section className="panel audit-history" id="audit-history"><div className="section-heading"><div><h2>{t('auditHistoryTitle')}</h2><p>{t('latestAssessments')}</p></div><button className="secondary-btn" onClick={() => void refreshHistory()}>{t('refresh')}</button></div>{historyError && <div className="error">{historyError}</div>}{history.length === 0 && !historyError ? <p>{t('noAudits')}</p> : <div className="history-list">{history.map(item => <article className="history-item" key={item.id}><div><b>{item.target}</b><small>{item.analysis_type.replaceAll("_", " ")} · {new Date(item.created_at).toLocaleString()}</small></div><span className="findings-summary">{item.finding_count} finding(s)</span><button className="history-view" onClick={() => void openAudit(item.id)}>{t('viewReport')}</button></article>)}</div>}{detailBusy && <p>{t('loadingReport')}</p>}{selectedAudit && <div className="audit-detail"><div className="audit-detail-heading"><div><h3>{selectedAudit.target}</h3><small>{selectedAudit.analysis_type.replaceAll('_', ' ')} · {new Date(selectedAudit.created_at).toLocaleString()}</small></div><button className="history-view" onClick={() => setSelectedAudit(null)}>{t('close')}</button></div><p>{selectedAudit.finding_count} {t('findingsRecorded')}</p>{selectedAudit.result.findings?.length ? selectedAudit.result.findings.map((finding, index) => <article className="finding" key={(finding.rule_id ?? 'finding') + index}><div className="finding-heading"><b>{finding.title ?? finding.rule_id ?? 'Achado de segurança'}</b><span className={'severity ' + (finding.severity ?? 'unknown')}>{(finding.severity ?? 'unknown').toUpperCase()}</span></div><small>{finding.rule_id ?? '—'} · {finding.file ?? finding.url ?? '—'}{finding.line ? ':' + finding.line : ''}</small>{finding.evidence && <pre>{finding.evidence}</pre>}{finding.recommendation && <p>{finding.recommendation}</p>}</article>) : <p>{t('noFindingDetails')}</p>}</div>}</section>
        <div className="bottom-note"><ShieldCheck size={17}/><span><b>{t('builtSecurely')}</b> {t('uploadedCodeNotice')}</span></div>
        <footer>VULNSCAN · SECURITY INTELLIGENCE · {t('authorizedTesting')}</footer>
      </section>
    </main>
  </div>
}
