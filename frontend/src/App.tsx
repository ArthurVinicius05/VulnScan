import { useEffect, useLayoutEffect, useRef, useState, type FormEvent } from 'react'
import AccountRecovery from './AccountRecovery'
import LanguageToggle from './LanguageToggle'
import ThemeToggle, { type Theme } from './ThemeToggle'
import FindingCard from './FindingCard'
import { getInitialLanguage, translate, translateAnalysisType, translateBackendText, translateStatus, translateSeverity, type Language, type TranslationKey } from './i18n'
import { ShieldCheck, LayoutDashboard, Globe, FolderCode, History, Settings, UploadCloud, FileArchive, Activity, ChevronRight, LockKeyhole, ScanSearch, AlertTriangle } from 'lucide-react'
import { ApiError, authenticate, checkSession, completeMfaLogin, fetchAccountInfo, beginMfaSetup, confirmMfaSetup, disableMfa, fetchAuditDetail, fetchAuditHistory, cancelAnalysisJob, deleteAccount, logout, uploadSourceZip, scanWebsite, compareAudits, type AuditHistoryItem, type AuditDetail, type AuditComparison, type WebsiteScanResult } from './lib/api'

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
  security_score?: { value: number; rating: string; model_version: string; raw_value: number; score_cap: number; is_capped: boolean; cap_reasons: string[]; confidence: string; finding_count: number; severity_counts: Record<string, number>; deductions: Record<string, number>; methodology: string; disclaimer: string }
  coverage?: {
    overall: string
    heuristics?: { candidate_files: number; files_scanned?: number; unreadable_files?: number; files_over_file_limit: number; files_over_total_limit: number; findings_returned: number; possibly_truncated_by_finding_limit: boolean }
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

function exportAuditReport(audit: AuditDetail) {
  const payload = {
    product: 'VulnScan',
    format_version: 1,
    exported_at: new Date().toISOString(),
    audit,
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  const safeId = audit.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80) || 'report'
  link.href = objectUrl
  link.download = `vulnscan-audit-${safeId}.json`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(objectUrl)
}

export default function App() {
  const [language, setLanguage] = useState<Language>(getInitialLanguage)
  const validSections = ['overview', 'website-scanner', 'code-analyzer', 'audit-history', 'settings', 'profile'] as const
  const [activeSection, setActiveSection] = useState<string>(() => {
    const requested = window.location.pathname.replace(/^\/+|\/+$/g, '') || 'overview'
    return (validSections as readonly string[]).includes(requested) ? requested : 'overview'
  })
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = window.localStorage.getItem('vulnscan-theme')
      if (saved === 'light' || saved === 'dark') return saved
    } catch { /* Storage may be unavailable. */ }
    return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })
  const t = (key: TranslationKey) => translate(language, key)
  const mainRef = useRef<HTMLElement>(null)
  const previousSection = useRef(activeSection)
  function navigateTo(section: string) {
    setActiveSection(section)
    const path = section === 'overview' ? '/overview' : `/${section}`
    if (window.location.pathname !== path) window.history.pushState({}, '', path)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
  useEffect(() => {
    const syncRoute = () => {
      const requested = window.location.pathname.replace(/^\/+|\/+$/g, '') || 'overview'
      setActiveSection((validSections as readonly string[]).includes(requested) ? requested : 'overview')
    }
    window.addEventListener('hashchange', syncRoute)
    window.addEventListener('popstate', syncRoute)
    return () => { window.removeEventListener('hashchange', syncRoute); window.removeEventListener('popstate', syncRoute) }
  }, [])
  useEffect(() => {
    if (previousSection.current !== activeSection) {
      mainRef.current?.focus({ preventScroll: true })
      previousSection.current = activeSection
    }
  }, [activeSection])

  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [analysisStatus, setAnalysisStatus] = useState('')
  const [error, setError] = useState('')
  const [websiteUrl, setWebsiteUrl] = useState('')
  const [websiteAuthorized, setWebsiteAuthorized] = useState(false)
  const [websiteBusy, setWebsiteBusy] = useState(false)
  const [websiteError, setWebsiteError] = useState('')
  const [websiteResult, setWebsiteResult] = useState<WebsiteScanResult | null>(null)
  const [result, setResult] = useState<Result | null>(null)
  const [history, setHistory] = useState<AuditHistoryItem[]>([])
  const [historyError, setHistoryError] = useState('')
  const [selectedAudit, setSelectedAudit] = useState<AuditDetail | null>(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [comparisonBaseline, setComparisonBaseline] = useState<string | null>(null)
  const [comparison, setComparison] = useState<AuditComparison | null>(null)
  const [comparisonBusy, setComparisonBusy] = useState(false)
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
    setComparisonBaseline(null)
    setComparison(null)
    setComparisonBusy(false)
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


  async function chooseComparison(item: AuditHistoryItem) {
    if (!comparisonBaseline || comparisonBaseline === item.id) {
      setComparisonBaseline(comparisonBaseline === item.id ? null : item.id)
      setComparison(null)
      return
    }
    setComparison(null)
    setComparisonBusy(true)
    setHistoryError('')
    try {
      setComparison(await compareAudits(comparisonBaseline, item.id))
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        clearWorkspaceState()
        setAuthenticated(false)
      } else {
        setHistoryError(e instanceof Error ? e.message : t('comparisonFailed'))
      }
    } finally {
      setComparisonBusy(false)
    }
  }

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
    try { window.localStorage.setItem('vulnscan-theme', theme) } catch { /* Storage may be unavailable. */ }
    const themeColor = document.querySelector('meta[name="theme-color"]')
    themeColor?.setAttribute('content', theme === 'light' ? '#f4f7fb' : '#090d18')
  }, [theme])

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
        setAuthNotice(typeof authResult?.message === 'string' ? authResult.message : t('accountCreatedNotice'))
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
    catch (e) {
      const message = e instanceof Error ? e.message : t('mfaSetupFailed')
      setMfaError(message.includes('MFA_ENCRYPTION_KEY') ? t('mfaKeyMissing') : message)
    }
  }

  async function activateMfa() {
    setMfaError(''); setMfaMessage('')
    try {
      const codes = await confirmMfaSetup(mfaActionCode)
      setMfaEnabled(true); setMfaSetup(null); setMfaActionCode('')
      setMfaRecoveryCodes(codes)
      setMfaMessage(t('mfaActivatedNotice'))
    } catch (e) { setMfaError(e instanceof Error ? e.message : t('mfaEnableFailed')) }
  }

  async function deactivateMfa() {
    setMfaError(''); setMfaMessage('')
    try {
      await disableMfa(mfaActionCode)
      clearWorkspaceState(); setAuthenticated(false)
      setMfaMessage(t('mfaDisabledNotice'))
    } catch (e) { setMfaError(e instanceof Error ? e.message : t('mfaDisableFailed')) }
  }

  async function removeAccount() {
    setMfaError(''); setMfaMessage('')
    try {
      await deleteAccount(deletePassword, deleteMfaCode)
      clearWorkspaceState(); setAuthenticated(false)
      setAuthNotice(t('accountDeletedNotice'))
    } catch (e) { setMfaError(e instanceof Error ? e.message : t('accountDeleteFailed')) }
  }

  async function endSession() { let logoutFailed = false; try { await logout() } catch { logoutFailed = true } finally { clearWorkspaceState(); setAuthenticated(false) } if (logoutFailed) setAuthNotice(t('logoutUnconfirmed')) }

  if (authChecking) return <div className="auth-screen"><div className="auth-language auth-controls"><ThemeToggle theme={theme} onChange={setTheme} language={language}/><LanguageToggle language={language} onChange={setLanguage}/></div><p>{t('checkingSession')}</p></div>
  if (!authenticated && (showRecovery || new URLSearchParams(window.location.hash.replace(/^#/, '')).has('verify') || new URLSearchParams(window.location.hash.replace(/^#/, '')).has('reset'))) return <AccountRecovery language={language} onLanguageChange={setLanguage} theme={theme} onThemeChange={setTheme} onBack={() => { setShowRecovery(false); window.history.replaceState({}, '', window.location.pathname) }} />
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

  async function runWebsiteScan() {
    setWebsiteBusy(true); setWebsiteError(''); setWebsiteResult(null)
    try {
      const result = await scanWebsite(websiteUrl.trim())
      setWebsiteResult(result)
      await refreshHistory()
    } catch (e) {
      setWebsiteError(e instanceof Error ? e.message : t('websiteScanFailed'))
    } finally { setWebsiteBusy(false) }
  }

  async function cancelQueuedJob() {
    if (!activeJobId) return
    try {
      await cancelAnalysisJob(activeJobId)
      setAnalysisStatus('cancelled')
      setError(t('queuedCancelled'))
    } catch (e) {
      setError(e instanceof Error ? e.message : t('cancelAnalysisFailed'))
    }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={22}/></div><div><strong>VulnScan</strong><small>SECURITY INTELLIGENCE</small></div></div>
      <div className="nav-label">{t('workspace').toUpperCase()}</div>
      <nav aria-label={t("workspace")}>
        <a className={activeSection === "overview" ? "active" : ""} aria-current={activeSection === "overview" ? "page" : undefined} href="/overview" onClick={e=>{e.preventDefault();navigateTo('overview')}}><LayoutDashboard size={18}/> {t('overview')}</a>
        <a className={activeSection === "website-scanner" ? "active" : ""} aria-current={activeSection === "website-scanner" ? "page" : undefined} href="/website-scanner" onClick={e=>{e.preventDefault();navigateTo('website-scanner')}}><Globe size={18}/> {t('websiteScanner')}</a>
        <a className={activeSection === "code-analyzer" ? "active" : ""} aria-current={activeSection === "code-analyzer" ? "page" : undefined} href="/code-analyzer" onClick={e=>{e.preventDefault();navigateTo('code-analyzer')}}><FolderCode size={18}/> {t('codeAnalyzer')}</a>
        <a className={activeSection === "audit-history" ? "active" : ""} aria-current={activeSection === "audit-history" ? "page" : undefined} href="/audit-history" onClick={e=>{e.preventDefault();navigateTo('audit-history')}}><History size={18}/> {t('auditHistory')}</a>
      </nav>
      <div className="sidebar-bottom"><a className={activeSection === "settings" ? "active" : ""} aria-current={activeSection === "settings" ? "page" : undefined} href="/settings" onClick={e=>{e.preventDefault();navigateTo('settings')}}><Settings size={18}/> {t('settings')}</a></div>
    </aside>
    <main ref={mainRef} className="main" tabIndex={-1}>
      <header className="topbar"><div className="crumb">{t('workspace')} <ChevronRight size={14}/> <b>{activeSection === 'settings' ? t('settings') : activeSection === 'profile' ? t('profileTitle') : activeSection === 'website-scanner' ? t('websiteScanner') : activeSection === 'code-analyzer' ? t('codeAnalyzer') : activeSection === 'audit-history' ? t('auditHistory') : t('overview')}</b></div><div className="top-actions"><ThemeToggle theme={theme} onChange={setTheme} language={language}/><LanguageToggle language={language} onChange={setLanguage}/><details className="profile-menu"><summary><div className="avatar">AV</div><span>{t('account')}</span></summary><div className="profile-menu-content"><b>{t('account')}</b><small>{emailVerified ? t('verifiedEmail') : t('unverifiedEmail')}</small><a href="/profile" onClick={e=>{e.preventDefault();navigateTo('profile')}}>{t('profileTitle')}</a><a href="/settings" onClick={e=>{e.preventDefault();navigateTo('settings')}}>{t('securitySettings')}</a><button type="button" onClick={()=>void endSession()}>{t('signOut')}</button></div></details></div></header>
      <section className="content">
{activeSection === 'overview' && <div className="route-page overview-page">
        <div className="welcome" id="overview"><div><div className="eyebrow"><span className="live-dot"/> {t('securityWorkspace')}</div><h1>{t('securityOverview')}</h1><p>{t('overviewDescription')}</p></div><div className="date-chip"><Activity size={15}/> {t('codeAnalyzerReady')}</div></div>
        <div className="stats">
          <div className="stat-card"><div className="stat-top"><span>{t('auditsPerformed')}</span><ScanSearch size={18}/></div><strong>{history.length}</strong><small>{t('savedAudits')}</small></div>
          <div className="stat-card"><div className="stat-top"><span>{t('issuesDetected')}</span><LockKeyhole size={18}/></div><strong>{result?.finding_count ?? '—'}</strong><small>{result ? t('currentArchive') : t('runFirstAudit')}</small></div>
          <div className="stat-card"><div className="stat-top"><span>{t('securityScore')}</span><ShieldCheck size={18}/></div><strong>{result?.security_score ? result.security_score.value + '/100' : '—'}</strong><small>{result?.security_score ? t('scoreFromCurrentAnalysis') : t('scoreNeedsAnalysis')}</small></div>
        </div>
        </div>}
{activeSection === 'settings' && <div className="route-page settings-page">
        <section className="panel account-security" id="settings">
          <div className="settings-page-heading"><div><h2>{t('settings')}</h2><p>{t('settingsDescription')}</p></div></div>
          <div className="section-heading" id="account-security"><div><h3>{t('accountSecurity')}</h3><p>{t('accountSecurityDescription')}</p></div><span className={mfaEnabled ? 'available' : 'coming'}>{mfaEnabled ? t('mfaEnabled') : t('mfaNotEnabled')}</span></div>
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
              {mfaEnabled && <label>{t('authenticatorOrRecovery')}<input value={deleteMfaCode} onChange={e=>setDeleteMfaCode(e.target.value)} maxLength={64}/></label>}
              <button className="secondary-btn" disabled={deletePassword.length < 12 || (mfaEnabled && deleteMfaCode.length < 6)} onClick={()=>void removeAccount()}>{t('permanentlyDelete')}</button>
              <button className="auth-switch" onClick={()=>{setDeleteAccountOpen(false);setDeletePassword('');setDeleteMfaCode('')}}>{t('cancel')}</button>
            </div>}
          </div>
        </section>
        <section className="panel settings-preferences" id="settings-preferences">
          <div className="section-heading"><div><h3>{t('preferences')}</h3><p>{t('preferencesDescription')}</p></div></div>
          <div className="settings-preference-row"><div><b>{t('appearance')}</b><small>{language === 'pt-BR' ? 'Claro ou escuro' : 'Light or dark'}</small></div><ThemeToggle theme={theme} onChange={setTheme} language={language}/></div>
          <div className="settings-preference-row"><div><b>{t('interfaceLanguage')}</b><small>{language === 'pt-BR' ? 'Português ou inglês' : 'Portuguese or English'}</small></div><LanguageToggle language={language} onChange={setLanguage}/></div>
        </section>
        </div>}
{activeSection === 'code-analyzer' && <div className="route-page analyzer-page">
        <div className="section-heading"><div><h2>{t('startAssessment')}</h2><p>{t('chooseTarget')}</p></div></div>
        <div className="scan-grid">
          <section className="panel" id="code-analyzer"><div className="panel-icon purple"><FolderCode size={21}/></div><div className="panel-title"><h3>{t('sourceAnalysis')}</h3><span className="available">{t('available')}</span></div><p>{t('sourceDescription')}</p>
            <label className="dropzone"><UploadCloud size={26}/><b>{file ? file.name : t('dropZip')}</b><span>{file ? (file.size / 1024 / 1024).toFixed(2) + ' MB' : t('browseZip')}</span><input type="file" accept=".zip,application/zip" onChange={e => {const selected=e.target.files?.[0] ?? null;setResult(null);if(selected && selected.size > 100 * 1024 * 1024){setFile(null);setError(t('fileTooLarge'));return}setFile(selected);setError('')}} /></label>
            <small className="source-archive-notice">{t('sourceArchiveNotice')}</small>
            <button className="primary-btn" disabled={!file || busy} onClick={runAnalysis}>{busy ? t('waitingAnalysis') : (language === 'pt-BR' ? 'Analisar arquivo-fonte' : 'Analyze source archive')} <ChevronRight size={17}/></button>
            {busy && <div className="analysis-progress"><span>{analysisStatus === 'queued' ? t('queuedStatus') : analysisStatus === 'running' ? t('runningStatus') : t('uploadingStatus')}</span>{analysisStatus === 'queued' && activeJobId && <button className="auth-switch" onClick={()=>void cancelQueuedJob()}>{t('cancelQueued')}</button>}</div>}
            {error && <div className="error">{error}</div>}
            {result && <div className="result"><b><FileArchive size={16}/> {result.status === 'partial' ? t('partialAnalysis') : result.status === 'failed' ? t('failedAnalysis') : t('completedAnalysis')}</b>{result.status === 'partial' && <div className="error">{t('partialCoverage')}</div>}<p>{result.file_count} {t('files')} · {result.detected_technologies.join(', ') || t('noStackMarkers')}</p><small>{translateBackendText(language, result.notice)}</small>
              <div className="findings-summary"><AlertTriangle size={16}/> {result.finding_count} {t('potentialFindings')}</div>
              {result.security_score && <div className="dependency-inventory"><b>{t('securityScore')}: {result.security_score.value}/100</b><span>{t('scoreRating')}: {t(result.security_score.rating === 'strong' ? 'scoreStrong' : result.security_score.rating === 'good' ? 'scoreGood' : result.security_score.rating === 'needs_attention' ? 'scoreNeedsAttention' : 'scoreHighRisk')}</span><span>{t('scoreModel')}: {result.security_score.model_version} · {t('scoreConfidence')}: {t(result.security_score.confidence === 'limited' ? 'scoreLimited' : 'scoreStandard')}</span>{result.security_score.is_capped && <span>{t('scoreCoverageCap')}</span>}<small>{t('scoreDisclaimer')}</small></div>}
              {result.scanner_tools && <div className="tool-status"><b>{t('staticTools')}</b>{result.scanner_tools.tools.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {translateStatus(language, tool.status)}{tool.files_scanned !== undefined ? ' · ' + tool.files_scanned + '/' + (tool.files_available ?? tool.files_scanned) + ' ' + t('files') : ''}</span>)}{result.scanner_tools.security_tools?.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {translateStatus(language, tool.status)}{tool.coverage?.truncated ? ' · ' + t('limitedCoverage') : ''}{tool.reason ? ' · ' + translateBackendText(language, tool.reason) : ''}</span>)}</div>}
              {result.coverage && <div className="dependency-inventory"><b>{t('coverage')}</b><span>{t('heuristics')}: {result.coverage.heuristics?.files_scanned ?? 0}/{result.coverage.heuristics?.candidate_files ?? 0} {t('files')} · {result.coverage.heuristics?.unreadable_files ?? 0} {t('unreadable')} · {result.coverage.heuristics?.files_over_file_limit ?? 0} {t('overFileLimit')} · {result.coverage.heuristics?.files_over_total_limit ?? 0} {t('overTotalLimit')}</span>{result.coverage.python_tools && <span>{t('pythonScanners')}:  {result.coverage.python_tools.python_files_scanned ?? 0}/{result.coverage.python_tools.python_files_available ?? 0} {t('files')}</span>}</div>}
              {result.dependencies && <div className="dependency-inventory">
                <b>{t('dependencyManifests')} · {result.dependencies.manifest_count}</b>
                <small>{translateBackendText(language, result.dependencies.notice)}</small>
                {result.dependencies.manifests.map(item => <span key={item.file}>{item.file} · {item.ecosystem} · {translateStatus(language, item.status)}{item.dependency_count !== null ? ' · ' + item.dependency_count + ' ' + t('dependencies') : ''}</span>)}
              </div>}
              {result.findings.map((finding, index) => <FindingCard key={finding.rule_id + finding.file + finding.line + index} finding={finding} language={language}/>)}
              <details><summary>{t('inspectedPaths')} ({result.sample_paths.length} {t('shown')})</summary><ul>{result.sample_paths.slice(0,20).map(p=><li key={p}>{p}</li>)}</ul></details>
            </div>}
          </section>

        </div>
        </div>}
{activeSection === 'website-scanner' && <section className="panel route-page website-scanner-page">
          <div className="settings-page-heading"><div><h1>{t('websitePageTitle')}</h1><p>{t('websitePageDescription')}</p></div><span className="available">PASSIVE CHECKS</span></div>
          <form className="website-scan-form" onSubmit={event=>{event.preventDefault();void runWebsiteScan()}}>
            <label>{t('websiteUrlLabel')}<input type="url" required maxLength={2048} placeholder="https://example.com" value={websiteUrl} onChange={event=>setWebsiteUrl(event.target.value)} /></label>
            <label className="authorization-check"><input type="checkbox" checked={websiteAuthorized} onChange={event=>setWebsiteAuthorized(event.target.checked)} /> <span>{t('websiteAuthorization')}</span></label>
            <button className="primary-btn" disabled={websiteBusy || !websiteAuthorized || !websiteUrl.trim()}>{websiteBusy ? t('websiteScanning') : t('websiteScanButton')} <ChevronRight size={17}/></button>
          </form>
          <div className="safety-note"><LockKeyhole size={15}/> {t('websiteResultNotice')}</div>
          <div className="website-local-help">{t('websiteDisabledHelp')}</div>
          {websiteError && <div className="error">{websiteError}</div>}
          {websiteResult && <div className="website-result"><h2>{t('websiteScanResult')}</h2><p><b>{websiteResult.target ?? websiteUrl}</b></p><div className="website-result-meta"><span>{t('websiteHttpStatus')}: {websiteResult.http_status ?? '—'}</span>{websiteResult.tls?.version && <span>{t('websiteTls')}: {websiteResult.tls.version}</span>}</div>{websiteResult.redirect_chain?.length ? <div><b>{t('websiteRedirects')}</b><ol>{websiteResult.redirect_chain.map((url,index)=><li key={url+index}>{url}</li>)}</ol></div> : null}<p>{websiteResult.finding_count ?? 0} {t('potentialFindings')}</p>{websiteResult.findings?.length ? websiteResult.findings.map((finding,index)=><article className="website-finding" key={finding.rule_id+index}><div className="finding-heading"><b>{finding.title}</b><span className={'severity '+finding.severity}>{translateSeverity(language,finding.severity)}</span></div><p>{finding.evidence}</p><small>{finding.remediation}</small></article>) : <p>{t('websiteNoFindings')}</p>}{websiteResult.notice && <small>{websiteResult.notice}</small>}</div>}
        </section>}
{activeSection === 'profile' && <section className="panel route-page profile-page"><div className="settings-page-heading"><div><h1>{t('profileTitle')}</h1><p>{t('profileDescription')}</p></div></div><div className="profile-detail-row"><span>{t('emailAddress')}</span><b>{accountEmail || '—'}</b></div><div className="profile-detail-row"><span>{t('accountStatus')}</span><b>{emailVerified ? t('verifiedEmail') : t('unverifiedEmail')}</b></div><button className="secondary-btn" onClick={()=>navigateTo('settings')}>{t('securitySettings')}</button></section>}
{activeSection === 'audit-history' && <div className="route-page history-page">
        <section className="panel audit-history" id="audit-history"><div className="section-heading"><div><h2>{t('auditHistoryTitle')}</h2><p>{t('latestAssessments')}</p></div><button className="secondary-btn" onClick={() => void refreshHistory()}>{t('refresh')}</button></div>{historyError && <div className="error">{historyError}</div>}{history.length === 0 && !historyError ? <p>{t('noAudits')}</p> : <div className="history-list">{history.map(item => <article className="history-item" key={item.id}><div><b>{item.target}</b><small>{translateAnalysisType(language, item.analysis_type)} · {new Date(item.created_at).toLocaleString()}</small></div><span className="findings-summary">{item.finding_count} {t('findingsRecorded')}</span><button className="history-view" onClick={() => void openAudit(item.id)}>{t('viewReport')}</button><button className={comparisonBaseline === item.id ? "history-compare selected" : "history-compare"} disabled={comparisonBusy} onClick={() => void chooseComparison(item)}>{comparisonBaseline === item.id ? t('baselineSelected') : comparisonBaseline ? t('compareWithBaseline') : t('selectBaseline')}</button></article>)}</div>}{comparisonBaseline && <div className="comparison-hint">{t('baselineSelectedHint')} <button className="history-compare" onClick={() => { setComparisonBaseline(null); setComparison(null) }}>{t('clearBaseline')}</button></div>}{comparisonBusy && <p>{t('comparingAudits')}</p>}{comparison && <div className="audit-comparison"><h3>{t('comparisonTitle')}</h3><p>{comparison.baseline.target} → {comparison.candidate.target}</p>{comparison.findings.details_available ? <div className="comparison-stats"><div><b>{comparison.findings.added}</b><small>{t('findingsAdded')}</small></div><div><b>{comparison.findings.resolved}</b><small>{t('findingsResolved')}</small></div><div><b>{comparison.findings.unchanged}</b><small>{t('findingsUnchanged')}</small></div></div> : <p>{t('findingDetailsUnavailable')}</p>}{comparison.score.comparable ? <p>{t('scoreChange')}: {comparison.score.baseline} → {comparison.score.candidate} ({comparison.score.delta !== null && comparison.score.delta > 0 ? '+' : ''}{comparison.score.delta})</p> : <small>{t('scoreNotComparable')}</small>}{comparison.findings.details_available && <details><summary>{t('severityBreakdown')}</summary>{Object.entries(comparison.severity_delta).map(([severity, values]) => <p key={severity}>{translateSeverity(language, severity)}: {values.baseline} → {values.candidate} ({values.delta > 0 ? '+' : ''}{values.delta})</p>)}</details>}</div>}{detailBusy && <p>{t('loadingReport')}</p>}{selectedAudit && <div className="audit-detail"><div className="audit-detail-heading"><div><h3>{selectedAudit.target}</h3><small>{translateAnalysisType(language, selectedAudit.analysis_type)} · {new Date(selectedAudit.created_at).toLocaleString()}</small></div><button className="history-view" onClick={() => exportAuditReport(selectedAudit)}>{t('exportReport')}</button><button className="history-view" onClick={() => setSelectedAudit(null)}>{t('close')}</button></div>{selectedAudit.result.security_score && <div className="dependency-inventory"><b>{t('securityScore')}: {selectedAudit.result.security_score.value}/100</b><span>{t('scoreModel')}: {selectedAudit.result.security_score.model_version} · {t('scoreConfidence')}: {t(selectedAudit.result.security_score.confidence === 'limited' ? 'scoreLimited' : 'scoreStandard')}</span>{selectedAudit.result.security_score.is_capped && <span>{t('scoreCoverageCap')}</span>}<small>{t('scoreDisclaimer')}</small></div>}<h4 className="audit-findings-heading">{t('findingsHeading')}</h4>{selectedAudit.result.findings?.length ? selectedAudit.result.findings.map((finding, index) => <FindingCard key={(finding.rule_id ?? 'finding') + index} finding={finding} language={language}/>) : <p>{t('noFindingDetails')}</p>}</div>}</section>
        </div>}
        <div className="bottom-note"><ShieldCheck size={17}/><span><b>{t('builtSecurely')}</b> {t('uploadedCodeNotice')}</span></div>
        <footer>VULNSCAN · SECURITY INTELLIGENCE · {t('authorizedTesting')}</footer>
      </section>
    </main>
  </div>
}
