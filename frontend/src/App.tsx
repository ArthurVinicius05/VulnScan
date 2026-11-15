import { useState } from 'react'
import { ShieldCheck, LayoutDashboard, Globe, FolderCode, History, Settings, Bell, Search, UploadCloud, FileArchive, Activity, ChevronRight, LockKeyhole, ScanSearch, AlertTriangle } from 'lucide-react'
import { uploadSourceZip } from './lib/api'

type Finding = {
  rule_id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  confidence: string
  file: string
  line: number
  evidence: string
  recommendation: string
  verified: boolean
}
type Result = {
  file_count: number
  detected_technologies: string[]
  sample_paths: string[]
  notice: string
  finding_count: number
  findings: Finding[]
  scanner_tools?: { status: string; tools: { name: string; status: string }[] }
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<Result | null>(null)

  async function runAnalysis() {
    if (!file) return
    setBusy(true); setError(''); setResult(null)
    try { setResult(await uploadSourceZip(file)) }
    catch (e) { setError(e instanceof Error ? e.message : 'Erro inesperado.') }
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
        <a><History size={18}/> Audit History</a>
      </nav>
      <div className="sidebar-bottom"><a><Settings size={18}/> Settings</a><div className="profile"><div className="avatar">AV</div><div><b>Workspace</b><small>Local environment</small></div></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb">Workspace <ChevronRight size={14}/> <b>Overview</b></div><div className="top-actions"><button className="icon-btn"><Search size={18}/></button><button className="icon-btn"><Bell size={18}/></button><div className="avatar">AV</div></div></header>
      <section className="content">
        <div className="welcome"><div><div className="eyebrow"><span className="live-dot"/> SECURITY WORKSPACE</div><h1>Security overview</h1><p>Find weaknesses before attackers do. Audit only codebases and websites you are authorized to test.</p></div><div className="date-chip"><Activity size={15}/> SYSTEM READY</div></div>
        <div className="stats">
          <div className="stat-card"><div className="stat-top"><span>Audits performed</span><ScanSearch size={18}/></div><strong>0</strong><small>New workspace</small></div>
          <div className="stat-card"><div className="stat-top"><span>Issues detected</span><LockKeyhole size={18}/></div><strong>{result?.finding_count ?? '—'}</strong><small>{result ? 'Current archive' : 'Run your first audit'}</small></div>
          <div className="stat-card"><div className="stat-top"><span>Security score</span><ShieldCheck size={18}/></div><strong>—</strong><small>Scoring not implemented</small></div>
        </div>
        <div className="section-heading"><div><h2>Start an assessment</h2><p>Choose a target type to begin your security review.</p></div></div>
        <div className="scan-grid">
          <section className="panel"><div className="panel-icon purple"><FolderCode size={21}/></div><div className="panel-title"><h3>Source code analysis</h3><span className="available">AVAILABLE · PHASE 2</span></div><p>Inspect project structure and run bounded static checks for common insecure coding patterns. Uploaded code is never executed.</p>
            <label className="dropzone"><UploadCloud size={26}/><b>{file ? file.name : 'Drop your ZIP file here'}</b><span>{file ? (file.size / 1024 / 1024).toFixed(2) + ' MB' : 'or click to browse · max 25 MB'}</span><input type="file" accept=".zip,application/zip" onChange={e => {setFile(e.target.files?.[0] ?? null);setResult(null);setError('')}} /></label>
            <button className="primary-btn" disabled={!file || busy} onClick={runAnalysis}>{busy ? 'Analyzing source…' : 'Analyze source archive'} <ChevronRight size={17}/></button>
            {error && <div className="error">{error}</div>}
            {result && <div className="result"><b><FileArchive size={16}/> Analysis completed</b><p>{result.file_count} files · {result.detected_technologies.join(', ') || 'No known stack markers detected'}</p><small>{result.notice}</small>
              <div className="findings-summary"><AlertTriangle size={16}/> {result.finding_count} potential finding(s)</div>
              {result.scanner_tools && <div className="tool-status"><b>Static tools</b>{result.scanner_tools.tools.map(tool => <span key={tool.name} className={tool.status}>{tool.name}: {tool.status}</span>)}</div>}
              {result.findings.map((finding, index) => <article className="finding" key={finding.rule_id + finding.file + finding.line + index}>
                <div className="finding-heading"><b>{finding.title}</b><span className={'severity ' + finding.severity}>{finding.severity.toUpperCase()}</span></div>
                <small>{finding.rule_id} · {finding.file}:{finding.line} · confidence: {finding.confidence} · not verified</small>
                <pre>{finding.evidence}</pre><p>{finding.recommendation}</p>
              </article>)}
              <details><summary>Inspected paths ({result.sample_paths.length} shown)</summary><ul>{result.sample_paths.slice(0,20).map(p=><li key={p}>{p}</li>)}</ul></details>
            </div>}
          </section>
          <section className="panel"><div className="panel-icon cyan"><Globe size={21}/></div><div className="panel-title"><h3>Website scanner</h3><span className="coming">COMING IN PHASE 3</span></div><p>Review HTTPS configuration, security headers, cookie attributes, and exposed information on authorized targets.</p><div className="disabled-input"><Globe size={17}/><span>https://your-authorized-domain.com</span><LockKeyhole size={15}/></div><button className="secondary-btn" disabled>Website scanning is not enabled yet</button><div className="safety-note"><LockKeyhole size={15}/> Active checks will require explicit authorization and safe scope controls.</div></section>
        </div>
        <div className="bottom-note"><ShieldCheck size={17}/><span><b>Built with security in mind.</b> Uploaded code is treated as untrusted input and is never executed by this service.</span></div>
        <footer>VULNSCAN PRO · STATIC ANALYSIS BUILD 0.2.0 · FOR AUTHORIZED SECURITY TESTING</footer>
      </section>
    </main>
  </div>
}
