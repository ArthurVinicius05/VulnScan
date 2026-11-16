import { useState, type FormEvent } from 'react'
import { requestPasswordReset, resetPassword, verifyEmail, resendVerification } from './lib/api'
import LanguageToggle from './LanguageToggle'
import ThemeToggle, { type Theme } from './ThemeToggle'
import type { Language } from './i18n'

type Props = { onBack: () => void; language: Language; onLanguageChange: (language: Language) => void; theme: Theme; onThemeChange: (theme: Theme) => void }

export default function AccountRecovery({ onBack, language, onLanguageChange, theme, onThemeChange }: Props) {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const verifyToken = params.get('verify') ?? ''
  const resetToken = params.get('reset') ?? ''
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pt = language === 'pt-BR'

  async function run(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true); setError(''); setMessage('')
    try {
      if (verifyToken) setMessage(await verifyEmail(verifyToken))
      else if (resetToken) setMessage(await resetPassword(resetToken, password))
      else setMessage(await requestPasswordReset(email))
      if (verifyToken || resetToken) window.history.replaceState({}, '', window.location.pathname)
    } catch (e) { setError(e instanceof Error ? e.message : (pt ? 'Não foi possível concluir a operação.' : 'Could not complete the request.')) }
    finally { setBusy(false) }
  }

  async function resend() {
    setBusy(true); setError(''); setMessage('')
    try { setMessage(await resendVerification(email)) }
    catch (e) { setError(e instanceof Error ? e.message : (pt ? 'Não foi possível reenviar o e-mail.' : 'Could not resend the email.')) }
    finally { setBusy(false) }
  }

  return <div className="auth-screen">
    <div className="auth-language auth-controls"><ThemeToggle theme={theme} onChange={onThemeChange} language={language}/><LanguageToggle language={language} onChange={onLanguageChange}/></div>
    <form className="auth-card" onSubmit={run}>
      <div className="brand-mark">V</div>
      <h1>{verifyToken ? (pt ? 'Confirmar e-mail' : 'Confirm email') : resetToken ? (pt ? 'Nova senha' : 'New password') : (pt ? 'Recuperar acesso' : 'Recover access')}</h1>
      <p>{verifyToken ? (pt ? 'Confirme seu endereço de e-mail para liberar o acesso.' : 'Confirm your email address to unlock access.') : resetToken ? (pt ? 'Escolha uma nova senha para sua conta.' : 'Choose a new password for your account.') : (pt ? 'Informe seu e-mail para receber um link seguro de redefinição.' : 'Enter your email to receive a secure reset link.')}</p>
      {!verifyToken && !resetToken && <label>{pt ? 'E-mail' : 'Email'}<input type="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)}/></label>}
      {resetToken && <label>{pt ? 'Nova senha' : 'New password'}<input type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)}/></label>}
      {message && <div className="success">{message}</div>}
      {error && <div className="error">{error}</div>}
      <button className="primary-btn" disabled={busy}>{busy ? (pt ? 'Aguarde…' : 'Please wait…') : verifyToken ? (pt ? 'Confirmar e-mail' : 'Confirm email') : resetToken ? (pt ? 'Redefinir senha' : 'Reset password') : (pt ? 'Enviar instruções' : 'Send instructions')}</button>
      {!verifyToken && !resetToken && <button type="button" className="auth-switch" disabled={busy} onClick={()=>void resend()}>{pt ? 'Reenviar confirmação de e-mail' : 'Resend email verification'}</button>}
      <button type="button" className="auth-switch" onClick={onBack}>{pt ? 'Voltar ao login' : 'Back to login'}</button>
    </form>
  </div>
}
