import { useState, type FormEvent } from 'react'
import { requestPasswordReset, resetPassword, verifyEmail, resendVerification } from './lib/api'

type Props = { onBack: () => void }

export default function AccountRecovery({ onBack }: Props) {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const verifyToken = params.get('verify') ?? ''
  const resetToken = params.get('reset') ?? ''
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function run(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true); setError(''); setMessage('')
    try {
      if (verifyToken) setMessage(await verifyEmail(verifyToken))
      else if (resetToken) setMessage(await resetPassword(resetToken, password))
      else setMessage(await requestPasswordReset(email))
      if (verifyToken || resetToken) window.history.replaceState({}, '', window.location.pathname)
    } catch (e) { setError(e instanceof Error ? e.message : 'Não foi possível concluir a operação.') }
    finally { setBusy(false) }
  }

  async function resend() {
    setBusy(true); setError(''); setMessage('')
    try { setMessage(await resendVerification(email)) }
    catch (e) { setError(e instanceof Error ? e.message : 'Não foi possível reenviar o e-mail.') }
    finally { setBusy(false) }
  }

  return <div className="auth-screen"><form className="auth-card" onSubmit={run}>
    <div className="brand-mark">V</div>
    <h1>{verifyToken ? 'Confirmar e-mail' : resetToken ? 'Nova senha' : 'Recuperar acesso'}</h1>
    <p>{verifyToken ? 'Confirme seu endereço de e-mail para liberar o acesso.' : resetToken ? 'Escolha uma nova senha para sua conta.' : 'Informe seu e-mail para receber um link seguro de redefinição.'}</p>
    {!verifyToken && !resetToken && <label>E-mail<input type="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)}/></label>}
    {resetToken && <label>Nova senha<input type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)}/></label>}
    {message && <div className="success">{message}</div>}
    {error && <div className="error">{error}</div>}
    <button className="primary-btn" disabled={busy}>{busy ? 'Aguarde…' : verifyToken ? 'Confirmar e-mail' : resetToken ? 'Redefinir senha' : 'Enviar instruções'}</button>
    {!verifyToken && !resetToken && <button type="button" className="auth-switch" disabled={busy} onClick={()=>void resend()}>Reenviar confirmação de e-mail</button>}
    <button type="button" className="auth-switch" onClick={onBack}>Voltar ao login</button>
  </form></div>
}
