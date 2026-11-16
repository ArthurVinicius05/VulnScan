import type { Language } from './i18n'
import { translate } from './i18n'

export type FindingCardData = {
  rule_id?: string
  title?: string
  severity?: string
  confidence?: string
  file?: string
  url?: string
  line?: number | null
  evidence?: string
  recommendation?: string
  verified?: boolean
  aliases?: string[]
  references?: string[]
  package?: { name: string; version: string; ecosystem: string }
}

type Props = {
  finding: FindingCardData
  language: Language
}

function safeReferenceUrl(value: string): string | null {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null
  } catch {
    return null
  }
}

export default function FindingCard({ finding, language }: Props) {
  const t = (key: Parameters<typeof translate>[1]) => translate(language, key)
  const severity = finding.severity || 'unknown'
  const location = finding.file || finding.url
  const title = finding.title || finding.rule_id || (language === 'pt-BR' ? 'Achado de segurança' : 'Security finding')

  return <article className="finding">
    <div className="finding-heading">
      <b>{title}</b>
      <span className={'severity ' + severity}>{severity.toUpperCase()}</span>
    </div>
    <div className="finding-meta">
      {finding.rule_id && <span>{finding.rule_id}</span>}
      {location && <span>{location}{finding.line ? ':' + finding.line : ''}</span>}
      {finding.confidence && <span>{t('confidence')}: {finding.confidence}</span>}
      {finding.verified !== undefined && <span>{finding.verified ? t('verified') : t('notVerified')}</span>}
    </div>
    {finding.package && <small>{finding.package.ecosystem}:{finding.package.name}@{finding.package.version}</small>}
    {finding.aliases?.length ? <small>{language === 'pt-BR' ? 'Apelidos' : 'Aliases'}: {finding.aliases.join(', ')}</small> : null}
    {finding.references?.map(reference => {
      const href = safeReferenceUrl(reference)
      return href ? <small key={reference}><a href={href} target="_blank" rel="noopener noreferrer">{t('advisoryReference')}</a></small> : null
    })}
    {finding.evidence && <section className="finding-section">
      <h4>{t('evidenceLabel')}</h4>
      <pre>{finding.evidence}</pre>
    </section>}
    {finding.recommendation && <section className="finding-section">
      <h4>{t('remediationLabel')}</h4>
      <p>{finding.recommendation}</p>
    </section>}
  </article>
}
