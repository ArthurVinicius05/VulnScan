import type { Language } from './i18n'

type Props = {
  language: Language
  onChange: (language: Language) => void
}

export default function LanguageToggle({ language, onChange }: Props) {
  return <div className="language-toggle" role="group" aria-label={language === 'pt-BR' ? 'Idioma' : 'Language'}>
    <button type="button" aria-pressed={language === 'pt-BR'} className={language === 'pt-BR' ? 'selected' : ''} onClick={() => onChange('pt-BR')}>PT-BR</button>
    <button type="button" aria-pressed={language === 'en'} className={language === 'en' ? 'selected' : ''} onClick={() => onChange('en')}>EN</button>
  </div>
}
