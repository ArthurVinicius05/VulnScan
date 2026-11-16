import { Moon, Sun } from 'lucide-react'

export type Theme = 'dark' | 'light'

type Props = {
  theme: Theme
  onChange: (theme: Theme) => void
  language: 'pt-BR' | 'en'
}

export default function ThemeToggle({ theme, onChange, language }: Props) {
  const label = language === 'pt-BR'
    ? (theme === 'dark' ? 'Ativar tema claro' : 'Ativar tema escuro')
    : (theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme')

  return <button
    type="button"
    className="theme-toggle"
    aria-label={label}
    aria-pressed={theme === 'light'}
    title={label}
    onClick={() => onChange(theme === 'dark' ? 'light' : 'dark')}
  >
    {theme === 'dark' ? <Sun size={16} aria-hidden="true"/> : <Moon size={16} aria-hidden="true"/>}
  </button>
}
