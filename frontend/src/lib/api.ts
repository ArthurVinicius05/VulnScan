const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export async function uploadSourceZip(file: File) {
  const body = new FormData()
  body.append('file', file)
  const response = await fetch(`${API_URL}/api/analysis/source-zip`, {
    method: 'POST',
    body,
  })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.detail ?? 'Falha ao analisar o arquivo.')
  return payload
}
