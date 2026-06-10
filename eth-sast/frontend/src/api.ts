export type Finding = {
  vulnerability: string
  function: string
  location: [number, number] | null
  message: string
}

export async function analyzeSource(source: string) {
  const response = await fetch('http://localhost:8000/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source }),
  })
  return response.json()
}
