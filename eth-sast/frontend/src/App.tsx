import { useState } from 'react'
import { analyzeSource, Finding } from './api'

export default function App() {
  const [source, setSource] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [status, setStatus] = useState('')

  async function handleAnalyze() {
    setStatus('Analyzing...')
    const result = await analyzeSource(source)
    if (result.findings) {
      setFindings(result.findings)
      setStatus(`Found ${result.findings.length} findings.`)
    } else {
      setStatus(result.detail || 'Unexpected response')
    }
  }

  return (
    <div className="app-shell">
      <header>
        <h1>EthSAST Dashboard</h1>
        <p>Upload Solidity source and inspect static analysis findings.</p>
      </header>
      <main>
        <section className="controls">
          <label>
            Solidity source
            <textarea
              value={source}
              onChange={(event) => setSource(event.target.value)}
              rows={16}
              placeholder="Paste Solidity contract source here"
            />
          </label>
          <button onClick={handleAnalyze}>Run Static Analysis</button>
          <div className="status">{status}</div>
        </section>
        <section className="findings">
          <h2>Findings</h2>
          {findings.length === 0 ? (
            <p>No findings yet.</p>
          ) : (
            <ul>
              {findings.map((finding, index) => (
                <li key={index} className="finding-card">
                  <strong>{finding.vulnerability}</strong> in <code>{finding.function}</code>
                  <div>{finding.message}</div>
                  <small>{finding.location ? `Line ${finding.location[0] + 1}, Column ${finding.location[1] + 1}` : 'Location unknown'}</small>
                </li>
              ))}
            </ul>
          )}
        </section>
      </main>
    </div>
  )
}
