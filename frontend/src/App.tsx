import { useState, useEffect } from 'react'
import { Shield } from 'lucide-react'
import { scanApi } from './api/client'
import { ScanForm } from './components/ScanForm'
import { ProgressBar } from './components/ProgressBar'
import { ResultsTable } from './components/ResultsTable'
import type { ScanStatusResponse } from './types'

function App() {
  const [scanId, setScanId] = useState<string | null>(null)
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Poll scan status
  useEffect(() => {
    if (!scanId) return

    const interval = setInterval(async () => {
      try {
        const status = await scanApi.getScanStatus(scanId)
        setScanStatus(status)

        if (status.status === 'done' || status.status === 'partial' || status.status === 'failed') {
          clearInterval(interval)
        }
      } catch (err) {
        console.error('Error polling scan status:', err)
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [scanId])

  const handleStartScan = async (targets: string[], modules: string[]) => {
    try {
      setIsLoading(true)
      setError(null)

      const response = await scanApi.createScan({
        targets,
        modules,
        options: {
          timeoutSeconds: 30,
          parallelism: 6,
        },
      })

      setScanId(response.scanId)
      setScanStatus({
        scanId: response.scanId,
        status: response.status,
        createdAt: response.createdAt,
        updatedAt: response.createdAt,
        startedAt: null,
        finishedAt: null,
        targets,
        modules,
        progress: {
          completedModules: 0,
          totalModules: modules.length,
          percent: 0,
        },
        results: null,
        errors: [],
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start scan'
      setError(message)
      console.error('Error starting scan:', err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="h-20 border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="h-full px-4 flex items-center gap-3">
          <Shield className="text-blue-500" size={32} />
          <div>
            <h1 className="text-2xl font-bold text-slate-100">SecVal</h1>
            <p className="text-sm text-slate-400">Vulnerability Assessment</p>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-[96rem] mx-auto px-4 py-8 w-full">
        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg text-red-400">
            {error}
          </div>
        )}

        <ScanForm
          onSubmit={handleStartScan}
          isLoading={isLoading}
          results={scanStatus && (
            <div className="space-y-6">
              {scanStatus.results && Object.keys(scanStatus.results).length > 0 && (
                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-slate-100">Results</h2>
                  <ResultsTable results={scanStatus.results} />
                </div>
              )}

              {scanStatus.errors && scanStatus.errors.length > 0 && (
                <div className="card p-6">
                  <h2 className="text-lg font-semibold text-slate-100 mb-4">Errors</h2>
                  <div className="space-y-2">
                    {scanStatus.errors.map((err, idx) => (
                      <div key={idx} className="text-sm text-slate-400 p-2 bg-red-900/10 rounded">
                        <strong className="text-slate-300">{err.module}:</strong> {err.message}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        >
          {scanStatus && (
            <ProgressBar
              progress={scanStatus.progress}
              status={scanStatus.status}
            />
          )}
        </ScanForm>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50">
        <div className="max-w-7xl mx-auto px-4 py-6 text-center text-slate-500 text-sm">
          SecVal v0.1.0 • Vulnerability Scanner
        </div>
      </footer>
    </div>
  )
}

export default App
