import { useState, useEffect } from 'react'
import {
  AlertTriangle,
  Download,
  Loader2,
  Printer,
  RotateCcw,
  Shield,
} from 'lucide-react'
import { scanApi } from './api/client'
import { ScanForm } from './components/ScanForm'
import { ProgressBar } from './components/ProgressBar'
import { ResultsTable } from './components/ResultsTable'
import type { ScanStatusResponse } from './types'

function App() {
  const [scanId, setScanId] = useState<string | null>(null)
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  const isScanning = scanStatus?.status === 'running' || scanStatus?.status === 'pending'
  const isFinished = scanStatus?.status === 'done' || scanStatus?.status === 'partial' || scanStatus?.status === 'failed'

  // Timer effect for elapsed time
  useEffect(() => {
    if (!isScanning) return

    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1)
    }, 1000)

    return () => clearInterval(timer)
  }, [isScanning])

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
      setElapsedSeconds(0)

      const response = await scanApi.createScan({
        targets,
        modules,
        options: {
          timeout_seconds: 600,
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
        skippedTargets: [],
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Gagal memulai proses scan.'
      setError(message)
      console.error('Error starting scan:', err)
    } finally {
      setIsLoading(false)
    }
  }

  const handleResetScan = () => {
    setScanId(null)
    setScanStatus(null)
    setError(null)
    setElapsedSeconds(0)
  }

  const handleDownloadReport = async () => {
    if (!scanId) return
    try {
      setIsDownloading(true)
      const blob = await scanApi.downloadReport(scanId)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `SecVal_Scan_Report_${scanId.slice(0, 8)}.xlsx`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Error downloading report:', err)
      alert('Laporan Excel belum siap atau gagal diunduh.')
    } finally {
      setIsDownloading(false)
    }
  }

  const handlePrint = () => {
    window.print()
  }

  const hasResults = Boolean(scanStatus?.results && Object.keys(scanStatus.results).length > 0)

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100 font-sans selection:bg-blue-600/30">
      {/* Top Header */}
      <header className="h-20 border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-[96rem] mx-auto h-full px-4 sm:px-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-500 shadow-sm shadow-blue-500/20">
              <Shield size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-slate-100">SecVal</h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-950/60 text-blue-400 border border-blue-800/60">
                  v0.1.0
                </span>
              </div>
              <p className="text-xs text-slate-400">Web Application Vulnerability Assessment</p>
            </div>
          </div>

          {/* Quick Header Actions (Print & Export) */}
          <div className="flex items-center gap-2.5 no-print">
            {hasResults && (
              <>
                <button
                  type="button"
                  onClick={handlePrint}
                  className="btn-secondary px-3.5 py-1.5 text-xs inline-flex items-center gap-1.5"
                  title="Cetak atau simpan laporan ke PDF"
                >
                  <Printer size={14} />
                  <span className="hidden sm:inline">Cetak / PDF</span>
                </button>

                <button
                  type="button"
                  onClick={handleDownloadReport}
                  disabled={isDownloading || !isFinished}
                  className="btn-primary px-3.5 py-1.5 text-xs inline-flex items-center gap-1.5"
                  title="Unduh laporan lengkap format Microsoft Excel (.xlsx)"
                >
                  {isDownloading ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Download size={14} />
                  )}
                  <span className="hidden sm:inline">
                    {isDownloading ? 'Mengunduh...' : 'Unduh Excel (.xlsx)'}
                  </span>
                </button>
              </>
            )}

            {isFinished && (
              <button
                type="button"
                onClick={handleResetScan}
                className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1 text-slate-300"
                title="Reset dan mulai pengujian baru"
              >
                <RotateCcw size={14} />
                <span className="hidden sm:inline">Scan Baru</span>
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-[96rem] mx-auto px-4 sm:px-6 py-6 w-full space-y-6">
        {/* Error Notification */}
        {error && (
          <div className="p-4 bg-red-950/40 border border-red-800 rounded-xl text-red-300 text-sm flex items-start gap-3 shadow-lg">
            <AlertTriangle size={18} className="text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <strong className="font-semibold block text-red-200">Terjadi Kesalahan:</strong>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Scan Setup Form */}
        <section className="no-print">
          <ScanForm
            onSubmit={handleStartScan}
            isLoading={isLoading}
            isScanning={isScanning}
            hasResults={hasResults}
            onResetScan={handleResetScan}
          />
        </section>

        {/* Live Progress Bar (when scan is active or recently completed) */}
        {scanStatus && (
          <section className="no-print">
            <ProgressBar
              progress={scanStatus.progress}
              status={scanStatus.status}
              scanId={scanStatus.scanId}
              elapsedSeconds={elapsedSeconds}
              onReset={handleResetScan}
            />
          </section>
        )}

        {/* Results Section */}
        {hasResults && (
          <section className="space-y-4 pt-2">
            {/* Results Header */}
            <div className="pb-2 border-b border-slate-800/80 no-print">
              <h2 className="text-lg font-bold text-slate-100">Hasil Pemeriksaan Keamanan</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Rincian hasil per modul pengujian. Pilih modul pada daftar di bawah.
              </p>
            </div>

            {/* Module-Centric Detail Table */}
            {scanStatus?.results && <ResultsTable results={scanStatus.results} />}

            {/* Skipped Targets (dropped by DNS/TCP pre-flight before scanning) */}
            {scanStatus?.skippedTargets && scanStatus.skippedTargets.length > 0 && (
              <div className="card p-5 border-slate-700/60 bg-slate-900/40 space-y-3 no-print">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <AlertTriangle size={16} className="text-slate-400" />
                  Target dilewati ({scanStatus.skippedTargets.length}) — tidak dapat dijangkau
                </h3>
                <div className="space-y-1.5">
                  {scanStatus.skippedTargets.map((item, idx) => (
                    <div
                      key={`${item.target}-${idx}`}
                      className="text-xs p-2.5 rounded bg-slate-900/60 border border-slate-800 text-slate-300 flex items-start gap-2"
                    >
                      <strong className="text-slate-200 shrink-0 font-mono">{item.target}:</strong>
                      <span className="text-slate-400 break-words">{item.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Module Scan Errors (if any specific module crashed/timed out) */}
            {scanStatus?.errors && scanStatus.errors.length > 0 && (
              <div className="card p-5 border-amber-900/40 bg-amber-950/10 space-y-3 no-print">
                <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
                  <AlertTriangle size={16} className="text-amber-400" />
                  Peringatan: Beberapa modul mengalami kendala ({scanStatus.errors.length})
                </h3>
                <div className="space-y-1.5">
                  {scanStatus.errors.map((err, idx) => (
                    <div
                      key={idx}
                      className="text-xs p-2.5 rounded bg-slate-900/60 border border-slate-800 text-slate-300 flex items-start gap-2"
                    >
                      <strong className="text-amber-400 shrink-0">{err.module}:</strong>
                      <span className="text-slate-400 break-words">{err.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50 py-5 no-print">
        <div className="max-w-[96rem] mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500">
          <div>SecVal v0.1.0 • Automated Web Vulnerability Assessment Platform</div>
          <div>Gunakan hanya pada target yang memiliki otorisasi pengujian.</div>
        </div>
      </footer>
    </div>
  )
}

export default App
