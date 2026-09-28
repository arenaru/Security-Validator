import { useState, useMemo } from 'react'
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  Globe,
  Printer,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import type { ModuleResult, TargetReport } from '../types'
import {
  extractSummaryData,
  formatFullSummaryText,
} from '../utils/reportTransformer'

interface WebSummaryReportProps {
  targetReports: TargetReport[]
  results: Record<string, ModuleResult[]>
  onSelectTarget: (domain: string) => void
}

export function WebSummaryReport({
  targetReports,
  results,
  onSelectTarget,
}: WebSummaryReportProps) {
  const [copied, setCopied] = useState(false)

  const { actionItems, moduleMatrix } = useMemo(() => {
    return extractSummaryData(targetReports, results)
  }, [targetReports, results])

  const handleCopySummary = async () => {
    const text = formatFullSummaryText(targetReports, actionItems, moduleMatrix)
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const insecureCount = actionItems.filter((i) => i.status === 'insecure').length
  const warningCount = actionItems.filter((i) => i.status === 'warning').length

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="card p-5 border-slate-800 bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-lg bg-blue-600/20 text-blue-400 flex items-center justify-center">
              <Shield size={18} />
            </div>
            <h3 className="text-base font-bold text-slate-100">
              Laporan Ringkasan Keamanan (Summary Report)
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Rangkuman menyeluruh dari {targetReports.length} target dan {Object.keys(results).length} modul pemeriksaan.
          </p>
        </div>

        {/* Quick Report Actions */}
        <div className="flex items-center gap-2 no-print">
          <button
            type="button"
            onClick={handleCopySummary}
            className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1.5"
            title="Salin teks ringkasan laporan ke clipboard"
          >
            {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
            <span>{copied ? 'Tersalin!' : 'Salin Ringkasan'}</span>
          </button>

          <button
            type="button"
            onClick={() => window.print()}
            className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1.5"
            title="Cetak atau simpan halaman ini ke PDF"
          >
            <Printer size={14} />
            <span>Cetak / PDF</span>
          </button>
        </div>
      </div>

      {/* SECTION 1: Prioritas Tindakan Perbaikan (Action Items) */}
      <section className="card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-red-400" />
            <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              1. Prioritas Tindakan Perbaikan (Action Items)
            </h4>
          </div>
          <div className="flex items-center gap-2 text-xs">
            {insecureCount > 0 && (
              <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800">
                {insecureCount} Celah Kritis
              </span>
            )}
            {warningCount > 0 && (
              <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800">
                {warningCount} Peringatan
              </span>
            )}
            {actionItems.length === 0 && (
              <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800">
                Nol Temuan Bahaya
              </span>
            )}
          </div>
        </div>

        {actionItems.length > 0 ? (
          <div className="space-y-3">
            {actionItems.map((item, idx) => {
              const isInsecure = item.status === 'insecure'
              return (
                <div
                  key={`${item.targetDomain}-${item.module}-${idx}`}
                  className={`p-3.5 rounded-lg border text-xs space-y-2 transition-colors ${
                    isInsecure
                      ? 'border-red-900/60 bg-red-950/20'
                      : 'border-amber-900/60 bg-amber-950/20'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                          isInsecure
                            ? 'bg-red-500/20 text-red-300 border-red-500/30'
                            : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                        }`}
                      >
                        {item.status}
                      </span>
                      <strong className="text-slate-100 text-sm">{item.module}</strong>
                      <span className="text-slate-400">• Target:</span>
                      <span className="font-mono text-slate-200 font-semibold">{item.targetDomain}</span>
                    </div>

                    <button
                      type="button"
                      onClick={() => onSelectTarget(item.targetDomain)}
                      className="text-xs text-blue-400 hover:text-blue-300 font-medium inline-flex items-center gap-1 self-start sm:self-auto shrink-0 transition-colors"
                      title={`Buka rapor lengkap target ${item.targetDomain}`}
                    >
                      <span>Lihat Rapor Target</span>
                      <ArrowRight size={13} />
                    </button>
                  </div>

                  {item.details && (
                    <p className="text-slate-300 leading-relaxed break-words">{item.details}</p>
                  )}

                  {item.missingHeaders && item.missingHeaders.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                      <span className="text-[11px] text-slate-400 font-medium">Header hilang:</span>
                      {item.missingHeaders.map((h) => (
                        <span
                          key={h}
                          className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-red-950/80 border border-red-800 text-red-300"
                        >
                          {h}
                        </span>
                      ))}
                    </div>
                  )}

                  {item.sisaHari && (
                    <div className="text-[11px] text-amber-300 font-mono">
                      Sisa Masa Berlaku: <strong>{item.sisaHari} hari</strong> (Kedaluwarsa: {item.expiredDate || '-'})
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          <div className="p-6 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 flex items-center gap-3">
            <CheckCircle2 size={24} className="text-emerald-400 shrink-0" />
            <div>
              <p className="font-semibold text-emerald-200 text-sm">
                Kondisi Keamanan Sangat Baik (All Passed)
              </p>
              <p className="text-xs text-emerald-400/80 mt-0.5">
                Tidak ada temuan berstatus rentan (insecure) maupun peringatan (warning) pada target yang diperiksa.
              </p>
            </div>
          </div>
        )}
      </section>

      {/* SECTION 2: Matriks Pemeriksaan 14 Modul */}
      <section className="card p-5 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <ShieldCheck size={18} className="text-blue-400" />
          <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
            2. Matriks Pemeriksaan Modul ({moduleMatrix.length} Modul)
          </h4>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-3 py-2.5">Modul Pemeriksaan</th>
                <th className="px-3 py-2.5 text-center">Target Diuji</th>
                <th className="px-3 py-2.5 text-center">Rentan 🔴</th>
                <th className="px-3 py-2.5 text-center">Peringatan 🟡</th>
                <th className="px-3 py-2.5 text-center">Lolos 🟢</th>
                <th className="px-3 py-2.5 text-center">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {moduleMatrix.map((m) => {
                const hasInsecure = m.insecureCount > 0
                const hasWarning = m.warningCount > 0

                return (
                  <tr key={m.moduleName} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-3 py-2.5 font-medium text-slate-200">{m.moduleName}</td>
                    <td className="px-3 py-2.5 text-center font-mono text-slate-300">{m.targetCount}</td>
                    <td className="px-3 py-2.5 text-center font-mono">
                      {m.insecureCount > 0 ? (
                        <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 font-bold border border-red-800/80">
                          {m.insecureCount}
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-center font-mono">
                      {m.warningCount > 0 ? (
                        <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 font-bold border border-amber-800/80">
                          {m.warningCount}
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-center font-mono">
                      <span className="text-emerald-400">{m.secureCount}</span>
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      {hasInsecure ? (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-950/60 text-red-400 border border-red-800">
                          PERLU PERBAIKAN
                        </span>
                      ) : hasWarning ? (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-950/60 text-amber-400 border border-amber-800">
                          PERINGATAN
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800">
                          AMAN / LOLOS
                        </span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* SECTION 3: Rekapitulasi Target */}
      <section className="card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Globe size={18} className="text-blue-400" />
            <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              3. Rekapitulasi Daftar Target ({targetReports.length})
            </h4>
          </div>
          <span className="text-xs text-slate-400">Klik tombol untuk membuka detail target</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {targetReports.map((report) => {
            const isInsecure = report.overallStatus === 'insecure'
            const isWarning = report.overallStatus === 'warning'

            return (
              <div
                key={report.normalizedDomain}
                className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60 flex items-center justify-between gap-3 hover:border-slate-700 transition-colors"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-slate-100 text-sm truncate">
                      {report.normalizedDomain}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                        isInsecure
                          ? 'bg-red-950/60 text-red-300 border-red-800'
                          : isWarning
                          ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                          : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                      }`}
                    >
                      {report.overallStatus}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
                    {report.geo?.ip && (
                      <span className="inline-flex items-center gap-1 font-mono text-slate-300">
                        <Server size={11} className="text-slate-400" />
                        {report.geo.ip}
                      </span>
                    )}
                    {report.geo?.country && <span>• {report.geo.country}</span>}
                    <span>
                      • {report.counts.insecure} Rentan, {report.counts.warning} Peringatan
                    </span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => onSelectTarget(report.normalizedDomain)}
                  className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1 shrink-0 hover:bg-slate-700/80 transition-colors"
                  title={`Buka rapor target ${report.normalizedDomain}`}
                >
                  <span>Buka Rapor</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
