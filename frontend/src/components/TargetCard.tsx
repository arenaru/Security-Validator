import { useState } from 'react'
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Globe,
  Info,
  Server,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react'
import type { TargetFinding, TargetReport } from '../types'
import { formatTargetReportText } from '../utils/reportTransformer'

interface TargetCardProps {
  report: TargetReport
}

export function TargetCard({ report }: TargetCardProps) {
  const [copied, setCopied] = useState(false)
  const [passedOpen, setPassedOpen] = useState(false)
  const [reconOpen, setReconOpen] = useState(false)
  const [expandedDetails, setExpandedDetails] = useState<Record<string, boolean>>({})

  const handleCopy = async () => {
    const text = formatTargetReportText(report)
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const toggleDetail = (key: string) => {
    setExpandedDetails(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const targetUrl = report.target.startsWith('http://') || report.target.startsWith('https://')
    ? report.target
    : `https://${report.target}`

  const statusConfig = {
    insecure: {
      border: 'border-red-800/60 hover:border-red-700/80',
      badgeBg: 'bg-red-500/10 text-red-400 border-red-500/30',
      icon: <ShieldAlert className="text-red-400" size={20} />,
      label: 'BERISIKO / INSECURE',
      accent: 'from-red-950/20 to-transparent',
    },
    warning: {
      border: 'border-amber-800/60 hover:border-amber-700/80',
      badgeBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      icon: <AlertTriangle className="text-amber-400" size={20} />,
      label: 'PERLU PERHATIAN',
      accent: 'from-amber-950/20 to-transparent',
    },
    error: {
      border: 'border-slate-700/70 hover:border-slate-600',
      badgeBg: 'bg-slate-700/20 text-slate-300 border-slate-600',
      icon: <XCircle className="text-slate-400" size={20} />,
      label: 'ERROR / UNREACHABLE',
      accent: 'from-slate-900 to-transparent',
    },
    secure: {
      border: 'border-emerald-800/60 hover:border-emerald-700/80',
      badgeBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      icon: <ShieldCheck className="text-emerald-400" size={20} />,
      label: 'AMAN & LOLOS',
      accent: 'from-emerald-950/20 to-transparent',
    },
  }[report.overallStatus]

  return (
    <article
      className={`card relative overflow-hidden transition-all duration-200 border bg-gradient-to-b ${statusConfig.accent} ${statusConfig.border}`}
    >
      {/* Top Target Header */}
      <div className="p-5 border-b border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <a
                href={targetUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-center gap-1.5 text-lg font-bold text-slate-100 hover:text-blue-400 transition-colors break-all"
                title={`Buka ${targetUrl} di tab baru`}
              >
                <span>{report.normalizedDomain}</span>
                <ArrowUpRight size={16} className="text-slate-500 group-hover:text-blue-400 transition-colors" />
              </a>

              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${statusConfig.badgeBg}`}
              >
                {statusConfig.icon}
                {statusConfig.label}
              </span>
            </div>

            {/* Server / Geo Info */}
            <div className="flex items-center gap-3 text-xs text-slate-400 flex-wrap">
              {report.geo?.ip && (
                <span className="flex items-center gap-1 font-mono text-slate-300 bg-slate-800/70 px-2 py-0.5 rounded">
                  <Server size={12} className="text-slate-400" />
                  {report.geo.ip}
                </span>
              )}
              {report.geo?.country && (
                <span className="flex items-center gap-1">
                  <Globe size={12} className="text-slate-400" />
                  {report.geo.countryCode ? `${report.geo.countryCode} • ` : ''}
                  {report.geo.city ? `${report.geo.city}, ` : ''}
                  {report.geo.country}
                </span>
              )}
              {report.geo?.isp && (
                <span className="text-slate-400 truncate max-w-xs" title={report.geo.isp}>
                  • {report.geo.isp}
                </span>
              )}
            </div>
          </div>

          {/* Quick Actions & Metric Pills */}
          <div className="flex items-center gap-2 shrink-0">
            <div className="hidden sm:flex items-center gap-1.5 text-xs font-medium">
              {report.counts.insecure > 0 && (
                <span className="px-2 py-1 rounded bg-red-950/60 text-red-400 border border-red-800/60">
                  {report.counts.insecure} Rentan
                </span>
              )}
              {report.counts.warning > 0 && (
                <span className="px-2 py-1 rounded bg-amber-950/60 text-amber-400 border border-amber-800/60">
                  {report.counts.warning} Peringatan
                </span>
              )}
              <span className="px-2 py-1 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/50">
                {report.counts.secure} Lolos
              </span>
            </div>

            <button
              type="button"
              onClick={handleCopy}
              className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1.5 hover:bg-slate-700/80 transition-colors"
              title="Salin rapor teks lengkap domain ini"
            >
              {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
              <span>{copied ? 'Tersalin!' : 'Salin Rapor'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Findings Body */}
      <div className="p-5 space-y-4">
        {/* Issues List (Priority) */}
        {report.issues.length > 0 ? (
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <ShieldAlert size={14} className="text-red-400" />
              Temuan yang Perlu Diperbaiki ({report.issues.length})
            </h4>

            <div className="space-y-2.5">
              {report.issues.map((issue, idx) => (
                <FindingRow
                  key={`${issue.module}-${idx}`}
                  finding={issue}
                  expanded={!!expandedDetails[`issue-${idx}`]}
                  onToggleExpand={() => toggleDetail(`issue-${idx}`)}
                />
              ))}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-3 p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-sm">
            <CheckCircle2 size={18} className="text-emerald-400 shrink-0" />
            <div>
              <p className="font-semibold text-emerald-200">Semua Uji Keamanan Lolos</p>
              <p className="text-xs text-emerald-400/80">
                Tidak ditemukan celah keamanan kritis atau peringatan pada seluruh modul yang diaktifkan untuk domain ini.
              </p>
            </div>
          </div>
        )}

        {/* Recon Data (facts, not findings) */}
        {report.recon.length > 0 && (
          <div className="pt-2 border-t border-slate-800/60">
            <button
              type="button"
              onClick={() => setReconOpen(!reconOpen)}
              className="w-full flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 py-1.5 transition-colors font-medium"
            >
              <span className="flex items-center gap-2">
                <Info size={14} className="text-sky-400" />
                Data rekonesans ({report.recon.length}) — informasi, bukan temuan
              </span>
              {reconOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>

            {reconOpen && (
              <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                {report.recon.map((r, idx) => (
                  <div
                    key={`${r.module}-${idx}`}
                    className="flex items-start gap-2 p-2.5 rounded bg-slate-900/60 border border-slate-800/80"
                  >
                    <Info size={14} className="text-sky-400 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <span className="font-semibold text-slate-200 block truncate">{r.module}</span>
                      {r.details && (
                        <span className="text-slate-400 text-[11px] block break-words mt-0.5">
                          {r.details}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Passed Checks Accordion */}
        {report.passed.length > 0 && (
          <div className="pt-2 border-t border-slate-800/60">
            <button
              type="button"
              onClick={() => setPassedOpen(!passedOpen)}
              className="w-full flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 py-1.5 transition-colors font-medium"
            >
              <span className="flex items-center gap-2">
                <CheckCircle2 size={14} className="text-emerald-500" />
                Lihat {report.passed.length} pemeriksaan yang lolos uji
              </span>
              {passedOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>

            {passedOpen && (
              <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                {report.passed.map((p, idx) => (
                  <div
                    key={`${p.module}-${idx}`}
                    className="flex items-start gap-2 p-2.5 rounded bg-slate-900/60 border border-slate-800/80"
                  >
                    <CheckCircle2 size={14} className="text-emerald-400 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <span className="font-semibold text-slate-200 block truncate">{p.module}</span>
                      {p.details && (
                        <span className="text-slate-400 text-[11px] block break-words mt-0.5">
                          {p.details}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </article>
  )
}

interface FindingRowProps {
  finding: TargetFinding
  expanded: boolean
  onToggleExpand: () => void
}

function FindingRow({ finding, expanded, onToggleExpand }: FindingRowProps) {
  const isInsecure = finding.status.toLowerCase() === 'insecure'
  const isWarning = finding.status.toLowerCase() === 'warning'

  const borderClass = isInsecure
    ? 'border-red-800/50 bg-red-950/20'
    : isWarning
    ? 'border-amber-800/50 bg-amber-950/20'
    : 'border-slate-800 bg-slate-900/50'

  const badgeClass = isInsecure
    ? 'bg-red-500/20 text-red-300 border-red-500/30'
    : isWarning
    ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
    : 'bg-slate-700/30 text-slate-300 border-slate-600'

  return (
    <div className={`p-3.5 rounded-lg border ${borderClass} transition-colors text-xs space-y-2`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider border ${badgeClass}`}>
            {finding.status}
          </span>
          <span className="font-semibold text-slate-200 text-sm">{finding.module}</span>
        </div>

        {/* Sisa Hari badge for SSL if present */}
        {finding.sisaHari && (
          <span className="font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-300 font-semibold text-[11px]">
            Sisa {finding.sisaHari} Hari
          </span>
        )}
      </div>

      {/* Main Details Description */}
      {finding.details && (
        <p className="text-slate-300 leading-relaxed break-words">{finding.details}</p>
      )}

      {/* Missing Security Headers formatted as tags */}
      {finding.missingHeaders && finding.missingHeaders.length > 0 && (
        <div className="space-y-1.5 pt-1">
          <span className="text-[11px] text-slate-400 font-medium">Header yang hilang:</span>
          <div className="flex flex-wrap gap-1.5">
            {finding.missingHeaders.map((header) => (
              <span
                key={header}
                className="px-2 py-0.5 rounded font-mono text-[11px] bg-red-950/60 border border-red-800/80 text-red-300"
              >
                {header}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Trigger / Payload if available */}
      {finding.payload && (
        <div className="pt-1">
          <span className="text-[11px] text-slate-400 font-medium">Trigger / Payload:</span>
          <div className="mt-1 p-2 rounded bg-slate-950 border border-slate-800 font-mono text-amber-300 text-[11px] break-all">
            {finding.payload}
          </div>
        </div>
      )}

      {/* Long Evidence / Bukti Error Collapsible */}
      {finding.evidence && (
        <div className="pt-1">
          <button
            type="button"
            onClick={onToggleExpand}
            className="text-[11px] text-blue-400 hover:text-blue-300 font-medium inline-flex items-center gap-1"
          >
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            <span>{expanded ? 'Sembunyikan Bukti Temuan' : 'Lihat Bukti Temuan (Evidence)'}</span>
          </button>

          {expanded && (
            <pre className="mt-2 p-3 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono text-[11px] overflow-x-auto max-h-48 whitespace-pre-wrap break-all">
              {finding.evidence}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}
