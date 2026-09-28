import { Activity, AlertTriangle, CheckCircle2, Clock, RotateCcw, XCircle } from 'lucide-react'
import type { Progress, ScanStatus } from '../types'

interface ProgressBarProps {
  progress: Progress
  status: ScanStatus
  scanId?: string
  elapsedSeconds?: number
  onReset?: () => void
}

export function ProgressBar({
  progress,
  status,
  scanId,
  elapsedSeconds = 0,
  onReset,
}: ProgressBarProps) {
  const statusStyles: Record<ScanStatus, string> = {
    pending: 'bg-yellow-400',
    running: 'bg-blue-500 shadow-sm shadow-blue-500/50',
    done: 'bg-emerald-400',
    partial: 'bg-amber-400',
    failed: 'bg-red-400',
  }

  const statusConfig = {
    pending: {
      label: 'Menunggu Antrean',
      icon: <Clock size={15} className="text-yellow-400" />,
      badge: 'bg-yellow-950/40 text-yellow-300 border-yellow-800/60',
    },
    running: {
      label: 'Sedang Memindai Target...',
      icon: <Activity size={15} className="animate-spin text-blue-400" />,
      badge: 'bg-blue-950/40 text-blue-300 border-blue-800/60',
    },
    done: {
      label: 'Pemeriksaan Selesai',
      icon: <CheckCircle2 size={15} className="text-emerald-400" />,
      badge: 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60',
    },
    partial: {
      label: 'Selesai Sebagian (Ada Modul Gagal)',
      icon: <AlertTriangle size={15} className="text-amber-400" />,
      badge: 'bg-amber-950/40 text-amber-300 border-amber-800/60',
    },
    failed: {
      label: 'Pemeriksaan Gagal',
      icon: <XCircle size={15} className="text-red-400" />,
      badge: 'bg-red-950/40 text-red-300 border-red-800/60',
    },
  }[status]

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
  }

  return (
    <section
      className="card p-4 border border-slate-800 bg-slate-900/80 shadow-md"
      aria-label="Scan progress"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2.5">
        <div className="flex items-center gap-2.5 flex-wrap">
          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${statusConfig.badge}`}
          >
            {statusConfig.icon}
            <span>{statusConfig.label}</span>
          </span>

          <span className="text-xs text-slate-400">
            {progress.completedModules} dari {progress.totalModules} modul selesai
          </span>

          {scanId && (
            <span className="text-[11px] font-mono text-slate-500 bg-slate-800/70 px-2 py-0.5 rounded">
              #{scanId.slice(0, 8)}
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 text-xs shrink-0">
          <span className="font-mono text-slate-300 bg-slate-800/60 px-2 py-0.5 rounded inline-flex items-center gap-1">
            <Clock size={12} className="text-slate-400" />
            {formatTime(elapsedSeconds)}
          </span>

          <span className="font-bold text-slate-100 font-mono text-sm">
            {Math.round(progress.percent)}%
          </span>

          {onReset && (status === 'done' || status === 'partial' || status === 'failed') && (
            <button
              type="button"
              onClick={onReset}
              className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1 hover:underline"
              title="Reset dan lakukan pengujian baru"
            >
              <RotateCcw size={12} />
              Scan Baru
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar Track */}
      <div className="h-2.5 overflow-hidden rounded-full bg-slate-800/90 p-0.5 border border-slate-700/50">
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${statusStyles[status]}`}
          style={{ width: `${Math.min(100, Math.max(0, progress.percent))}%` }}
        />
      </div>
    </section>
  )
}
