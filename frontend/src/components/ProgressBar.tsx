import { Activity } from 'lucide-react'
import type { Progress, ScanStatus } from '../types'

interface ProgressBarProps {
  progress: Progress
  status: ScanStatus
}

export function ProgressBar({ progress, status }: ProgressBarProps) {
  const statusStyles: Record<ScanStatus, string> = {
    pending: 'bg-yellow-400',
    running: 'bg-blue-400',
    done: 'bg-emerald-400',
    partial: 'bg-orange-400',
    failed: 'bg-red-400',
  }

  const statusLabels: Record<ScanStatus, string> = {
    pending: 'Pending',
    running: 'Running',
    done: 'Completed',
    partial: 'Partial Results',
    failed: 'Failed',
  }

  return (
    <section className="border border-slate-800 bg-slate-900/60 px-4 py-3" aria-label="Scan progress">
      <div className="mb-2 flex items-center justify-between gap-4 text-sm">
        <div className="flex min-w-0 items-center gap-2 text-slate-400">
          {status === 'running' && <Activity className="shrink-0 animate-spin text-blue-400" size={16} />}
          <span className="truncate">{statusLabels[status]}: {progress.completedModules}/{progress.totalModules} modules</span>
        </div>
        <span className="shrink-0 font-semibold text-slate-100">{Math.round(progress.percent)}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full transition-all duration-500 ${statusStyles[status]}`}
          style={{ width: `${progress.percent}%` }}
        />
      </div>
    </section>
  )
}
