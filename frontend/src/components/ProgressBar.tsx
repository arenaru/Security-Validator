import { Activity } from 'lucide-react'
import type { Progress, ScanStatus } from '../types'

interface ProgressBarProps {
  progress: Progress
  status: ScanStatus
}

export function ProgressBar({ progress, status }: ProgressBarProps) {
  const statusColors: Record<ScanStatus, string> = {
    pending: 'bg-yellow-500',
    running: 'bg-blue-500',
    done: 'bg-green-500',
    partial: 'bg-orange-500',
    failed: 'bg-red-500',
  }

  const statusLabels: Record<ScanStatus, string> = {
    pending: 'Pending',
    running: 'Running',
    done: 'Completed',
    partial: 'Partial Results',
    failed: 'Failed',
  }

  return (
    <div className="card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {status === 'running' && (
            <Activity className="text-blue-400 animate-spin" size={20} />
          )}
          <h3 className="text-lg font-semibold">Scan Progress</h3>
        </div>
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${statusColors[status]} text-white`}>
          {statusLabels[status]}
        </span>
      </div>

      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ${statusColors[status]}`}
            style={{ width: `${progress.percent}%` }}
          />
        </div>
        <div className="flex justify-between text-sm text-slate-400">
          <span>{progress.completedModules} of {progress.totalModules} modules</span>
          <span className="font-semibold text-slate-100">{Math.round(progress.percent)}%</span>
        </div>
      </div>
    </div>
  )
}
