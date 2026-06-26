import { Download, Loader } from 'lucide-react'
import type { ScanStatus } from '../types'

interface ReportDownloadProps {
  scanId: string
  status: ScanStatus
  onDownload: (scanId: string) => Promise<void>
  isLoading: boolean
}

export function ReportDownload({ scanId, status, onDownload, isLoading }: ReportDownloadProps) {
  const canDownload = status === 'done' || status === 'partial'

  const handleClick = async () => {
    try {
      await onDownload(scanId)
    } catch (error) {
      alert('Failed to download report')
    }
  }

  return (
    <div className="card p-6 flex items-center justify-between">
      <div>
        <h3 className="font-semibold text-slate-100">Download Report</h3>
        <p className="text-sm text-slate-400 mt-1">
          {canDownload
            ? 'Export your scan results as XLSX'
            : 'Report will be available when scan completes'}
        </p>
      </div>
      <button
        onClick={handleClick}
        disabled={!canDownload || isLoading}
        className="btn-primary flex items-center gap-2"
      >
        {isLoading ? (
          <>
            <Loader size={18} className="animate-spin" />
            Downloading...
          </>
        ) : (
          <>
            <Download size={18} />
            Download XLSX
          </>
        )}
      </button>
    </div>
  )
}
