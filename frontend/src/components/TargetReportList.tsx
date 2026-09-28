import { useMemo, useState, useEffect } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Filter,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react'
import type { TargetReport } from '../types'
import { TargetCard } from './TargetCard'

interface TargetReportListProps {
  reports: TargetReport[]
  initialSearch?: string
}

type StatusFilter = 'all' | 'insecure' | 'warning' | 'secure'

export function TargetReportList({ reports, initialSearch = '' }: TargetReportListProps) {
  const [search, setSearch] = useState(initialSearch)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')

  useEffect(() => {
    if (initialSearch) {
      setSearch(initialSearch)
    }
  }, [initialSearch])

  const counts = useMemo(() => {
    let insecure = 0
    let warning = 0
    let secure = 0

    for (const r of reports) {
      if (r.overallStatus === 'insecure') insecure++
      else if (r.overallStatus === 'warning') warning++
      else secure++
    }

    return { all: reports.length, insecure, warning, secure }
  }, [reports])

  const filteredReports = useMemo(() => {
    const q = search.trim().toLowerCase()

    return reports.filter((item) => {
      // Filter status
      if (statusFilter !== 'all' && item.overallStatus !== statusFilter) {
        return false
      }

      // Filter search query
      if (!q) return true

      if (item.normalizedDomain.toLowerCase().includes(q)) return true
      if (item.target.toLowerCase().includes(q)) return true
      if (item.geo?.ip?.toLowerCase().includes(q)) return true
      if (item.geo?.country?.toLowerCase().includes(q)) return true

      // Search inside issues
      for (const issue of item.issues) {
        if (issue.module.toLowerCase().includes(q)) return true
        if (issue.details?.toLowerCase().includes(q)) return true
        if (issue.missingHeaders?.some(h => h.toLowerCase().includes(q))) return true
      }

      return false
    })
  }, [reports, search, statusFilter])

  return (
    <div className="space-y-6">
      {/* Control Bar: Search & Status Filters */}
      <div className="card p-4 space-y-3 sm:space-y-0 sm:flex sm:items-center sm:justify-between sm:gap-4">
        {/* Search Input */}
        <div className="relative flex-1 max-w-md">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Cari domain, IP, atau nama modul..."
            className="input-field pl-9 pr-8 py-2 text-xs w-full"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
            >
              <X size={14} />
            </button>
          )}
        </div>

        {/* Status Filter Buttons */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400 mr-1 hidden sm:inline-flex items-center gap-1">
            <Filter size={12} />
            Filter:
          </span>

          <button
            type="button"
            onClick={() => setStatusFilter('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              statusFilter === 'all'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-700/80'
            }`}
          >
            Semua ({counts.all})
          </button>

          {counts.insecure > 0 && (
            <button
              type="button"
              onClick={() => setStatusFilter('insecure')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 transition-colors ${
                statusFilter === 'insecure'
                  ? 'bg-red-600 text-white shadow-sm'
                  : 'bg-red-950/40 text-red-400 border border-red-900/50 hover:bg-red-900/40'
              }`}
            >
              <ShieldAlert size={14} />
              Rentan ({counts.insecure})
            </button>
          )}

          {counts.warning > 0 && (
            <button
              type="button"
              onClick={() => setStatusFilter('warning')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 transition-colors ${
                statusFilter === 'warning'
                  ? 'bg-amber-600 text-white shadow-sm'
                  : 'bg-amber-950/40 text-amber-400 border border-amber-900/50 hover:bg-amber-900/40'
              }`}
            >
              <AlertTriangle size={14} />
              Peringatan ({counts.warning})
            </button>
          )}

          <button
            type="button"
            onClick={() => setStatusFilter('secure')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 transition-colors ${
              statusFilter === 'secure'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'bg-emerald-950/30 text-emerald-400 border border-emerald-900/50 hover:bg-emerald-900/30'
            }`}
          >
            <CheckCircle2 size={14} />
            Lolos ({counts.secure})
          </button>
        </div>
      </div>

      {/* Target Cards List */}
      {filteredReports.length > 0 ? (
        <div className="space-y-4">
          {filteredReports.map((report) => (
            <TargetCard key={report.normalizedDomain} report={report} />
          ))}
        </div>
      ) : (
        <div className="card p-12 text-center space-y-3">
          <p className="text-slate-400 text-sm">
            Tidak ada target yang sesuai dengan kata kunci pencarian atau filter yang dipilih.
          </p>
          {(search || statusFilter !== 'all') && (
            <button
              type="button"
              onClick={() => {
                setSearch('')
                setStatusFilter('all')
              }}
              className="btn-secondary px-4 py-2 text-xs"
            >
              Reset Filter Pencarian
            </button>
          )}
        </div>
      )}
    </div>
  )
}
