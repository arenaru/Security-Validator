import { ChevronDown, ChevronUp } from 'lucide-react'
import type { ReactNode } from 'react'
import { useState } from 'react'
import type { ModuleResult } from '../types'

interface ResultsTableProps {
  results: Record<string, ModuleResult[]>
}

function normalizeCell(value: unknown): string {
  if (value === null || value === undefined) return '-'
  const text = String(value).trim()
  if (!text || text.toLowerCase() === 'none (all found)') return '-'
  return text
}

function getRaw(item: ModuleResult, ...keys: string[]): unknown {
  if (!item.raw) return undefined
  for (const key of keys) {
    if (key in item.raw) {
      return item.raw[key]
    }
  }
  return undefined
}

function getUrl(item: ModuleResult): string {
  return normalizeCell(getRaw(item, 'URL', 'url', 'target', 'Target') ?? item.target)
}

function getDetail(item: ModuleResult): string {
  return normalizeCell(getRaw(item, 'Detail', 'details', 'Message', 'message', 'finding') ?? item.details)
}

function getPayload(item: ModuleResult): string {
  return normalizeCell(getRaw(item, 'payload', 'Payload'))
}

function getStatusLabel(item: ModuleResult): string {
  const status = normalizeCell(getRaw(item, 'Status', 'status') ?? item.status.toUpperCase())
  return status.toLowerCase() === 'safe' ? 'secure' : status
}

type ColumnDef = {
  key: string
  header: string
  className?: string
  sortable?: boolean
  sortValue?: (item: ModuleResult, index: number) => string | number
  render: (item: ModuleResult, index: number) => ReactNode
}

type SortDirection = 'asc' | 'desc'

type SortState = {
  key: string
  direction: SortDirection
}

const STATUS_PRIORITY: Record<string, number> = {
  ERROR: 5,
  INSECURE: 4,
  WARNING: 3,
  INFO: 2,
  SECURE: 1,
}

function getScoreNumber(value: string): number {
  const text = normalizeCell(value)
  if (text === '-') return -1
  const parts = text.split('/')
  const first = Number(parts[0])
  return Number.isFinite(first) ? first : -1
}

function compareSortValues(a: string | number, b: string | number, direction: SortDirection): number {
  const normalizedA = typeof a === 'string' ? a.trim() : a
  const normalizedB = typeof b === 'string' ? b.trim() : b

  const emptyA = normalizedA === '' || normalizedA === '-' || normalizedA === null || normalizedA === undefined
  const emptyB = normalizedB === '' || normalizedB === '-' || normalizedB === null || normalizedB === undefined

  if (emptyA && emptyB) return 0
  if (emptyA) return 1
  if (emptyB) return -1

  let result = 0

  if (typeof normalizedA === 'number' && typeof normalizedB === 'number') {
    result = normalizedA - normalizedB
  } else {
    result = String(normalizedA).localeCompare(String(normalizedB), undefined, { sensitivity: 'base' })
  }

  return direction === 'asc' ? result : -result
}

function getColumnsForModule(moduleName: string, statusColors: Record<string, string>): ColumnDef[] {
  const indexCol: ColumnDef = {
    key: 'index',
    header: '',
    className: 'w-14',
    sortable: true,
    sortValue: (_, index) => index,
    render: (_, index) => <span className="text-slate-500">{index}</span>,
  }

  const statusCol: ColumnDef = {
    key: 'status',
    header: 'Status',
    className: 'min-w-[140px]',
    sortable: true,
    sortValue: (item) => STATUS_PRIORITY[getStatusLabel(item).toUpperCase()] ?? 0,
    render: (item) => (
      <span className={`px-2 py-1 rounded text-xs font-semibold whitespace-nowrap ${statusColors[item.status]}`}>
        {getStatusLabel(item)}
      </span>
    ),
  }

  if (moduleName === 'SSL Certificate Check') {
    return [
      indexCol,
      { key: 'target', header: 'Target Domain', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'sisa_hari', header: 'Sisa Hari', className: 'min-w-[140px] text-right', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Sisa Hari'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Sisa Hari'))}</span> },
      { key: 'expired_date', header: 'Expired Date', className: 'min-w-[180px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Expired Date')), render: (item) => <span>{normalizeCell(getRaw(item, 'Expired Date'))}</span> },
      { key: 'detail', header: 'Detail', className: 'min-w-[220px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-200 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'SSL Certificate Hostname Mismatch') {
    return [
      indexCol,
      { key: 'target', header: 'Target Domain', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-200 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'SSLv3 Detection' || moduleName === 'TLS 1.0 Detection' || moduleName === 'TLS 1.1 Detection') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[360px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-200 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'Response Code Check') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      { key: 'status_code', header: 'Status Code', className: 'min-w-[150px]', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Status Code'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Status Code'))}</span> },
      { key: 'reason', header: 'Reason', className: 'min-w-[140px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Reason')), render: (item) => <span>{normalizeCell(getRaw(item, 'Reason'))}</span> },
      { key: 'category', header: 'Category', className: 'min-w-[160px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Category')), render: (item) => <span>{normalizeCell(getRaw(item, 'Category'))}</span> },
      { key: 'message', header: 'Message', className: 'min-w-[220px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Message')), render: (item) => <span className="text-slate-200 break-words">{normalizeCell(getRaw(item, 'Message'))}</span> },
    ]
  }

  if (moduleName === 'HSTS Security Check') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'details', header: 'Details', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-200 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'Security Headers Check') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      { key: 'status_code', header: 'Status Code', className: 'min-w-[150px]', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Status Code'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Status Code'))}</span> },
      { key: 'redirects', header: 'Redirects', className: 'min-w-[120px]', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Redirects'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Redirects'))}</span> },
      { key: 'missing_headers', header: 'Missing Headers', className: 'min-w-[420px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Missing Headers')), render: (item) => <span className="text-red-300 break-words">{normalizeCell(getRaw(item, 'Missing Headers'))}</span> },
      { key: 'score', header: 'Score', className: 'min-w-[100px]', sortable: true, sortValue: (item) => getScoreNumber(normalizeCell(getRaw(item, 'Score'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Score'))}</span> },
    ]
  }

  if (moduleName === 'Cookie Secure Flag' || moduleName === 'Cookie HttpOnly Flag') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[340px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'message', header: 'Message', className: 'min-w-[280px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'message', 'Message') ?? item.details), render: (item) => <span className="text-slate-200 break-words">{normalizeCell(getRaw(item, 'message', 'Message') ?? item.details)}</span> },
    ]
  }

  if (moduleName === 'Laravel Debug Mode' || moduleName === 'Node.js Debug Mode') {
    return [
      indexCol,
      { key: 'target', header: 'Target Domain', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'payload', header: 'Trigger / Payload', className: 'min-w-[220px]', sortable: true, sortValue: (item) => getPayload(item), render: (item) => <span className="text-amber-300 font-mono break-all">{getPayload(item)}</span> },
      {
        key: 'bukti_error',
        header: 'Bukti Error',
        className: 'min-w-[320px]',
        sortable: true,
        sortValue: (item) => normalizeCell(getRaw(item, 'finding', 'Finding', 'Error', 'error') ?? item.details),
        render: (item) => (
          <span className="text-slate-200 break-words">{normalizeCell(getRaw(item, 'finding', 'Finding', 'Error', 'error') ?? item.details)}</span>
        ),
      },
    ]
  }

  if (moduleName === 'PHP Version Disclosure') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[340px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
      statusCol,
      { key: 'detail', header: 'Detail', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-200 break-words">{getDetail(item)}</span> },
    ]
  }

  return [
    indexCol,
    { key: 'target', header: 'Target', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => <span className="text-slate-100 break-all">{getUrl(item)}</span> },
    statusCol,
    { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-200 break-words">{getDetail(item)}</span> },
  ]
}

export function ResultsTable({ results }: ResultsTableProps) {
  const [expandedModule, setExpandedModule] = useState<string | null>(null)
  const [sortByModule, setSortByModule] = useState<Record<string, SortState>>({})

  const statusColors: Record<string, string> = {
    secure: 'text-green-400 bg-green-900/20',
    valid: 'text-green-400 bg-green-900/20',
    warning: 'text-yellow-400 bg-yellow-900/20',
    insecure: 'text-red-400 bg-red-900/20',
    error: 'text-slate-400 bg-slate-800/20',
    info: 'text-blue-400 bg-blue-900/20',
    disclosure: 'text-blue-400 bg-blue-900/20',
  }

  const getModuleSummary = (moduleName: string, items: ModuleResult[]) => {
    return items.reduce(
      (summary, item) => {
        if (moduleName === 'Response Code Check') {
          const statusCode = normalizeCell(getRaw(item, 'Status Code'))
          summary[statusCode] = (summary[statusCode] ?? 0) + 1
          return summary
        }

        const status = getStatusLabel(item).toLowerCase()
        summary[status] = (summary[status] ?? 0) + 1

        return summary
      },
      {} as Record<string, number>
    )
  }

  return (
    <div className="card overflow-hidden">
      {Object.entries(results).map(([moduleName, items]) => {
        const summary = getModuleSummary(moduleName, items)
        const columns = getColumnsForModule(moduleName, statusColors)
        const sortState = sortByModule[moduleName]

        const sortedRows = (() => {
          const rows = items.map((item, originalIndex) => ({ item, originalIndex }))
          if (!sortState) return rows
          const col = columns.find((c) => c.key === sortState.key)
          if (!col || !col.sortable || !col.sortValue) return rows

          // Create a copy so we never mutate source results from API/state.
          return [...rows].sort((a, b) => {
            const aVal = col.sortValue!(a.item, a.originalIndex)
            const bVal = col.sortValue!(b.item, b.originalIndex)
            return compareSortValues(aVal, bVal, sortState.direction)
          })
        })()

        const toggleSort = (col: ColumnDef) => {
          if (!col.sortable) return
          setSortByModule((prev) => {
            const current = prev[moduleName]
            if (!current || current.key !== col.key) {
              return { ...prev, [moduleName]: { key: col.key, direction: 'asc' } }
            }
            const nextDirection: SortDirection = current.direction === 'asc' ? 'desc' : 'asc'
            return { ...prev, [moduleName]: { key: col.key, direction: nextDirection } }
          })
        }

        return (
        <div key={moduleName} className="border-b border-slate-800 last:border-b-0">
          {/* Module Header */}
          <button
            onClick={() => setExpandedModule(expandedModule === moduleName ? null : moduleName)}
            className="w-full flex items-center justify-between p-4 hover:bg-slate-800/50 transition-colors"
          >
            <div className="flex-1 text-left">
              <h3 className="font-semibold text-slate-100">{moduleName}</h3>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-400">
                <span>{items.length} results</span>
                {Object.entries(summary).map(([status, count]) => (
                  <span
                    key={status}
                    className={`rounded-full px-2 py-0.5 text-xs font-semibold ${statusColors[status] ?? 'text-slate-300 bg-slate-800/80'}`}
                  >
                    {count} {status}
                  </span>
                ))}
              </div>
            </div>
            {expandedModule === moduleName ? (
              <ChevronUp size={20} className="text-slate-500" />
            ) : (
              <ChevronDown size={20} className="text-slate-500" />
            )}
          </button>

          {/* Module Results */}
          {expandedModule === moduleName && (
            <div className="bg-slate-800/30 p-4 border-t border-slate-800">
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-sm">
                  <thead className="bg-slate-900/80">
                    <tr className="text-left text-slate-300">
                      {columns.map((col, idx) => (
                        <th key={`${moduleName}-head-${idx}`} className={`px-3 py-3 ${col.className || ''}`}>
                          {col.sortable ? (
                            <button
                              type="button"
                              onClick={() => toggleSort(col)}
                              className="inline-flex items-center gap-1 hover:text-slate-100 transition-colors"
                            >
                              <span>{col.header}</span>
                              {sortState?.key === col.key ? (
                                sortState.direction === 'asc' ? (
                                  <ChevronUp size={14} className="text-slate-400" />
                                ) : (
                                  <ChevronDown size={14} className="text-slate-400" />
                                )
                              ) : (
                                <ChevronDown size={14} className="text-slate-600" />
                              )}
                            </button>
                          ) : (
                            col.header
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sortedRows.map((row, index) => (
                      <tr key={row.originalIndex} className="border-t border-slate-800 align-top">
                        {columns.map((col, colIdx) => (
                          <td key={`${moduleName}-row-${index}-col-${colIdx}`} className={`px-3 py-3 ${col.className || ''}`}>
                            {col.render(row.item, row.originalIndex)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )})}
    </div>
  )
}
