import { useState, useMemo } from 'react'
import {
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Layers,
  Search,
  X,
} from 'lucide-react'
import type { ReactNode } from 'react'
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

function renderTargetLink(urlStr: string) {
  if (urlStr === '-') return <span>-</span>
  const href = urlStr.startsWith('http://') || urlStr.startsWith('https://') ? urlStr : `https://${urlStr}`
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="group inline-flex items-center gap-1 text-slate-100 hover:text-blue-400 font-medium break-all transition-colors"
    >
      <span>{urlStr}</span>
      <ArrowUpRight size={13} className="text-slate-500 group-hover:text-blue-400 shrink-0" />
    </a>
  )
}

function renderMissingHeaders(val: unknown) {
  const text = normalizeCell(val)
  if (text === '-') return <span className="text-slate-500">-</span>
  const headers = text.split(',').map((h) => h.trim()).filter(Boolean)
  return (
    <div className="flex flex-wrap gap-1">
      {headers.map((h) => (
        <span
          key={h}
          className="px-1.5 py-0.5 rounded font-mono text-[11px] bg-red-950/60 border border-red-800/80 text-red-300"
        >
          {h}
        </span>
      ))}
    </div>
  )
}

function getColumnsForModule(moduleName: string, statusColors: Record<string, string>): ColumnDef[] {
  const indexCol: ColumnDef = {
    key: 'index',
    header: '#',
    className: 'w-12 text-slate-500 text-center',
    sortable: true,
    sortValue: (_, index) => index + 1,
    render: (_, index) => <span className="text-slate-500 text-xs font-mono">{index + 1}</span>,
  }

  const statusCol: ColumnDef = {
    key: 'status',
    header: 'Status',
    className: 'min-w-[120px]',
    sortable: true,
    sortValue: (item) => STATUS_PRIORITY[getStatusLabel(item).toUpperCase()] ?? 0,
    render: (item) => {
      const label = getStatusLabel(item)
      const colorCls = statusColors[item.status] || 'text-slate-300 bg-slate-800'
      return (
        <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider whitespace-nowrap border ${colorCls}`}>
          {label}
        </span>
      )
    },
  }

  if (moduleName === 'SSL Certificate Check') {
    return [
      indexCol,
      { key: 'target', header: 'Target Domain', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      {
        key: 'sisa_hari',
        header: 'Sisa Hari',
        className: 'min-w-[120px]',
        sortable: true,
        sortValue: (item) => Number(normalizeCell(getRaw(item, 'Sisa Hari'))),
        render: (item) => {
          const sisa = normalizeCell(getRaw(item, 'Sisa Hari'))
          const num = Number(sisa)
          const isDanger = !isNaN(num) && num <= 14
          return (
            <span className={isDanger ? 'font-mono text-red-400 font-semibold' : 'font-mono text-slate-200'}>
              {sisa !== '-' ? `${sisa} hari` : '-'}
            </span>
          )
        },
      },
      { key: 'expired_date', header: 'Expired Date', className: 'min-w-[160px] font-mono text-xs', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Expired Date')), render: (item) => <span>{normalizeCell(getRaw(item, 'Expired Date'))}</span> },
      { key: 'detail', header: 'Detail', className: 'min-w-[220px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-300 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'SSL Certificate Hostname Mismatch') {
    return [
      indexCol,
      { key: 'target', header: 'Target Domain', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-300 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'SSLv3 Detection' || moduleName === 'TLS 1.0 Detection' || moduleName === 'TLS 1.1 Detection') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-300 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'Response Code Check') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      {
        key: 'status_code',
        header: 'Status Code',
        className: 'min-w-[120px]',
        sortable: true,
        sortValue: (item) => Number(normalizeCell(getRaw(item, 'Status Code'))),
        render: (item) => {
          const code = normalizeCell(getRaw(item, 'Status Code'))
          const isErr = code.startsWith('4') || code.startsWith('5')
          return (
            <span className={`font-mono font-bold px-2 py-0.5 rounded text-xs ${isErr ? 'bg-amber-950/60 text-amber-300 border border-amber-800' : 'bg-emerald-950/40 text-emerald-300 border border-emerald-800'}`}>
              {code}
            </span>
          )
        },
      },
      { key: 'reason', header: 'Reason', className: 'min-w-[120px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Reason')), render: (item) => <span>{normalizeCell(getRaw(item, 'Reason'))}</span> },
      { key: 'category', header: 'Category', className: 'min-w-[140px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Category')), render: (item) => <span>{normalizeCell(getRaw(item, 'Category'))}</span> },
      { key: 'message', header: 'Message', className: 'min-w-[220px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Message')), render: (item) => <span className="text-slate-300 break-words">{normalizeCell(getRaw(item, 'Message'))}</span> },
    ]
  }

  if (moduleName === 'HSTS Security Check') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'details', header: 'Details', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-300 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'Security Headers Check') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      { key: 'status_code', header: 'Status Code', className: 'min-w-[110px] font-mono', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Status Code'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Status Code'))}</span> },
      { key: 'redirects', header: 'Redirects', className: 'min-w-[100px] font-mono', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Redirects'))), render: (item) => <span>{normalizeCell(getRaw(item, 'Redirects'))}</span> },
      { key: 'missing_headers', header: 'Missing Headers', className: 'min-w-[320px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Missing Headers')), render: (item) => renderMissingHeaders(getRaw(item, 'Missing Headers')) },
      {
        key: 'score',
        header: 'Score',
        className: 'min-w-[100px]',
        sortable: true,
        sortValue: (item) => getScoreNumber(normalizeCell(getRaw(item, 'Score'))),
        render: (item) => (
          <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200">
            {normalizeCell(getRaw(item, 'Score'))}
          </span>
        ),
      },
    ]
  }

  if (moduleName === 'Cookie Secure Flag' || moduleName === 'Cookie HttpOnly Flag') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'message', header: 'Message', className: 'min-w-[280px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'message', 'Message') ?? item.details), render: (item) => <span className="text-slate-300 break-words">{normalizeCell(getRaw(item, 'message', 'Message') ?? item.details)}</span> },
    ]
  }

  if (moduleName === 'Laravel Debug Mode' || moduleName === 'Node.js Debug Mode') {
    return [
      indexCol,
      { key: 'target', header: 'Target Domain', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'payload', header: 'Trigger / Payload', className: 'min-w-[220px]', sortable: true, sortValue: (item) => getPayload(item), render: (item) => <span className="text-amber-300 font-mono text-xs break-all">{getPayload(item)}</span> },
      {
        key: 'bukti_error',
        header: 'Bukti Error',
        className: 'min-w-[320px]',
        sortable: true,
        sortValue: (item) => normalizeCell(getRaw(item, 'finding', 'Finding', 'Error', 'error') ?? item.details),
        render: (item) => (
          <span className="text-slate-300 text-xs break-words">{normalizeCell(getRaw(item, 'finding', 'Finding', 'Error', 'error') ?? item.details)}</span>
        ),
      },
    ]
  }

  if (moduleName === 'PHP Version Disclosure') {
    return [
      indexCol,
      { key: 'url', header: 'URL', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'detail', header: 'Detail', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-300 break-words">{getDetail(item)}</span> },
    ]
  }

  if (moduleName === 'IP Country Lookup') {
    return [
      indexCol,
      { key: 'url', header: 'Target', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
      statusCol,
      { key: 'ip', header: 'IP Address', className: 'min-w-[150px] font-mono', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'IP')), render: (item) => <span className="font-mono text-slate-200">{normalizeCell(getRaw(item, 'IP'))}</span> },
      { key: 'country', header: 'Country', className: 'min-w-[180px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Country')), render: (item) => <span className="text-slate-100">{normalizeCell(getRaw(item, 'Country Code')) !== '-' ? `${normalizeCell(getRaw(item, 'Country Code'))} — ` : ''}{normalizeCell(getRaw(item, 'Country'))}</span> },
      { key: 'city', header: 'City', className: 'min-w-[140px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'City')), render: (item) => <span className="text-slate-200">{normalizeCell(getRaw(item, 'City'))}</span> },
      { key: 'isp', header: 'ISP', className: 'min-w-[220px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'ISP')), render: (item) => <span className="text-slate-300 break-words">{normalizeCell(getRaw(item, 'ISP'))}</span> },
      { key: 'as', header: 'AS', className: 'min-w-[220px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'AS')), render: (item) => <span className="text-slate-400 font-mono text-xs break-all">{normalizeCell(getRaw(item, 'AS'))}</span> },
    ]
  }

  return [
    indexCol,
    { key: 'target', header: 'Target', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => renderTargetLink(getUrl(item)) },
    statusCol,
    { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => <span className="text-slate-300 break-words">{getDetail(item)}</span> },
  ]
}

export function ResultsTable({ results }: ResultsTableProps) {
  const [selectedModule, setSelectedModule] = useState<string | null>(null)
  const [moduleSearch, setModuleSearch] = useState('')
  const [sortByModule, setSortByModule] = useState<Record<string, SortState>>({})
  const [selectedRowsByModule, setSelectedRowsByModule] = useState<Record<string, number[]>>({})
  const [selectionAnchorByModule, setSelectionAnchorByModule] = useState<Record<string, number>>({})
  const [copied, setCopied] = useState(false)

  const statusColors: Record<string, string> = {
    secure: 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60',
    valid: 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60',
    warning: 'text-amber-400 bg-amber-950/40 border-amber-800/60',
    insecure: 'text-red-400 bg-red-950/40 border-red-800/60',
    error: 'text-slate-400 bg-slate-800/40 border-slate-700/60',
    info: 'text-sky-400 bg-sky-950/40 border-sky-800/60',
    disclosure: 'text-sky-400 bg-sky-950/40 border-sky-800/60',
  }

  const moduleEntries = Object.entries(results)
  const activeModuleName = moduleEntries.some(([moduleName]) => moduleName === selectedModule)
    ? selectedModule!
    : moduleEntries[0]?.[0]
  const activeItems = moduleEntries.find(([moduleName]) => moduleName === activeModuleName)?.[1] ?? []

  const activeColumns = getColumnsForModule(activeModuleName ?? '', statusColors)
  const activeSortState = sortByModule[activeModuleName ?? '']
  const selectedRows = selectedRowsByModule[activeModuleName ?? ''] ?? []
  const selectedRowSet = new Set(selectedRows)

  const getModuleSummary = (items: ModuleResult[]) => {
    return items.reduce(
      (summary, item) => {
        const status = getStatusLabel(item).toLowerCase()
        summary[status] = (summary[status] ?? 0) + 1
        return summary
      },
      {} as Record<string, number>
    )
  }

  // Filter items by quick search inside module
  const filteredItems = useMemo(() => {
    if (!moduleSearch.trim()) return activeItems
    const q = moduleSearch.toLowerCase()
    return activeItems.filter((item) => {
      const url = getUrl(item).toLowerCase()
      const detail = getDetail(item).toLowerCase()
      return url.includes(q) || detail.includes(q)
    })
  }, [activeItems, moduleSearch])

  const sortedRows = useMemo(() => {
    const rows = filteredItems.map((item, originalIndex) => ({ item, originalIndex }))
    if (!activeSortState) return rows

    const column = activeColumns.find((item) => item.key === activeSortState.key)
    if (!column?.sortable || !column.sortValue) return rows

    return [...rows].sort((first, second) => {
      const firstValue = column.sortValue!(first.item, first.originalIndex)
      const secondValue = column.sortValue!(second.item, second.originalIndex)
      return compareSortValues(firstValue, secondValue, activeSortState.direction)
    })
  }, [filteredItems, activeSortState, activeColumns])

  const allRowsSelected = activeItems.length > 0 && selectedRows.length === activeItems.length

  const toggleSort = (column: ColumnDef) => {
    if (!column.sortable || !activeModuleName) return

    setSortByModule((previous) => {
      const current = previous[activeModuleName]
      if (!current || current.key !== column.key) {
        return { ...previous, [activeModuleName]: { key: column.key, direction: 'asc' } }
      }

      const nextDirection: SortDirection = current.direction === 'asc' ? 'desc' : 'asc'
      return { ...previous, [activeModuleName]: { key: column.key, direction: nextDirection } }
    })
  }

  const toggleRowSelection = (originalIndex: number, sortedIndex: number, selectRange: boolean) => {
    if (!activeModuleName) return

    setSelectedRowsByModule((previous) => {
      const current = previous[activeModuleName] ?? []
      const anchor = selectionAnchorByModule[activeModuleName]

      if (selectRange && anchor !== undefined) {
        const anchorSortedIndex = sortedRows.findIndex((row) => row.originalIndex === anchor)
        const firstIndex = Math.min(anchorSortedIndex, sortedIndex)
        const lastIndex = Math.max(anchorSortedIndex, sortedIndex)
        const range = sortedRows.slice(firstIndex, lastIndex + 1).map((row) => row.originalIndex)
        const next = current.includes(originalIndex)
          ? current.filter((index) => !range.includes(index))
          : [...new Set([...current, ...range])]
        return { ...previous, [activeModuleName]: next }
      }

      const next = current.includes(originalIndex)
        ? current.filter((index) => index !== originalIndex)
        : [...current, originalIndex]
      return { ...previous, [activeModuleName]: next }
    })
    setSelectionAnchorByModule((previous) => ({ ...previous, [activeModuleName]: originalIndex }))
    setCopied(false)
  }

  const toggleAllRows = () => {
    if (!activeModuleName) return

    setSelectedRowsByModule((previous) => ({
      ...previous,
      [activeModuleName]: allRowsSelected ? [] : activeItems.map((_, index) => index),
    }))
    setSelectionAnchorByModule((previous) => ({ ...previous, [activeModuleName]: 0 }))
    setCopied(false)
  }

  const copySelectedUrls = async () => {
    const urls = selectedRows
      .map((index) => getUrl(activeItems[index]))
      .filter((url) => url !== '-')

    if (!urls.length) return

    await navigator.clipboard.writeText(urls.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (moduleEntries.length === 0) {
    return (
      <div className="card p-8 text-center text-slate-400">
        Belum ada data modul yang selesai dipindai.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Top Module Selector Bar (Replaced the awkward secondary sidebar) */}
      <div className="card p-3">
        <div className="flex items-center gap-2 mb-2 text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
          <Layers size={14} className="text-blue-400" />
          <span>Pilih Modul Pemeriksaan ({moduleEntries.length})</span>
        </div>

        {/* Scrollable Pills on Desktop, Select dropdown on Mobile */}
        <div className="sm:hidden mb-2">
          <select
            value={activeModuleName}
            onChange={(e) => {
              setSelectedModule(e.target.value)
              setModuleSearch('')
            }}
            className="input-field text-xs py-2 w-full"
          >
            {moduleEntries.map(([name, items]) => (
              <option key={name} value={name}>
                {name} ({items.length} data)
              </option>
            ))}
          </select>
        </div>

        <div className="hidden sm:flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
          {moduleEntries.map(([name, items]) => {
            const summary = getModuleSummary(items)
            const isActive = name === activeModuleName
            const hasInsecure = (summary.insecure ?? 0) > 0
            const hasWarning = (summary.warning ?? 0) > 0

            return (
              <button
                key={name}
                type="button"
                onClick={() => {
                  setSelectedModule(name)
                  setModuleSearch('')
                }}
                className={`shrink-0 px-3 py-2 rounded-lg text-xs font-medium transition-all inline-flex items-center gap-2 border ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-200 border-blue-500/80 shadow-sm'
                    : 'bg-slate-800/60 text-slate-300 border-slate-700/60 hover:bg-slate-800 hover:text-slate-100'
                }`}
              >
                <span>{name}</span>
                <span className="font-mono text-[11px] px-1.5 py-0.2 rounded bg-slate-900/60 text-slate-400">
                  {items.length}
                </span>

                {/* Micro indicators */}
                {hasInsecure && (
                  <span className="h-2 w-2 rounded-full bg-red-500" title="Ada temuan Insecure" />
                )}
                {!hasInsecure && hasWarning && (
                  <span className="h-2 w-2 rounded-full bg-amber-500" title="Ada temuan Warning" />
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* Active Module Table Section (Full Width) */}
      {activeModuleName && (
        <section className="card overflow-hidden">
          {/* Header Bar */}
          <div className="border-b border-slate-800 px-5 py-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="font-bold text-base text-slate-100 flex items-center gap-2">
                  <span>{activeModuleName}</span>
                  <span className="text-xs font-normal text-slate-400">({activeItems.length} hasil)</span>
                </h3>
              </div>

              {/* Search & Actions */}
              <div className="flex items-center gap-3 flex-wrap">
                <div className="relative">
                  <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={moduleSearch}
                    onChange={(e) => setModuleSearch(e.target.value)}
                    placeholder="Filter tabel ini..."
                    className="input-field pl-8 pr-7 py-1.5 text-xs w-48"
                  />
                  {moduleSearch && (
                    <button
                      type="button"
                      onClick={() => setModuleSearch('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                    >
                      <X size={12} />
                    </button>
                  )}
                </div>

                <button
                  type="button"
                  onClick={copySelectedUrls}
                  disabled={selectedRows.length === 0}
                  className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1.5 disabled:cursor-not-allowed disabled:opacity-40"
                  title="Salin URL yang dicentang"
                >
                  {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                  <span>{copied ? 'Tersalin' : `Salin Target (${selectedRows.length})`}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Table Container */}
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-900/90 border-b border-slate-800 text-slate-300 font-semibold uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="w-10 px-3 py-3 text-center">
                    <input
                      type="checkbox"
                      checked={allRowsSelected}
                      onChange={toggleAllRows}
                      aria-label="Pilih semua baris"
                      className="h-3.5 w-3.5 cursor-pointer accent-blue-600 rounded"
                    />
                  </th>
                  {activeColumns.map((column, index) => (
                    <th key={`${activeModuleName}-head-${index}`} className={`px-3 py-3 ${column.className || ''}`}>
                      {column.sortable ? (
                        <button
                          type="button"
                          onClick={() => toggleSort(column)}
                          className="inline-flex items-center gap-1 hover:text-slate-100 transition-colors"
                        >
                          <span>{column.header}</span>
                          {activeSortState?.key === column.key ? (
                            activeSortState.direction === 'asc' ? (
                              <ChevronUp size={12} className="text-blue-400" />
                            ) : (
                              <ChevronDown size={12} className="text-blue-400" />
                            )
                          ) : (
                            <ChevronDown size={12} className="text-slate-600" />
                          )}
                        </button>
                      ) : (
                        column.header
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {sortedRows.length > 0 ? (
                  sortedRows.map((row, index) => {
                    const isSelected = selectedRowSet.has(row.originalIndex)
                    return (
                      <tr
                        key={row.originalIndex}
                        className={`transition-colors align-top ${
                          isSelected ? 'bg-blue-950/20' : 'hover:bg-slate-800/30'
                        }`}
                      >
                        <td className="px-3 py-3 text-center">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={(event) =>
                              toggleRowSelection(
                                row.originalIndex,
                                index,
                                event.nativeEvent instanceof MouseEvent && event.nativeEvent.shiftKey
                              )
                            }
                            aria-label={`Select ${getUrl(row.item)}`}
                            className="h-3.5 w-3.5 cursor-pointer accent-blue-600 rounded"
                          />
                        </td>
                        {activeColumns.map((column, columnIndex) => (
                          <td
                            key={`${activeModuleName}-row-${index}-col-${columnIndex}`}
                            className={`px-3 py-3 ${column.className || ''}`}
                          >
                            {column.render(row.item, row.originalIndex)}
                          </td>
                        ))}
                      </tr>
                    )
                  })
                ) : (
                  <tr>
                    <td colSpan={activeColumns.length + 1} className="p-8 text-center text-slate-400">
                      {moduleSearch
                        ? 'Tidak ada baris yang cocok dengan kata kunci pencarian.'
                        : 'Tidak ada data untuk modul ini.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
