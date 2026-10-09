import { useState, useId } from 'react'
import {
  Check,
  ChevronDown,
  ChevronUp,
  Cookie,
  Globe,
  Loader2,
  Play,
  RotateCcw,
  Server,
  Shield,
  Sparkles,
  Trash2,
} from 'lucide-react'
import {
  MODULE_CATEGORIES,
  MODULE_NAMES,
  SCAN_PRESETS,
  type ScanPreset,
} from '../types'

interface ScanFormProps {
  onSubmit: (targets: string[], modules: string[]) => void
  isLoading: boolean
  isScanning?: boolean
  hasResults?: boolean
  onResetScan?: () => void
}

export function ScanForm({
  onSubmit,
  isLoading,
  isScanning = false,
  hasResults = false,
  onResetScan,
}: ScanFormProps) {
  const [targetsInput, setTargetsInput] = useState('')
  // Default to Full Audit (all modules selected)
  const [selectedModules, setSelectedModules] = useState<string[]>([...MODULE_NAMES])
  const [collapsed, setCollapsed] = useState(false)
  const [activePreset, setActivePreset] = useState<string>('full')

  const formId = useId()

  const validTargets = targetsInput
    .split(/\r?\n/)
    .map(t => t.trim())
    .filter(Boolean)

  const detectActivePreset = (modules: string[]): string => {
    if (modules.length === MODULE_NAMES.length) return 'full'
    const matchedCategory = MODULE_CATEGORIES.find(
      cat => modules.length === cat.modules.length && cat.modules.every(m => modules.includes(m))
    )
    return matchedCategory ? matchedCategory.id : 'custom'
  }

  const handleApplyPreset = (preset: ScanPreset) => {
    setActivePreset(preset.id)
    setSelectedModules([...preset.modules])
  }

  const handleModuleToggle = (module: string) => {
    setSelectedModules(prev => {
      const next = prev.includes(module) ? prev.filter(m => m !== module) : [...prev, module]
      setActivePreset(detectActivePreset(next))
      return next
    })
  }

  const handleCategoryToggle = (categoryModules: readonly string[]) => {
    const allSelected = categoryModules.every(m => selectedModules.includes(m))
    let next: string[]
    if (allSelected) {
      next = selectedModules.filter(m => !categoryModules.includes(m))
    } else {
      next = Array.from(new Set([...selectedModules, ...categoryModules]))
    }
    setActivePreset(detectActivePreset(next))
    setSelectedModules(next)
  }

  const handleLoadSample = () => {
    setTargetsInput('example.com\ncloudflare.com')
  }

  const handleClearTargets = () => {
    setTargetsInput('')
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!validTargets.length) {
      alert('Silakan masukkan minimal 1 target domain atau URL')
      return
    }

    if (!selectedModules.length) {
      alert('Silakan pilih minimal 1 modul pemeriksaan keamanan')
      return
    }

    // Auto collapse form when scan starts
    setCollapsed(true)
    onSubmit(validTargets, selectedModules)
  }

  // Collapsed Banner View (when results exist or scanning)
  if (collapsed && (hasResults || isScanning)) {
    return (
      <div className="card p-4 border-slate-800 bg-slate-900/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield size={18} />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-bold text-slate-100">
                {validTargets.length} Target Dipindai
              </span>
              <span className="text-xs text-slate-400">
                ({selectedModules.length} dari {MODULE_NAMES.length} modul aktif)
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono truncate max-w-md">
              {validTargets.slice(0, 3).join(', ')}
              {validTargets.length > 3 ? ` +${validTargets.length - 3} lainnya` : ''}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCollapsed(false)}
            className="btn-secondary px-3 py-1.5 text-xs inline-flex items-center gap-1.5"
          >
            <span>Ubah Target / Modul</span>
            <ChevronDown size={14} />
          </button>

          {onResetScan && (
            <button
              type="button"
              onClick={onResetScan}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors inline-flex items-center gap-1"
              title="Reset dan mulai pengujian baru"
            >
              <RotateCcw size={13} />
              <span>Scan Baru</span>
            </button>
          )}
        </div>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="card p-5 space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Shield size={18} className="text-blue-500" />
            <span>Konfigurasi Pemeriksaan Keamanan</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Tentukan target domain dan pilih modul kerentanan yang ingin diuji.
          </p>
        </div>

        {(hasResults || isScanning) && (
          <button
            type="button"
            onClick={() => setCollapsed(true)}
            className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1"
          >
            <span>Tutup Panel</span>
            <ChevronUp size={14} />
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Targets Input (5 cols) */}
        <div className="lg:col-span-5 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <label htmlFor={formId} className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Target Pengujian (Domain / URL)
            </label>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleLoadSample}
                className="text-[11px] text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 transition-colors"
                title="Isi otomatis dengan contoh domain demo"
              >
                <Sparkles size={12} />
                Contoh Demo
              </button>
              {targetsInput && (
                <button
                  type="button"
                  onClick={handleClearTargets}
                  className="text-[11px] text-slate-400 hover:text-red-400 inline-flex items-center gap-1 transition-colors"
                  title="Kosongkan teks target"
                >
                  <Trash2 size={12} />
                  Bersihkan
                </button>
              )}
            </div>
          </div>

          <textarea
            id={formId}
            value={targetsInput}
            onChange={(e) => setTargetsInput(e.target.value)}
            placeholder={`example.com\nhttps://api.domain.id\nsubdomain.target.org`}
            rows={8}
            className="input-field flex-1 font-mono text-xs resize-y min-h-[160px] leading-relaxed"
          />

          <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
            <span>Satu domain atau URL per baris</span>
            <span
              className={`font-semibold ${
                validTargets.length > 0 ? 'text-blue-400' : 'text-slate-500'
              }`}
            >
              {validTargets.length} target terdeteksi
            </span>
          </div>
        </div>

        {/* Right Column: Presets & Module Categories (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* 1-Click Presets */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Preset Cepat (1-Klik)
              </span>
              <span className="text-[11px] text-slate-400">
                {selectedModules.length} dari {MODULE_NAMES.length} modul aktif
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {SCAN_PRESETS.map((preset) => {
                const isSelected = activePreset === preset.id
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => handleApplyPreset(preset)}
                    className={`p-2.5 rounded-lg text-left transition-all border ${
                      isSelected
                        ? 'bg-blue-600/20 text-blue-200 border-blue-500/80 shadow-sm'
                        : 'bg-slate-800/60 text-slate-300 border-slate-700/60 hover:bg-slate-800 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold block">{preset.name}</span>
                      {isSelected && <Check size={12} className="text-blue-400" />}
                    </div>
                    <span className="text-[10px] text-slate-400 block mt-0.5">{preset.badge}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Categorized Modules */}
          <div className="space-y-2.5 pt-1">
            <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider block">
              Kategori Modul Pemeriksaan
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {MODULE_CATEGORIES.map((cat) => {
                const categorySelectedCount = cat.modules.filter((m) =>
                  selectedModules.includes(m)
                ).length
                const isAllSelected = categorySelectedCount === cat.modules.length
                const isNoneSelected = categorySelectedCount === 0

                const CategoryIcon =
                  cat.id === 'ssl-tls'
                    ? Shield
                    : cat.id === 'web-headers'
                    ? Globe
                    : cat.id === 'cookies'
                    ? Cookie
                    : Server

                return (
                  <div
                    key={cat.id}
                    className="p-3 rounded-lg border border-slate-800/90 bg-slate-900/50 space-y-2"
                  >
                    {/* Category Header */}
                    <div className="flex items-center justify-between pb-1.5 border-b border-slate-800/60">
                      <label className="flex items-center gap-2 cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={isAllSelected}
                          ref={(el) => {
                            if (el) el.indeterminate = !isAllSelected && !isNoneSelected
                          }}
                          onChange={() => handleCategoryToggle(cat.modules)}
                          className="h-3.5 w-3.5 rounded accent-blue-600 cursor-pointer"
                        />
                        <CategoryIcon size={14} className="text-blue-400 shrink-0" />
                        <span className="text-xs font-bold text-slate-200">{cat.title}</span>
                      </label>
                      <span className="text-[10px] font-mono text-slate-400">
                        {categorySelectedCount}/{cat.modules.length}
                      </span>
                    </div>

                    {/* Modules Checklist */}
                    <div className="space-y-1 pt-0.5">
                      {cat.modules.map((moduleName) => {
                        const isChecked = selectedModules.includes(moduleName)
                        return (
                          <label
                            key={moduleName}
                            className="flex items-center gap-2 py-0.5 text-[11px] text-slate-300 hover:text-slate-100 cursor-pointer select-none"
                          >
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => handleModuleToggle(moduleName)}
                              className="h-3 w-3 rounded accent-blue-600 cursor-pointer"
                            />
                            <span className="truncate">{moduleName}</span>
                          </label>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Submit Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-3 border-t border-slate-800">
        <p className="text-xs text-slate-400">
          Uji keamanan akan dijalankan secara paralel terhadap target yang dimasukkan.
        </p>

        <button
          type="submit"
          disabled={isLoading || isScanning || validTargets.length === 0 || selectedModules.length === 0}
          className="btn-primary px-6 py-2.5 text-sm inline-flex items-center justify-center gap-2 shadow-lg shadow-blue-900/20 disabled:opacity-50 disabled:cursor-not-allowed font-semibold"
        >
          {isLoading || isScanning ? (
            <>
              <Loader2 size={16} className="animate-spin text-white" />
              <span>{isLoading ? 'Menyiapkan Scan...' : 'Scan Sedang Berjalan...'}</span>
            </>
          ) : (
            <>
              <Play size={16} className="fill-white" />
              <span>
                Mulai Uji Keamanan ({validTargets.length} Target • {selectedModules.length} Modul)
              </span>
            </>
          )}
        </button>
      </div>
    </form>
  )
}
