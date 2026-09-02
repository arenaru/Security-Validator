import { useState, type ReactNode } from 'react'
import { ChevronLeft, ChevronRight, ShieldCheck } from 'lucide-react'
import { MODULE_NAMES } from '../types'

interface ScanFormProps {
  onSubmit: (targets: string[], modules: string[]) => void
  isLoading: boolean
  children?: ReactNode
  results?: ReactNode
}

export function ScanForm({ onSubmit, isLoading, children, results }: ScanFormProps) {
  const [targetsInput, setTargetsInput] = useState('')
  const [modules, setModules] = useState<string[]>([])
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const allModulesSelected = modules.length === MODULE_NAMES.length

  const handleModuleToggle = (module: string) => {
    setModules(prev =>
      prev.includes(module)
        ? prev.filter(m => m !== module)
        : [...prev, module]
    )
  }

  const handleToggleAllModules = () => {
    setModules(allModulesSelected ? [] : [...MODULE_NAMES])
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const validTargets = targetsInput
      .split(/\r?\n/)
      .map(target => target.trim())
      .filter(Boolean)

    if (!validTargets.length) {
      alert('Please enter at least one target')
      return
    }

    if (!modules.length) {
      alert('Please select at least one module')
      return
    }

    onSubmit(validTargets, modules)
  }

  return (
    <div className={`grid items-start gap-6 transition-[grid-template-columns] duration-300 ${
      sidebarOpen ? 'lg:grid-cols-[18rem_minmax(0,1fr)]' : 'lg:grid-cols-[3.5rem_minmax(0,1fr)]'
    }`}>
      {/* Scan configuration */}
      <aside
        className={`card flex max-h-[calc(100vh-7rem)] flex-col overflow-hidden transition-all duration-300 lg:sticky lg:top-24 ${
          sidebarOpen ? 'w-full' : 'w-14'
        }`}
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-3 py-4">
          {sidebarOpen && (
            <span className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <ShieldCheck size={18} className="text-blue-500" />
              Scan Modules
            </span>
          )}
          <button
            type="button"
            onClick={() => setSidebarOpen(prev => !prev)}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors"
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <ChevronLeft size={18} /> : <ChevronRight size={18} />}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-4">
          {sidebarOpen ? (
            <>
              <label className="mb-3 flex items-center gap-3 p-3 rounded-lg bg-slate-800/40 hover:bg-slate-800/60 cursor-pointer transition-colors">
                <input
                  type="checkbox"
                  checked={allModulesSelected}
                  onChange={handleToggleAllModules}
                  className="w-4 h-4 rounded border-slate-600 accent-blue-600"
                />
                <span className="text-sm font-medium text-slate-200">Select all modules</span>
              </label>
              <div className="space-y-1">
                {MODULE_NAMES.map(module => (
                  <label key={module} className="flex items-center gap-3 p-3 rounded-lg hover:bg-slate-800/50 cursor-pointer transition-colors">
                    <input
                      type="checkbox"
                      checked={modules.includes(module)}
                      onChange={() => handleModuleToggle(module)}
                      className="w-4 h-4 rounded border-slate-600 accent-blue-600"
                    />
                    <span className="text-sm text-slate-300">{module}</span>
                  </label>
                ))}
              </div>
              {modules.length > 0 && (
                <p className="mt-3 px-1 text-xs text-slate-500">
                  {modules.length} of {MODULE_NAMES.length} selected
                </p>
              )}
            </>
          ) : (
            <div className="flex flex-col items-center">
              <span
                title={`${modules.length} of ${MODULE_NAMES.length} modules selected`}
                className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600/20 text-xs font-semibold text-blue-400"
              >
                {modules.length}
              </span>
            </div>
          )}
        </div>
      </aside>

      <div className="min-w-0 space-y-8">
        <div className="max-w-3xl space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Targets Section */}
            <div className="card p-5">
              <h2 className="mb-3 text-lg font-semibold text-slate-100">Scan Target</h2>
              <textarea
                value={targetsInput}
                onChange={(e) => setTargetsInput(e.target.value)}
                placeholder={['example.com', 'https://target.tld', 'subdomain.example.org'].join('\n')}
                rows={6}
                className="input-field min-h-40 w-full resize-y"
              />
              <p className="mt-2 text-xs text-slate-400">
                Enter one target per line. Empty lines will be ignored.
              </p>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className="btn-primary px-6 py-2 text-sm"
            >
              {isLoading ? 'Starting scan...' : 'Start Scan'}
            </button>
          </form>

          {children}
        </div>

        {results && <div>{results}</div>}
      </div>
    </div>
  )
}
