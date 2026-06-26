import { useState } from 'react'
import { MODULE_NAMES } from '../types'

interface ScanFormProps {
  onSubmit: (targets: string[], modules: string[]) => void
  isLoading: boolean
}

export function ScanForm({ onSubmit, isLoading }: ScanFormProps) {
  const [targetsInput, setTargetsInput] = useState('')
  const [modules, setModules] = useState<string[]>([])
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
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Targets Section */}
      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-4 text-slate-100">Targets</h2>
        <textarea
          value={targetsInput}
          onChange={(e) => setTargetsInput(e.target.value)}
          placeholder={['example.com', 'https://target.tld', 'subdomain.example.org'].join('\n')}
          rows={8}
          className="input-field min-h-48 w-full resize-y"
        />
        <p className="mt-3 text-sm text-slate-400">
          Enter one target per line. Empty lines will be ignored.
        </p>
      </div>

      {/* Modules Section */}
      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-4 text-slate-100">Scan Modules</h2>
        <label className="mb-4 flex items-center gap-3 p-3 rounded-lg bg-slate-800/40 hover:bg-slate-800/60 cursor-pointer transition-colors">
          <input
            type="checkbox"
            checked={allModulesSelected}
            onChange={handleToggleAllModules}
            className="w-4 h-4 rounded border-slate-600 accent-blue-600"
          />
          <span className="text-sm font-medium text-slate-200">Select all modules</span>
        </label>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
      </div>

      {/* Submit Button */}
      <button
        type="submit"
        disabled={isLoading}
        className="btn-primary w-full text-lg py-3"
      >
        {isLoading ? 'Starting scan...' : 'Start Scan'}
      </button>
    </form>
  )
}
