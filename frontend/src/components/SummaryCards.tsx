import { CheckCircle, AlertCircle, XCircle, HelpCircle } from 'lucide-react'
import type { SummaryTotals } from '../types'

interface SummaryCardsProps {
  totals: SummaryTotals
}

export function SummaryCards({ totals }: SummaryCardsProps) {
  const cards = [
    {
        label: 'Secure domains',
        value: totals.secure,
        icon: CheckCircle,
        color: 'text-green-400',
        bg: 'bg-green-900/10',
      },
      {
        label: 'Warning domains',
        value: totals.warning,
        icon: AlertCircle,
        color: 'text-yellow-400',
        bg: 'bg-yellow-900/10',
      },
      {
        label: 'Vulnerable domains',
        value: totals.insecure,
        icon: XCircle,
        color: 'text-red-400',
        bg: 'bg-red-900/10',
      },
      {
        label: 'Error domains',
      color: 'text-slate-400',
      bg: 'bg-slate-800/20',
    },
  ]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map(({ label, value, icon: Icon, color, bg }) => (
        <div key={label} className={`card p-6 ${bg}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">{label}</p>
              <p className="text-3xl font-bold mt-1">{value}</p>
            </div>
            <Icon className={`${color}`} size={32} />
          </div>
        </div>
      ))}
      <div className="col-span-1 md:col-span-2 lg:col-span-4">
        <div className="card p-4 bg-slate-800/50">
          <p className="text-center text-slate-400 text-sm">
            Total domains scanned: <span className="font-semibold text-slate-100">{totals.items}</span>
          </p>
        </div>
      </div>
    </div>
  )
}
