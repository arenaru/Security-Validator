export interface ScanCreateRequest {
  targets: string[]
  modules: string[]
  options?: {
    timeoutSeconds?: number
    parallelism?: number
  }
}

export type ScanStatus = 'pending' | 'running' | 'done' | 'failed' | 'partial'

export interface ScanAcceptedResponse {
  scanId: string
  status: ScanStatus
  createdAt: string
  message: string
}

export interface Progress {
  completedModules: number
  totalModules: number
  percent: number
}

export interface ModuleResult {
  module: string
  target: string
  status: 'secure' | 'warning' | 'insecure' | 'error' | 'info'
  details: string
  severity?: 'low' | 'medium' | 'high' | 'critical'
  code?: string
  vuln_name?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  raw?: Record<string, any>
}

export interface ModuleError {
  module: string
  message: string
  target?: string
}

export interface ScanStatusResponse {
  scanId: string
  status: ScanStatus
  createdAt: string
  updatedAt: string
  startedAt?: string | null
  finishedAt?: string | null
  targets: string[]
  modules: string[]
  progress: Progress
  results?: Record<string, ModuleResult[]> | null
  errors: ModuleError[]
}

export interface ModuleSummary {
  module: string
  count: number
  secure: number
  warning: number
  insecure: number
  error: number
}

export interface SummaryTotals {
  items: number
  secure: number
  warning: number
  insecure: number
  error: number
}

export interface ScanSummaryResponse {
  scanId: string
  byModule: ModuleSummary[]
  totals: SummaryTotals
}

export const MODULE_NAMES = [
  'SSL Certificate Check',
  'SSL Certificate Hostname Mismatch',
  'SSLv3 Detection',
  'TLS 1.0 Detection',
  'TLS 1.1 Detection',
  'Response Code Check',
  'HSTS Security Check',
  'Security Headers Check',
  'Cookie Secure Flag',
  'Cookie HttpOnly Flag',
  'Laravel Debug Mode',
  'Node.js Debug Mode',
  'PHP Version Disclosure',
] as const
