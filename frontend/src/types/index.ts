export interface ScanCreateRequest {
  targets: string[]
  modules: string[]
  options?: {
    timeout_seconds?: number
    parallelism?: number
    allow_private_targets?: boolean
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

export interface SkippedTarget {
  target: string
  reason: string
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
  /** Targets dropped before scanning (DNS/TCP pre-flight), with the reason. */
  skippedTargets: SkippedTarget[]
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
  'IP Country Lookup',
] as const

export interface ModuleCategoryDef {
  id: string
  title: string
  description: string
  icon: string
  modules: typeof MODULE_NAMES[number][]
}

export const MODULE_CATEGORIES: ModuleCategoryDef[] = [
  {
    id: 'ssl-tls',
    title: 'SSL / TLS Security',
    description: 'Sertifikat SSL, hostname mismatch, dan protokol usang (SSLv3, TLS 1.0/1.1)',
    icon: 'Shield',
    modules: [
      'SSL Certificate Check',
      'SSL Certificate Hostname Mismatch',
      'SSLv3 Detection',
      'TLS 1.0 Detection',
      'TLS 1.1 Detection',
    ],
  },
  {
    id: 'web-headers',
    title: 'Web & Headers Security',
    description: 'Response code server, HSTS, dan missing security headers (CSP, X-Frame, dll.)',
    icon: 'Globe',
    modules: [
      'Response Code Check',
      'HSTS Security Check',
      'Security Headers Check',
    ],
  },
  {
    id: 'cookies',
    title: 'Cookie & Session Security',
    description: 'Proteksi flag Secure dan HttpOnly pada cookies untuk mencegah XSS & man-in-the-middle',
    icon: 'Cookie',
    modules: [
      'Cookie Secure Flag',
      'Cookie HttpOnly Flag',
    ],
  },
  {
    id: 'framework-leaks',
    title: 'Framework & Info Leaks',
    description: 'Deteksi debug mode bocor (Laravel, Node.js), versi PHP terekspos, dan lookup IP',
    icon: 'Server',
    modules: [
      'Laravel Debug Mode',
      'Node.js Debug Mode',
      'PHP Version Disclosure',
      'IP Country Lookup',
    ],
  },
]

export interface ScanPreset {
  id: string
  name: string
  badge: string
  description: string
  modules: typeof MODULE_NAMES[number][]
}

export const SCAN_PRESETS: ScanPreset[] = [
  {
    id: 'full',
    name: 'Full Audit',
    badge: '14 Modul',
    description: 'Pemeriksaan keamanan lengkap seluruh 14 modul',
    modules: [...MODULE_NAMES],
  },
  {
    id: 'quick',
    name: 'Quick Check',
    badge: '4 Modul',
    description: 'Audit cepat: SSL, Headers, HSTS, dan Response Code (< 15 detik)',
    modules: [
      'SSL Certificate Check',
      'Security Headers Check',
      'HSTS Security Check',
      'Response Code Check',
    ],
  },
  {
    id: 'ssl',
    name: 'SSL / TLS Only',
    badge: '5 Modul',
    description: 'Fokus sertifikat SSL dan kerentanan protokol enkripsi transport',
    modules: [
      'SSL Certificate Check',
      'SSL Certificate Hostname Mismatch',
      'SSLv3 Detection',
      'TLS 1.0 Detection',
      'TLS 1.1 Detection',
    ],
  },
  {
    id: 'web',
    name: 'Web & Framework',
    badge: '6 Modul',
    description: 'Audit kerentanan aplikasi web, debug mode bocor, dan proteksi cookies',
    modules: [
      'Laravel Debug Mode',
      'Node.js Debug Mode',
      'PHP Version Disclosure',
      'Security Headers Check',
      'Cookie Secure Flag',
      'Cookie HttpOnly Flag',
    ],
  },
]

