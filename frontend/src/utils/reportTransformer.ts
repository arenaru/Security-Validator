import { INFORMATIONAL_MODULES } from '../types'
import type {
  ModuleResult,
  TargetFinding,
  TargetGeoInfo,
  TargetReport,
} from '../types'

/**
 * Normalizes a target string (URL, hostname, IP) to a standard hostname/domain key.
 */
export function normalizeDomain(target: string): string {
  if (!target) return ''
  let cleaned = target.trim().toLowerCase()
  if (cleaned.startsWith('http://')) cleaned = cleaned.slice(7)
  if (cleaned.startsWith('https://')) cleaned = cleaned.slice(8)
  cleaned = cleaned.split('/')[0] // remove paths
  cleaned = cleaned.split(':')[0] // remove port
  return cleaned
}

function getRawValue(item: ModuleResult, ...keys: string[]): unknown {
  if (!item.raw) return undefined
  for (const key of keys) {
    if (key in item.raw) {
      return item.raw[key]
    }
  }
  return undefined
}

function normalizeText(value: unknown): string {
  if (value === null || value === undefined) return ''
  const str = String(value).trim()
  if (str.toLowerCase() === 'none (all found)') return ''
  return str
}

/**
 * Parses missing headers string into individual clean header names.
 */
function parseMissingHeaders(rawVal: unknown): string[] {
  const text = normalizeText(rawVal)
  if (!text) return []
  return text
    .split(',')
    .map(h => h.trim())
    .filter(Boolean)
}

/**
 * Extracts structured finding info from a ModuleResult.
 */
function parseFinding(item: ModuleResult): TargetFinding {
  const missingHeaders = parseMissingHeaders(getRawValue(item, 'Missing Headers', 'missing_headers'))
  const payload = normalizeText(getRawValue(item, 'payload', 'Payload'))
  const evidence = normalizeText(getRawValue(item, 'finding', 'Finding', 'Error', 'error', 'bukti_error'))
  const sisaHari = getRawValue(item, 'Sisa Hari', 'sisa_hari')
  const expiredDate = normalizeText(getRawValue(item, 'Expired Date', 'expired_date'))
  const statusCode = getRawValue(item, 'Status Code', 'status_code')

  return {
    module: item.module,
    status: item.status,
    details: item.details || normalizeText(getRawValue(item, 'Detail', 'details', 'Message', 'message')),
    severity: item.severity,
    raw: item.raw,
    missingHeaders: missingHeaders.length > 0 ? missingHeaders : undefined,
    payload: payload || undefined,
    evidence: evidence || undefined,
    sisaHari: sisaHari !== undefined && sisaHari !== null && sisaHari !== '' ? String(sisaHari) : undefined,
    expiredDate: expiredDate || undefined,
    statusCode: statusCode !== undefined && statusCode !== null ? String(statusCode) : undefined,
  }
}

/**
 * Transforms API results (Record<string, ModuleResult[]>) into an array of TargetReport.
 */
export function transformToTargetReports(
  results: Record<string, ModuleResult[]>,
  originalTargets: string[] = []
): TargetReport[] {
  const targetMap = new Map<string, {
    originalTarget: string
    findings: TargetFinding[]
    geo?: TargetGeoInfo
  }>()

  // Pre-seed with original targets if available so targets with no findings or pending results are not lost
  for (const t of originalTargets) {
    const norm = normalizeDomain(t)
    if (norm && !targetMap.has(norm)) {
      targetMap.set(norm, {
        originalTarget: t,
        findings: [],
      })
    }
  }

  // Iterate over each module
  for (const [moduleName, items] of Object.entries(results)) {
    for (const item of items) {
      const rawTarget = normalizeText(getRawValue(item, 'URL', 'url', 'target', 'Target') ?? item.target)
      const domainKey = normalizeDomain(rawTarget)
      if (!domainKey) continue

      let entry = targetMap.get(domainKey)
      if (!entry) {
        entry = {
          originalTarget: rawTarget,
          findings: [],
        }
        targetMap.set(domainKey, entry)
      }

      // Special handling for IP Country Lookup
      if (moduleName === 'IP Country Lookup') {
        const ip = normalizeText(getRawValue(item, 'IP'))
        const country = normalizeText(getRawValue(item, 'Country'))
        const countryCode = normalizeText(getRawValue(item, 'Country Code'))
        const city = normalizeText(getRawValue(item, 'City'))
        const isp = normalizeText(getRawValue(item, 'ISP'))
        const asInfo = normalizeText(getRawValue(item, 'AS'))

        if (ip || country) {
          entry.geo = {
            ip: ip || undefined,
            country: country || undefined,
            countryCode: countryCode || undefined,
            city: city || undefined,
            isp: isp || undefined,
            as: asInfo || undefined,
          }
        }
      }

      const finding = parseFinding({ ...item, module: moduleName })
      entry.findings.push(finding)
    }
  }

  const reports: TargetReport[] = []

  for (const [domainKey, entry] of targetMap.entries()) {
    const issues: TargetFinding[] = []
    const passed: TargetFinding[] = []

    const recon: TargetFinding[] = []

    let insecureCount = 0
    let warningCount = 0
    let secureCount = 0
    let errorCount = 0
    let infoCount = 0

    for (const f of entry.findings) {
      // Recon modules report facts, not findings. Routing them here keeps a
      // 401/404 off the remediation list and out of overallStatus, and stops an
      // HTTP 200 being counted as a passed security check.
      if (INFORMATIONAL_MODULES.has(f.module)) {
        infoCount++
        recon.push(f)
        continue
      }

      const st = f.status.toLowerCase()
      if (st === 'insecure') {
        insecureCount++
        issues.push(f)
      } else if (st === 'warning') {
        warningCount++
        issues.push(f)
      } else if (st === 'error') {
        errorCount++
        issues.push(f)
      } else if (st === 'info') {
        infoCount++
        recon.push(f)
      } else {
        secureCount++
        passed.push(f)
      }
    }

    let overallStatus: TargetReport['overallStatus'] = 'secure'
    if (insecureCount > 0) {
      overallStatus = 'insecure'
    } else if (warningCount > 0) {
      overallStatus = 'warning'
    } else if (errorCount > 0) {
      overallStatus = 'error'
    }

    reports.push({
      target: entry.originalTarget,
      normalizedDomain: domainKey,
      overallStatus,
      geo: entry.geo,
      issues,
      passed,
      recon,
      counts: {
        total: entry.findings.length,
        insecure: insecureCount,
        warning: warningCount,
        secure: secureCount,
        error: errorCount,
        info: infoCount,
      },
    })
  }

  // Sort reports: insecure first, then warning, then error, then secure
  const statusRank: Record<string, number> = {
    insecure: 0,
    warning: 1,
    error: 2,
    secure: 3,
  }

  reports.sort((a, b) => {
    const rankA = statusRank[a.overallStatus] ?? 9
    const rankB = statusRank[b.overallStatus] ?? 9
    if (rankA !== rankB) return rankA - rankB
    return a.normalizedDomain.localeCompare(b.normalizedDomain)
  })

  return reports
}

/**
 * Generates formatted text report for a target to easily copy to clipboard.
 */
export function formatTargetReportText(report: TargetReport): string {
  const lines: string[] = [
    `=== RAPOR KEAMANAN: ${report.normalizedDomain} ===`,
    `Target: ${report.target}`,
  ]

  if (report.geo) {
    const geoParts = [
      report.geo.ip ? `IP: ${report.geo.ip}` : null,
      report.geo.country ? `Negara: ${report.geo.country}${report.geo.countryCode ? ` (${report.geo.countryCode})` : ''}` : null,
      report.geo.isp ? `ISP: ${report.geo.isp}` : null,
    ].filter(Boolean)
    if (geoParts.length) {
      lines.push(`Server: ${geoParts.join(' | ')}`)
    }
  }

  lines.push(`Status Keseluruhan: ${report.overallStatus.toUpperCase()}`)
  lines.push(`Rekapitulasi: ${report.counts.insecure} Rentan, ${report.counts.warning} Peringatan, ${report.counts.secure} Lolos, ${report.counts.info} Info`)
  lines.push('')

  if (report.issues.length > 0) {
    lines.push('[TEMUAN YANG PERLU DIPERBAIKI]:')
    for (const issue of report.issues) {
      lines.push(`• [${issue.status.toUpperCase()}] ${issue.module}`)
      if (issue.details) lines.push(`  Detail: ${issue.details}`)
      if (issue.missingHeaders?.length) {
        lines.push(`  Missing Headers: ${issue.missingHeaders.join(', ')}`)
      }
      if (issue.payload) lines.push(`  Trigger/Payload: ${issue.payload}`)
      if (issue.evidence) lines.push(`  Bukti: ${issue.evidence}`)
      if (issue.sisaHari) lines.push(`  Sisa Hari SSL: ${issue.sisaHari} hari (Exp: ${issue.expiredDate || '-'})`)
    }
    lines.push('')
  } else {
    lines.push('[HASIL PEMERIKSAAN]:')
    lines.push('Semua modul keamanan yang diuji lulus (tidak ditemukan celah keamanan).')
    lines.push('')
  }

  if (report.passed.length > 0) {
    lines.push('[MODUL LOLOS UJI]:')
    const passedList = report.passed.map(p => `• ${p.module}`).join('\n')
    lines.push(passedList)
    lines.push('')
  }

  if (report.recon.length > 0) {
    lines.push('[DATA REKONESANS (bukan temuan)]:')
    for (const r of report.recon) {
      lines.push(`• ${r.module}: ${r.details || '-'}`)
    }
  }

  lines.push('')
  lines.push(`Dibuat oleh SecVal Vulnerability Scanner`)
  return lines.join('\n')
}

export interface SummaryActionItem {
  targetDomain: string
  targetUrl: string
  module: string
  status: 'insecure' | 'warning' | 'error'
  details: string
  missingHeaders?: string[]
  sisaHari?: string | number
  expiredDate?: string
  payload?: string
}

export interface ModuleMatrixItem {
  moduleName: string
  targetCount: number
  insecureCount: number
  warningCount: number
  secureCount: number
  errorCount: number
  infoCount: number
  /** True for recon modules (see INFORMATIONAL_MODULES): reports facts, not findings. */
  informational: boolean
}

export function extractSummaryData(
  targetReports: TargetReport[],
  results: Record<string, ModuleResult[]>
) {
  const actionItems: SummaryActionItem[] = []

  for (const report of targetReports) {
    for (const issue of report.issues) {
      actionItems.push({
        targetDomain: report.normalizedDomain,
        targetUrl: report.target,
        module: issue.module,
        status: issue.status as 'insecure' | 'warning' | 'error',
        details: issue.details,
        missingHeaders: issue.missingHeaders,
        sisaHari: issue.sisaHari,
        expiredDate: issue.expiredDate,
        payload: issue.payload,
      })
    }
  }

  // Sort action items: insecure first, then warning, then error
  const priorityMap: Record<string, number> = { insecure: 0, warning: 1, error: 2 }
  actionItems.sort((a, b) => (priorityMap[a.status] ?? 9) - (priorityMap[b.status] ?? 9))

  const moduleMatrix: ModuleMatrixItem[] = []
  for (const [moduleName, items] of Object.entries(results)) {
    const informational = INFORMATIONAL_MODULES.has(moduleName)

    let insecureCount = 0
    let warningCount = 0
    let secureCount = 0
    let errorCount = 0
    let infoCount = 0

    for (const item of items) {
      // Recon rows are facts, not verdicts: counting them as "Lolos" would
      // claim a security test passed when none was performed.
      if (informational) {
        infoCount++
        continue
      }

      const st = String(item.status).toLowerCase()
      if (st === 'insecure') insecureCount++
      else if (st === 'warning') warningCount++
      else if (st === 'error') errorCount++
      else if (st === 'info') infoCount++
      else secureCount++
    }

    moduleMatrix.push({
      moduleName,
      targetCount: items.length,
      insecureCount,
      warningCount,
      secureCount,
      errorCount,
      infoCount,
      informational,
    })
  }

  // Sort module matrix: modules with issues first
  moduleMatrix.sort((a, b) => {
    const issuesA = a.insecureCount * 10 + a.warningCount
    const issuesB = b.insecureCount * 10 + b.warningCount
    return issuesB - issuesA
  })

  return {
    actionItems,
    moduleMatrix,
  }
}

export function formatFullSummaryText(
  targetReports: TargetReport[],
  actionItems: SummaryActionItem[],
  moduleMatrix: ModuleMatrixItem[]
): string {
  const lines: string[] = [
    '====================================================',
    '       SECVAL - LAPORAN RINGKASAN KEAMANAN WEB       ',
    '====================================================',
    `Jumlah Target: ${targetReports.length} domain`,
    `Total Temuan Masalah: ${actionItems.length}`,
    '',
  ]

  if (actionItems.length > 0) {
    lines.push('[ 1. PRIORITAS TINDAKAN PERBAIKAN ]')
    for (const item of actionItems) {
      lines.push(`• [${item.status.toUpperCase()}] ${item.module} - ${item.targetDomain}`)
      if (item.details) lines.push(`  Detail: ${item.details}`)
      if (item.missingHeaders?.length) {
        lines.push(`  Missing Headers: ${item.missingHeaders.join(', ')}`)
      }
      if (item.sisaHari) {
        lines.push(`  Sisa Hari SSL: ${item.sisaHari} hari (Exp: ${item.expiredDate || '-'})`)
      }
    }
    lines.push('')
  } else {
    lines.push('[ 1. STATUS KEAMANAN ]')
    lines.push('Semua target bersih dan lolos seluruh modul pengujian.')
    lines.push('')
  }

  lines.push(`[ 2. MATRIKS ${moduleMatrix.length} MODUL PEMERIKSAAN ]`)
  for (const m of moduleMatrix) {
    if (m.informational) {
      lines.push(`• ${m.moduleName.padEnd(32)} | Total: ${m.targetCount} | Rekonesans (bukan temuan)`)
    } else {
      lines.push(
        `• ${m.moduleName.padEnd(32)} | Total: ${m.targetCount} | Rentan: ${m.insecureCount} | Warning: ${m.warningCount} | Lolos: ${m.secureCount}`
      )
    }
  }
  lines.push('')

  lines.push('[ 3. REKAPITULASI TARGET ]')
  for (const r of targetReports) {
    const geo = r.geo?.country ? ` (${r.geo.country})` : ''
    lines.push(`• ${r.normalizedDomain}${geo}: ${r.overallStatus.toUpperCase()} [${r.counts.insecure} Rentan, ${r.counts.warning} Peringatan, ${r.counts.secure} Lolos]`)
  }

  lines.push('')
  lines.push('Dibuat oleh SecVal Vulnerability Assessment Platform')
  return lines.join('\n')
}

