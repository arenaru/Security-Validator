import axios from 'axios'
import type {
  ScanCreateRequest,
  ScanAcceptedResponse,
  ScanStatusResponse,
  ScanSummaryResponse,
} from '../types'

/**
 * Unwraps the API error envelope so callers surface the server's reason
 * instead of axios' generic "Request failed with status code 400".
 * Backend shape: { detail: { error: { code, message, trace_id } } }
 */
function apiErrorMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail
    const message = detail?.error?.message ?? detail?.message
    if (typeof message === 'string' && message) return message
    if (typeof detail === 'string' && detail) return detail
  }
  return err instanceof Error && err.message ? err.message : fallback
}

export class ApiError extends Error {
  readonly status?: number

  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function toApiError(err: unknown, fallback: string): ApiError {
  const status = axios.isAxiosError(err) ? err.response?.status : undefined
  return new ApiError(apiErrorMessage(err, fallback), status)
}

const API_BASE = '/api'

const client = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
})

type ApiProgress = {
  completedModules?: number
  completed_modules?: number
  totalModules?: number
  total_modules?: number
  percent?: number
}

type ApiScanAcceptedResponse = {
  scanId?: string
  scan_id?: string
  status: ScanAcceptedResponse['status']
  createdAt?: string
  created_at?: string
  message: string
}

type ApiScanStatusResponse = {
  scanId?: string
  scan_id?: string
  status: ScanStatusResponse['status']
  createdAt?: string
  created_at?: string
  updatedAt?: string
  updated_at?: string
  startedAt?: string | null
  started_at?: string | null
  finishedAt?: string | null
  finished_at?: string | null
  targets: string[]
  modules: string[]
  progress: ApiProgress
  results?: ScanStatusResponse['results']
  errors: ScanStatusResponse['errors']
}

type ApiScanSummaryResponse = {
  scanId?: string
  scan_id?: string
  byModule?: ScanSummaryResponse['byModule']
  by_module?: ScanSummaryResponse['byModule']
  totals: ScanSummaryResponse['totals']
}

function normalizeProgress(progress: ApiProgress): ScanStatusResponse['progress'] {
  const completedModules = progress.completedModules ?? progress.completed_modules ?? 0
  const totalModules = progress.totalModules ?? progress.total_modules ?? 0
  const percent = progress.percent ?? (totalModules > 0 ? (completedModules / totalModules) * 100 : 0)

  return {
    completedModules,
    totalModules,
    percent,
  }
}

function normalizeAcceptedResponse(data: ApiScanAcceptedResponse): ScanAcceptedResponse {
  return {
    scanId: data.scanId ?? data.scan_id ?? '',
    status: data.status,
    createdAt: data.createdAt ?? data.created_at ?? '',
    message: data.message,
  }
}

function normalizeStatusResponse(data: ApiScanStatusResponse): ScanStatusResponse {
  return {
    scanId: data.scanId ?? data.scan_id ?? '',
    status: data.status,
    createdAt: data.createdAt ?? data.created_at ?? '',
    updatedAt: data.updatedAt ?? data.updated_at ?? '',
    startedAt: data.startedAt ?? data.started_at ?? null,
    finishedAt: data.finishedAt ?? data.finished_at ?? null,
    targets: data.targets,
    modules: data.modules,
    progress: normalizeProgress(data.progress),
    results: data.results ?? null,
    errors: data.errors,
  }
}

function normalizeSummaryResponse(data: ApiScanSummaryResponse): ScanSummaryResponse {
  return {
    scanId: data.scanId ?? data.scan_id ?? '',
    byModule: data.byModule ?? data.by_module ?? [],
    totals: data.totals,
  }
}

export const scanApi = {
  // Create a new scan
  async createScan(request: ScanCreateRequest): Promise<ScanAcceptedResponse> {
    try {
      const { data } = await client.post<ApiScanAcceptedResponse>('/scans', request)
      return normalizeAcceptedResponse(data)
    } catch (err) {
      throw toApiError(err, 'Gagal memulai proses scan.')
    }
  },

  // Get scan status and results
  async getScanStatus(scanId: string): Promise<ScanStatusResponse> {
    try {
      const { data } = await client.get<ApiScanStatusResponse>(`/scans/${scanId}`)
      return normalizeStatusResponse(data)
    } catch (err) {
      throw toApiError(err, 'Gagal mengambil status scan.')
    }
  },

  // Get scan summary
  async getScanSummary(scanId: string): Promise<ScanSummaryResponse> {
    try {
      const { data } = await client.get<ApiScanSummaryResponse>(`/scans/${scanId}/summary`)
      return normalizeSummaryResponse(data)
    } catch (err) {
      throw toApiError(err, 'Gagal mengambil ringkasan scan.')
    }
  },

  // Download XLSX report
  async downloadReport(scanId: string): Promise<Blob> {
    try {
      const { data } = await client.get(`/scans/${scanId}/report.xlsx`, {
        responseType: 'blob',
      })
      return data
    } catch (err) {
      throw toApiError(err, 'Gagal mengunduh laporan.')
    }
  },

  // Health check
  async getHealth() {
    const { data } = await client.get('/health')
    return data
  },
}
