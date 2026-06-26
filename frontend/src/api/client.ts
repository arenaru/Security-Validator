import axios from 'axios'
import type {
  ScanCreateRequest,
  ScanAcceptedResponse,
  ScanStatusResponse,
  ScanSummaryResponse,
} from '../types'

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
    const { data } = await client.post<ApiScanAcceptedResponse>('/scans', request)
    return normalizeAcceptedResponse(data)
  },

  // Get scan status and results
  async getScanStatus(scanId: string): Promise<ScanStatusResponse> {
    const { data } = await client.get<ApiScanStatusResponse>(`/scans/${scanId}`)
    return normalizeStatusResponse(data)
  },

  // Get scan summary
  async getScanSummary(scanId: string): Promise<ScanSummaryResponse> {
    const { data } = await client.get<ApiScanSummaryResponse>(`/scans/${scanId}/summary`)
    return normalizeSummaryResponse(data)
  },

  // Download XLSX report
  async downloadReport(scanId: string): Promise<Blob> {
    const { data } = await client.get(`/scans/${scanId}/report.xlsx`, {
      responseType: 'blob',
    })
    return data
  },

  // Health check
  async getHealth() {
    const { data } = await client.get('/health')
    return data
  },
}
