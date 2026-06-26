import axios from 'axios';
const API_BASE = '/api';
const client = axios.create({
    baseURL: API_BASE,
    headers: {
        'Content-Type': 'application/json',
    },
});
function normalizeProgress(progress) {
    const completedModules = progress.completedModules ?? progress.completed_modules ?? 0;
    const totalModules = progress.totalModules ?? progress.total_modules ?? 0;
    const percent = progress.percent ?? (totalModules > 0 ? (completedModules / totalModules) * 100 : 0);
    return {
        completedModules,
        totalModules,
        percent,
    };
}
function normalizeAcceptedResponse(data) {
    return {
        scanId: data.scanId ?? data.scan_id ?? '',
        status: data.status,
        createdAt: data.createdAt ?? data.created_at ?? '',
        message: data.message,
    };
}
function normalizeStatusResponse(data) {
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
    };
}
function normalizeSummaryResponse(data) {
    return {
        scanId: data.scanId ?? data.scan_id ?? '',
        byModule: data.byModule ?? data.by_module ?? [],
        totals: data.totals,
    };
}
export const scanApi = {
    // Create a new scan
    async createScan(request) {
        const { data } = await client.post('/scans', request);
        return normalizeAcceptedResponse(data);
    },
    // Get scan status and results
    async getScanStatus(scanId) {
        const { data } = await client.get(`/scans/${scanId}`);
        return normalizeStatusResponse(data);
    },
    // Get scan summary
    async getScanSummary(scanId) {
        const { data } = await client.get(`/scans/${scanId}/summary`);
        return normalizeSummaryResponse(data);
    },
    // Download XLSX report
    async downloadReport(scanId) {
        const { data } = await client.get(`/scans/${scanId}/report.xlsx`, {
            responseType: 'blob',
        });
        return data;
    },
    // Health check
    async getHealth() {
        const { data } = await client.get('/health');
        return data;
    },
};
