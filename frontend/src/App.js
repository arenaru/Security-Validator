import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import { scanApi } from './api/client';
import { ScanForm } from './components/ScanForm';
import { ProgressBar } from './components/ProgressBar';
import { SummaryCards } from './components/SummaryCards';
import { ResultsTable } from './components/ResultsTable';
function App() {
    const [scanId, setScanId] = useState(null);
    const [scanStatus, setScanStatus] = useState(null);
    const [summary, setSummary] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    // Poll scan status
    useEffect(() => {
        if (!scanId)
            return;
        const interval = setInterval(async () => {
            try {
                const status = await scanApi.getScanStatus(scanId);
                setScanStatus(status);
                if (status.status === 'done' || status.status === 'partial' || status.status === 'failed') {
                    clearInterval(interval);
                    const summaryData = await scanApi.getScanSummary(scanId);
                    setSummary(summaryData);
                }
            }
            catch (err) {
                console.error('Error polling scan status:', err);
            }
        }, 1000);
        return () => clearInterval(interval);
    }, [scanId]);
    const handleStartScan = async (targets, modules) => {
        try {
            setIsLoading(true);
            setError(null);
            const response = await scanApi.createScan({
                targets,
                modules,
                options: {
                    timeoutSeconds: 30,
                    parallelism: 6,
                },
            });
            setScanId(response.scanId);
            setScanStatus({
                scanId: response.scanId,
                status: response.status,
                createdAt: response.createdAt,
                updatedAt: response.createdAt,
                startedAt: null,
                finishedAt: null,
                targets,
                modules,
                progress: {
                    completedModules: 0,
                    totalModules: modules.length,
                    percent: 0,
                },
                results: null,
                errors: [],
            });
        }
        catch (err) {
            const message = err instanceof Error ? err.message : 'Failed to start scan';
            setError(message);
            console.error('Error starting scan:', err);
        }
        finally {
            setIsLoading(false);
        }
    };
    return (_jsxs("div", { className: "min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950", children: [_jsx("header", { className: "border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50", children: _jsxs("div", { className: "max-w-7xl mx-auto px-4 py-6 flex items-center gap-3", children: [_jsx(Shield, { className: "text-blue-500", size: 32 }), _jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-bold text-slate-100", children: "SecVal" }), _jsx("p", { className: "text-sm text-slate-400", children: "Vulnerability Assessment" })] })] }) }), _jsxs("main", { className: "max-w-7xl mx-auto px-4 py-8", children: [error && (_jsx("div", { className: "mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg text-red-400", children: error })), !scanId ? (_jsx("div", { className: "max-w-2xl", children: _jsx(ScanForm, { onSubmit: handleStartScan, isLoading: isLoading }) })) : scanStatus ? (_jsxs("div", { className: "space-y-6", children: [_jsx(ProgressBar, { progress: scanStatus.progress, status: scanStatus.status }), summary && (_jsxs("div", { className: "space-y-4", children: [_jsx("h2", { className: "text-xl font-semibold text-slate-100", children: "Summary" }), _jsx(SummaryCards, { totals: summary.totals })] })), scanStatus.results && Object.keys(scanStatus.results).length > 0 && (_jsxs("div", { className: "space-y-4", children: [_jsx("h2", { className: "text-xl font-semibold text-slate-100", children: "Detailed Results" }), _jsx(ResultsTable, { results: scanStatus.results })] })), scanStatus.errors && scanStatus.errors.length > 0 && (_jsxs("div", { className: "card p-6", children: [_jsx("h2", { className: "text-lg font-semibold text-slate-100 mb-4", children: "Errors" }), _jsx("div", { className: "space-y-2", children: scanStatus.errors.map((err, idx) => (_jsxs("div", { className: "text-sm text-slate-400 p-2 bg-red-900/10 rounded", children: [_jsxs("strong", { className: "text-slate-300", children: [err.module, ":"] }), " ", err.message] }, idx))) })] })), scanStatus.status !== 'pending' && (_jsx("div", { children: _jsx("button", { onClick: () => {
                                        setScanId(null);
                                        setScanStatus(null);
                                        setSummary(null);
                                    }, className: "btn-secondary w-full", children: "Start New Scan" }) }))] })) : null] }), _jsx("footer", { className: "border-t border-slate-800 bg-slate-900/50 mt-12", children: _jsx("div", { className: "max-w-7xl mx-auto px-4 py-6 text-center text-slate-500 text-sm", children: "SecVal v0.1.0 \u2022 Vulnerability Scanner" }) })] }));
}
export default App;
