import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { Download, Loader } from 'lucide-react';
export function ReportDownload({ scanId, status, onDownload, isLoading }) {
    const canDownload = status === 'done' || status === 'partial';
    const handleClick = async () => {
        try {
            await onDownload(scanId);
        }
        catch (error) {
            alert('Failed to download report');
        }
    };
    return (_jsxs("div", { className: "card p-6 flex items-center justify-between", children: [_jsxs("div", { children: [_jsx("h3", { className: "font-semibold text-slate-100", children: "Download Report" }), _jsx("p", { className: "text-sm text-slate-400 mt-1", children: canDownload
                            ? 'Export your scan results as XLSX'
                            : 'Report will be available when scan completes' })] }), _jsx("button", { onClick: handleClick, disabled: !canDownload || isLoading, className: "btn-primary flex items-center gap-2", children: isLoading ? (_jsxs(_Fragment, { children: [_jsx(Loader, { size: 18, className: "animate-spin" }), "Downloading..."] })) : (_jsxs(_Fragment, { children: [_jsx(Download, { size: 18 }), "Download XLSX"] })) })] }));
}
