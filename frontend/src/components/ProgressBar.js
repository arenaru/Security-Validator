import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Activity } from 'lucide-react';
export function ProgressBar({ progress, status }) {
    const statusColors = {
        pending: 'bg-yellow-500',
        running: 'bg-blue-500',
        done: 'bg-green-500',
        partial: 'bg-orange-500',
        failed: 'bg-red-500',
    };
    const statusLabels = {
        pending: 'Pending',
        running: 'Running',
        done: 'Completed',
        partial: 'Partial Results',
        failed: 'Failed',
    };
    return (_jsxs("div", { className: "card p-6 space-y-4", children: [_jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("div", { className: "flex items-center gap-2", children: [status === 'running' && (_jsx(Activity, { className: "text-blue-400 animate-spin", size: 20 })), _jsx("h3", { className: "text-lg font-semibold", children: "Scan Progress" })] }), _jsx("span", { className: `px-3 py-1 rounded-full text-sm font-medium ${statusColors[status]} text-white`, children: statusLabels[status] })] }), _jsxs("div", { className: "space-y-2", children: [_jsx("div", { className: "w-full bg-slate-800 rounded-full h-3 overflow-hidden", children: _jsx("div", { className: `h-full transition-all duration-500 ${statusColors[status]}`, style: { width: `${progress.percent}%` } }) }), _jsxs("div", { className: "flex justify-between text-sm text-slate-400", children: [_jsxs("span", { children: [progress.completedModules, " of ", progress.totalModules, " modules"] }), _jsxs("span", { className: "font-semibold text-slate-100", children: [Math.round(progress.percent), "%"] })] })] })] }));
}
