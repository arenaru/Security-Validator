import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { ChevronDown, ChevronUp } from 'lucide-react';
import { useState } from 'react';
function normalizeCell(value) {
    if (value === null || value === undefined)
        return '-';
    const text = String(value).trim();
    if (!text || text.toLowerCase() === 'none (all found)')
        return '-';
    return text;
}
function getRaw(item, ...keys) {
    if (!item.raw)
        return undefined;
    for (const key of keys) {
        if (key in item.raw) {
            return item.raw[key];
        }
    }
    return undefined;
}
function getUrl(item) {
    return normalizeCell(getRaw(item, 'URL', 'url', 'target', 'Target') ?? item.target);
}
function getDetail(item) {
    return normalizeCell(getRaw(item, 'Detail', 'details', 'Message', 'message', 'finding') ?? item.details);
}
function getPayload(item) {
    return normalizeCell(getRaw(item, 'payload', 'Payload'));
}
function getStatusLabel(item) {
    return normalizeCell(getRaw(item, 'Status', 'status') ?? item.status.toUpperCase());
}
const STATUS_PRIORITY = {
    ERROR: 5,
    INSECURE: 4,
    WARNING: 3,
    INFO: 2,
    SECURE: 1,
};
function getScoreNumber(value) {
    const text = normalizeCell(value);
    if (text === '-')
        return -1;
    const parts = text.split('/');
    const first = Number(parts[0]);
    return Number.isFinite(first) ? first : -1;
}
function compareSortValues(a, b, direction) {
    const normalizedA = typeof a === 'string' ? a.trim() : a;
    const normalizedB = typeof b === 'string' ? b.trim() : b;
    const emptyA = normalizedA === '' || normalizedA === '-' || normalizedA === null || normalizedA === undefined;
    const emptyB = normalizedB === '' || normalizedB === '-' || normalizedB === null || normalizedB === undefined;
    if (emptyA && emptyB)
        return 0;
    if (emptyA)
        return 1;
    if (emptyB)
        return -1;
    let result = 0;
    if (typeof normalizedA === 'number' && typeof normalizedB === 'number') {
        result = normalizedA - normalizedB;
    }
    else {
        result = String(normalizedA).localeCompare(String(normalizedB), undefined, { sensitivity: 'base' });
    }
    return direction === 'asc' ? result : -result;
}
function getColumnsForModule(moduleName, statusColors) {
    const indexCol = {
        key: 'index',
        header: '',
        className: 'w-14',
        sortable: true,
        sortValue: (_, index) => index,
        render: (_, index) => _jsx("span", { className: "text-slate-500", children: index }),
    };
    const statusCol = {
        key: 'status',
        header: 'Status',
        className: 'min-w-[140px]',
        sortable: true,
        sortValue: (item) => STATUS_PRIORITY[getStatusLabel(item).toUpperCase()] ?? 0,
        render: (item) => (_jsx("span", { className: `px-2 py-1 rounded text-xs font-semibold whitespace-nowrap ${statusColors[item.status]}`, children: getStatusLabel(item) })),
    };
    if (moduleName === 'SSL Certificate Check') {
        return [
            indexCol,
            { key: 'target', header: 'Target Domain', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'sisa_hari', header: 'Sisa Hari', className: 'min-w-[140px] text-right', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Sisa Hari'))), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Sisa Hari')) }) },
            { key: 'expired_date', header: 'Expired Date', className: 'min-w-[180px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Expired Date')), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Expired Date')) }) },
            { key: 'detail', header: 'Detail', className: 'min-w-[220px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: getDetail(item) }) },
        ];
    }
    if (moduleName === 'SSL Certificate Hostname Mismatch') {
        return [
            indexCol,
            { key: 'target', header: 'Target Domain', className: 'min-w-[300px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: getDetail(item) }) },
        ];
    }
    if (moduleName === 'SSLv3 Detection' || moduleName === 'TLS 1.0 Detection' || moduleName === 'TLS 1.1 Detection') {
        return [
            indexCol,
            { key: 'url', header: 'URL', className: 'min-w-[360px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: getDetail(item) }) },
        ];
    }
    if (moduleName === 'Response Code Check') {
        return [
            indexCol,
            { key: 'url', header: 'URL', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            { key: 'status_code', header: 'Status Code', className: 'min-w-[150px]', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Status Code'))), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Status Code')) }) },
            { key: 'reason', header: 'Reason', className: 'min-w-[140px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Reason')), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Reason')) }) },
            { key: 'category', header: 'Category', className: 'min-w-[160px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Category')), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Category')) }) },
            { key: 'message', header: 'Message', className: 'min-w-[220px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Message')), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: normalizeCell(getRaw(item, 'Message')) }) },
        ];
    }
    if (moduleName === 'HSTS Security Check') {
        return [
            indexCol,
            { key: 'url', header: 'URL', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'details', header: 'Details', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: getDetail(item) }) },
        ];
    }
    if (moduleName === 'Security Headers Check') {
        return [
            indexCol,
            { key: 'url', header: 'URL', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            { key: 'status_code', header: 'Status Code', className: 'min-w-[150px]', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Status Code'))), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Status Code')) }) },
            { key: 'redirects', header: 'Redirects', className: 'min-w-[120px]', sortable: true, sortValue: (item) => Number(normalizeCell(getRaw(item, 'Redirects'))), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Redirects')) }) },
            { key: 'missing_headers', header: 'Missing Headers', className: 'min-w-[420px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'Missing Headers')), render: (item) => _jsx("span", { className: "text-red-300 break-words", children: normalizeCell(getRaw(item, 'Missing Headers')) }) },
            { key: 'score', header: 'Score', className: 'min-w-[100px]', sortable: true, sortValue: (item) => getScoreNumber(normalizeCell(getRaw(item, 'Score'))), render: (item) => _jsx("span", { children: normalizeCell(getRaw(item, 'Score')) }) },
        ];
    }
    if (moduleName === 'Cookie Secure Flag' || moduleName === 'Cookie HttpOnly Flag') {
        return [
            indexCol,
            { key: 'url', header: 'URL', className: 'min-w-[340px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'message', header: 'Message', className: 'min-w-[280px]', sortable: true, sortValue: (item) => normalizeCell(getRaw(item, 'message', 'Message') ?? item.details), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: normalizeCell(getRaw(item, 'message', 'Message') ?? item.details) }) },
        ];
    }
    if (moduleName === 'Laravel Debug Mode' || moduleName === 'Node.js Debug Mode') {
        return [
            indexCol,
            { key: 'target', header: 'Target Domain', className: 'min-w-[280px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'payload', header: 'Trigger / Payload', className: 'min-w-[220px]', sortable: true, sortValue: (item) => getPayload(item), render: (item) => _jsx("span", { className: "text-amber-300 font-mono break-all", children: getPayload(item) }) },
            {
                key: 'bukti_error',
                header: 'Bukti Error',
                className: 'min-w-[320px]',
                sortable: true,
                sortValue: (item) => normalizeCell(getRaw(item, 'finding', 'Finding', 'Error', 'error') ?? item.details),
                render: (item) => (_jsx("span", { className: "text-slate-200 break-words", children: normalizeCell(getRaw(item, 'finding', 'Finding', 'Error', 'error') ?? item.details) })),
            },
        ];
    }
    if (moduleName === 'PHP Version Disclosure') {
        return [
            indexCol,
            { key: 'url', header: 'URL', className: 'min-w-[340px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
            statusCol,
            { key: 'detail', header: 'Detail', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: getDetail(item) }) },
        ];
    }
    return [
        indexCol,
        { key: 'target', header: 'Target', className: 'min-w-[320px]', sortable: true, sortValue: (item) => getUrl(item), render: (item) => _jsx("span", { className: "text-slate-100 break-all", children: getUrl(item) }) },
        statusCol,
        { key: 'detail', header: 'Detail', className: 'min-w-[260px]', sortable: true, sortValue: (item) => getDetail(item), render: (item) => _jsx("span", { className: "text-slate-200 break-words", children: getDetail(item) }) },
    ];
}
export function ResultsTable({ results }) {
    const [expandedModule, setExpandedModule] = useState(null);
    const [sortByModule, setSortByModule] = useState({});
    const statusColors = {
        secure: 'text-green-400 bg-green-900/20',
        warning: 'text-yellow-400 bg-yellow-900/20',
        insecure: 'text-red-400 bg-red-900/20',
        error: 'text-slate-400 bg-slate-800/20',
        info: 'text-blue-400 bg-blue-900/20',
    };
    const getModuleSummary = (items) => {
        return items.reduce((summary, item) => {
            if (item.status === 'secure') {
                summary.secure += 1;
            }
            else if (item.status === 'info') {
                summary.secure += 1;
            }
            else if (item.status === 'warning') {
                summary.warning += 1;
            }
            else if (item.status === 'insecure') {
                summary.insecure += 1;
            }
            else if (item.status === 'error') {
                summary.error += 1;
            }
            return summary;
        }, { secure: 0, warning: 0, insecure: 0, error: 0 });
    };
    return (_jsx("div", { className: "card overflow-hidden", children: Object.entries(results).map(([moduleName, items]) => {
            const summary = getModuleSummary(items);
            const columns = getColumnsForModule(moduleName, statusColors);
            const sortState = sortByModule[moduleName];
            const sortedRows = (() => {
                const rows = items.map((item, originalIndex) => ({ item, originalIndex }));
                if (!sortState)
                    return rows;
                const col = columns.find((c) => c.key === sortState.key);
                if (!col || !col.sortable || !col.sortValue)
                    return rows;
                // Create a copy so we never mutate source results from API/state.
                return [...rows].sort((a, b) => {
                    const aVal = col.sortValue(a.item, a.originalIndex);
                    const bVal = col.sortValue(b.item, b.originalIndex);
                    return compareSortValues(aVal, bVal, sortState.direction);
                });
            })();
            const toggleSort = (col) => {
                if (!col.sortable)
                    return;
                setSortByModule((prev) => {
                    const current = prev[moduleName];
                    if (!current || current.key !== col.key) {
                        return { ...prev, [moduleName]: { key: col.key, direction: 'asc' } };
                    }
                    const nextDirection = current.direction === 'asc' ? 'desc' : 'asc';
                    return { ...prev, [moduleName]: { key: col.key, direction: nextDirection } };
                });
            };
            return (_jsxs("div", { className: "border-b border-slate-800 last:border-b-0", children: [_jsxs("button", { onClick: () => setExpandedModule(expandedModule === moduleName ? null : moduleName), className: "w-full flex items-center justify-between p-4 hover:bg-slate-800/50 transition-colors", children: [_jsxs("div", { className: "flex-1 text-left", children: [_jsx("h3", { className: "font-semibold text-slate-100", children: moduleName }), _jsxs("div", { className: "mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-400", children: [_jsxs("span", { children: [items.length, " results"] }), summary.secure > 0 && (_jsxs("span", { className: "rounded-full bg-green-900/20 px-2 py-0.5 text-xs font-semibold text-green-400", children: [summary.secure, " secure"] })), summary.warning > 0 && (_jsxs("span", { className: "rounded-full bg-yellow-900/20 px-2 py-0.5 text-xs font-semibold text-yellow-400", children: [summary.warning, " warning"] })), summary.insecure > 0 && (_jsxs("span", { className: "rounded-full bg-red-900/20 px-2 py-0.5 text-xs font-semibold text-red-400", children: [summary.insecure, " vulnerable"] })), summary.error > 0 && (_jsxs("span", { className: "rounded-full bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-300", children: [summary.error, " error"] }))] })] }), expandedModule === moduleName ? (_jsx(ChevronUp, { size: 20, className: "text-slate-500" })) : (_jsx(ChevronDown, { size: 20, className: "text-slate-500" }))] }), expandedModule === moduleName && (_jsx("div", { className: "bg-slate-800/30 p-4 border-t border-slate-800", children: _jsx("div", { className: "overflow-x-auto rounded-lg border border-slate-800", children: _jsxs("table", { className: "w-full text-sm", children: [_jsx("thead", { className: "bg-slate-900/80", children: _jsx("tr", { className: "text-left text-slate-300", children: columns.map((col, idx) => (_jsx("th", { className: `px-3 py-3 ${col.className || ''}`, children: col.sortable ? (_jsxs("button", { type: "button", onClick: () => toggleSort(col), className: "inline-flex items-center gap-1 hover:text-slate-100 transition-colors", children: [_jsx("span", { children: col.header }), sortState?.key === col.key ? (sortState.direction === 'asc' ? (_jsx(ChevronUp, { size: 14, className: "text-slate-400" })) : (_jsx(ChevronDown, { size: 14, className: "text-slate-400" }))) : (_jsx(ChevronDown, { size: 14, className: "text-slate-600" }))] })) : (col.header) }, `${moduleName}-head-${idx}`))) }) }), _jsx("tbody", { children: sortedRows.map((row, index) => (_jsx("tr", { className: "border-t border-slate-800 align-top", children: columns.map((col, colIdx) => (_jsx("td", { className: `px-3 py-3 ${col.className || ''}`, children: col.render(row.item, row.originalIndex) }, `${moduleName}-row-${index}-col-${colIdx}`))) }, row.originalIndex))) })] }) }) }))] }, moduleName));
        }) }));
}
