import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { CheckCircle, AlertCircle, XCircle, HelpCircle } from 'lucide-react';
export function SummaryCards({ totals }) {
    const cards = [
        {
            label: 'Secure domains',
            value: totals.secure,
            icon: CheckCircle,
            color: 'text-green-400',
            bg: 'bg-green-900/10',
        },
        {
            label: 'Warning domains',
            value: totals.warning,
            icon: AlertCircle,
            color: 'text-yellow-400',
            bg: 'bg-yellow-900/10',
        },
        {
            label: 'Vulnerable domains',
            value: totals.insecure,
            icon: XCircle,
            color: 'text-red-400',
            bg: 'bg-red-900/10',
        },
        {
            label: 'Error domains',
            value: totals.error,
            icon: HelpCircle,
            color: 'text-slate-400',
            bg: 'bg-slate-800/20',
        },
    ];
    return (_jsxs("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4", children: [cards.map(({ label, value, icon: Icon, color, bg }) => (_jsx("div", { className: `card p-6 ${bg}`, children: _jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("div", { children: [_jsx("p", { className: "text-slate-400 text-sm", children: label }), _jsx("p", { className: "text-3xl font-bold mt-1", children: value })] }), _jsx(Icon, { className: `${color}`, size: 32 })] }) }, label))), _jsx("div", { className: "col-span-1 md:col-span-2 lg:col-span-4", children: _jsx("div", { className: "card p-4 bg-slate-800/50", children: _jsxs("p", { className: "text-center text-slate-400 text-sm", children: ["Total domains scanned: ", _jsx("span", { className: "font-semibold text-slate-100", children: totals.items })] }) }) })] }));
}
