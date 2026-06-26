import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { MODULE_NAMES } from '../types';
export function ScanForm({ onSubmit, isLoading }) {
    const [targetsInput, setTargetsInput] = useState('');
    const [modules, setModules] = useState([]);
    const allModulesSelected = modules.length === MODULE_NAMES.length;
    const handleModuleToggle = (module) => {
        setModules(prev => prev.includes(module)
            ? prev.filter(m => m !== module)
            : [...prev, module]);
    };
    const handleToggleAllModules = () => {
        setModules(allModulesSelected ? [] : [...MODULE_NAMES]);
    };
    const handleSubmit = (e) => {
        e.preventDefault();
        const validTargets = targetsInput
            .split(/\r?\n/)
            .map(target => target.trim())
            .filter(Boolean);
        if (!validTargets.length) {
            alert('Please enter at least one target');
            return;
        }
        if (!modules.length) {
            alert('Please select at least one module');
            return;
        }
        onSubmit(validTargets, modules);
    };
    return (_jsxs("form", { onSubmit: handleSubmit, className: "space-y-6", children: [_jsxs("div", { className: "card p-6", children: [_jsx("h2", { className: "text-lg font-semibold mb-4 text-slate-100", children: "Targets" }), _jsx("textarea", { value: targetsInput, onChange: (e) => setTargetsInput(e.target.value), placeholder: ['example.com', 'https://target.tld', 'subdomain.example.org'].join('\n'), rows: 8, className: "input-field min-h-48 w-full resize-y" }), _jsx("p", { className: "mt-3 text-sm text-slate-400", children: "Enter one target per line. Empty lines will be ignored." })] }), _jsxs("div", { className: "card p-6", children: [_jsx("h2", { className: "text-lg font-semibold mb-4 text-slate-100", children: "Scan Modules" }), _jsxs("label", { className: "mb-4 flex items-center gap-3 p-3 rounded-lg bg-slate-800/40 hover:bg-slate-800/60 cursor-pointer transition-colors", children: [_jsx("input", { type: "checkbox", checked: allModulesSelected, onChange: handleToggleAllModules, className: "w-4 h-4 rounded border-slate-600 accent-blue-600" }), _jsx("span", { className: "text-sm font-medium text-slate-200", children: "Select all modules" })] }), _jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-3", children: MODULE_NAMES.map(module => (_jsxs("label", { className: "flex items-center gap-3 p-3 rounded-lg hover:bg-slate-800/50 cursor-pointer transition-colors", children: [_jsx("input", { type: "checkbox", checked: modules.includes(module), onChange: () => handleModuleToggle(module), className: "w-4 h-4 rounded border-slate-600 accent-blue-600" }), _jsx("span", { className: "text-sm text-slate-300", children: module })] }, module))) })] }), _jsx("button", { type: "submit", disabled: isLoading, className: "btn-primary w-full text-lg py-3", children: isLoading ? 'Starting scan...' : 'Start Scan' })] }));
}
