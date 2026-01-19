import { FileCode, AlertCircle, ShieldX, ShieldCheck, ShieldQuestion } from 'lucide-react'

/**
 * AuditTable Component
 * Displays the list of cryptographic findings from the scanner
 */
function AuditTable({ data }) {
    const getRiskBadge = (risk) => {
        const configs = {
            'CRITICAL': { class: 'status-critical border', icon: ShieldX, label: 'Critical' },
            'HIGH': { class: 'status-high border', icon: AlertCircle, label: 'High' },
            'MEDIUM': { class: 'status-medium border', icon: ShieldQuestion, label: 'Medium' },
            'LOW': { class: 'status-low border', icon: ShieldCheck, label: 'Low' },
            'UNKNOWN': { class: 'status-unknown border', icon: ShieldQuestion, label: 'Unknown' },
        }
        const config = configs[risk] || configs['UNKNOWN']
        const Icon = config.icon

        return (
            <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${config.class}`}>
                <Icon className="w-3 h-3" />
                {config.label}
            </span>
        )
    }

    const getAlgoBadge = (algo) => {
        const isQuantumSafe = ['AES-256', 'KYBER', 'DILITHIUM', 'SPHINCS'].some(
            safe => algo?.toUpperCase().includes(safe)
        )
        return (
            <span className={`px-2 py-1 rounded text-xs font-mono ${isQuantumSafe
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : 'bg-slate-700 text-slate-300'
                }`}>
                {algo}
            </span>
        )
    }

    if (data.length === 0) {
        return (
            <div className="glass-card p-6">
                <div className="flex items-center gap-3 mb-4">
                    <FileCode className="w-6 h-6 text-cyan-400" />
                    <h3 className="text-lg font-semibold">Migration Audit</h3>
                </div>
                <p className="text-slate-500 text-center py-8">
                    No cryptographic call sites found. Run the scanner to analyze your codebase.
                </p>
            </div>
        )
    }

    return (
        <div className="glass-card p-6 overflow-hidden">
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                    <FileCode className="w-6 h-6 text-cyan-400" />
                    <h3 className="text-lg font-semibold">Migration Audit</h3>
                </div>
                <span className="text-sm text-slate-400">{data.length} findings</span>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
                <table className="w-full">
                    <thead>
                        <tr className="border-b border-slate-700">
                            <th className="text-left py-3 px-2 text-slate-400 text-sm font-medium">File</th>
                            <th className="text-left py-3 px-2 text-slate-400 text-sm font-medium">Line</th>
                            <th className="text-left py-3 px-2 text-slate-400 text-sm font-medium">Algorithm</th>
                            <th className="text-left py-3 px-2 text-slate-400 text-sm font-medium">Key Size</th>
                            <th className="text-left py-3 px-2 text-slate-400 text-sm font-medium">Risk</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                        {data.slice(0, 20).map((item, index) => (
                            <tr
                                key={index}
                                className="hover:bg-slate-800/50 transition-colors"
                            >
                                <td className="py-3 px-2">
                                    <span className="text-slate-300 font-mono text-sm truncate max-w-[200px] block">
                                        {item.file?.split(/[/\\]/).pop() || 'Unknown'}
                                    </span>
                                </td>
                                <td className="py-3 px-2">
                                    <span className="text-slate-400 font-mono text-sm">
                                        :{item.line || '?'}
                                    </span>
                                </td>
                                <td className="py-3 px-2">
                                    {getAlgoBadge(item.algo)}
                                </td>
                                <td className="py-3 px-2">
                                    <span className="text-slate-300 font-mono text-sm">
                                        {item.bits !== 'Unknown' ? `${item.bits} bits` : '—'}
                                    </span>
                                </td>
                                <td className="py-3 px-2">
                                    {getRiskBadge(item.risk)}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {data.length > 20 && (
                <p className="text-center text-slate-500 text-sm mt-4">
                    Showing 20 of {data.length} findings
                </p>
            )}
        </div>
    )
}

export default AuditTable
