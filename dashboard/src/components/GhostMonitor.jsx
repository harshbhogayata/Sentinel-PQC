import { AlertTriangle, CheckCircle, Wifi, WifiOff } from 'lucide-react'

/**
 * GhostMonitor Component
 * Displays the network fragmentation risk status from the PQC Proxy
 */
function GhostMonitor({ data }) {
    if (!data) {
        return (
            <div className="glass-card p-6 border-slate-700">
                <div className="flex items-center gap-3 mb-4">
                    <WifiOff className="w-6 h-6 text-slate-500" />
                    <h2 className="text-lg font-semibold text-slate-400">Ghost Monitor</h2>
                </div>
                <p className="text-slate-500">No ghost report data available. Run the PQC Proxy to generate data.</p>
            </div>
        )
    }

    const isRisk = data.fragmentation_risk
    const handshakeSize = data.handshake_size_bytes || 0
    const safeMTU = 1400
    const percentage = Math.min((handshakeSize / safeMTU) * 100, 150)

    return (
        <div className={`glass-card p-6 ${isRisk ? 'border-red-500/50 pulse-critical' : 'border-emerald-500/50'}`}>
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    {isRisk ? (
                        <AlertTriangle className="w-8 h-8 text-red-400" />
                    ) : (
                        <CheckCircle className="w-8 h-8 text-emerald-400" />
                    )}
                    <div>
                        <h2 className="text-xl font-bold">
                            {isRisk ? 'MTU Fragmentation Risk Detected' : 'Network Status: Safe'}
                        </h2>
                        <p className="text-sm text-slate-400">{data.algorithm || 'Kyber-768'} Key Exchange</p>
                    </div>
                </div>
                <span className={`px-4 py-2 rounded-full text-sm font-semibold border ${isRisk ? 'status-critical' : 'status-low'
                    }`}>
                    {data.status || (isRisk ? 'CRITICAL' : 'SAFE')}
                </span>
            </div>

            {/* Progress Bar */}
            <div className="mb-6">
                <div className="flex justify-between text-sm mb-2">
                    <span className="text-slate-400">Handshake Size</span>
                    <span className={isRisk ? 'text-red-400' : 'text-emerald-400'}>
                        {handshakeSize} / {safeMTU} bytes
                    </span>
                </div>
                <div className="h-4 bg-slate-800 rounded-full overflow-hidden">
                    <div
                        className={`h-full rounded-full transition-all duration-500 ${isRisk
                                ? 'bg-gradient-to-r from-red-500 to-orange-500'
                                : 'bg-gradient-to-r from-emerald-500 to-cyan-500'
                            }`}
                        style={{ width: `${Math.min(percentage, 100)}%` }}
                    />
                </div>
                {percentage > 100 && (
                    <p className="text-red-400 text-sm mt-2">
                        ⚠️ Exceeds safe MTU by {handshakeSize - safeMTU} bytes ({(percentage - 100).toFixed(0)}% over limit)
                    </p>
                )}
            </div>

            {/* Details Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-800/50 rounded-xl p-3">
                    <p className="text-slate-400 text-xs mb-1">Public Key</p>
                    <p className="text-lg font-semibold">{data.public_key_size || 1184}B</p>
                </div>
                <div className="bg-slate-800/50 rounded-xl p-3">
                    <p className="text-slate-400 text-xs mb-1">Total Size</p>
                    <p className="text-lg font-semibold">{handshakeSize}B</p>
                </div>
                <div className="bg-slate-800/50 rounded-xl p-3">
                    <p className="text-slate-400 text-xs mb-1">Safe Limit</p>
                    <p className="text-lg font-semibold">{safeMTU}B</p>
                </div>
                <div className="bg-slate-800/50 rounded-xl p-3">
                    <p className="text-slate-400 text-xs mb-1">Client</p>
                    <p className="text-lg font-semibold truncate">{data.client_ip?.split(':')[0] || 'N/A'}</p>
                </div>
            </div>

            {/* Warning Message */}
            {isRisk && (
                <div className="mt-6 p-4 bg-red-500/10 border border-red-500/30 rounded-xl">
                    <p className="text-red-300 text-sm">
                        <strong>⚠️ Ghost Incompatibility:</strong> {data.message || 'Large PQC keys will cause packet fragmentation on legacy networks. This may result in silent connection failures.'}
                    </p>
                </div>
            )}
        </div>
    )
}

export default GhostMonitor
