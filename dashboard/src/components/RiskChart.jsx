import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts'
import { ShieldAlert, ShieldCheck } from 'lucide-react'

/**
 * RiskChart Component
 * Donut chart showing distribution of crypto risk levels
 */
function RiskChart({ data }) {
    // Aggregate risk counts
    const riskCounts = data.reduce((acc, item) => {
        const risk = item.risk || 'UNKNOWN'
        acc[risk] = (acc[risk] || 0) + 1
        return acc
    }, {})

    // Transform for Recharts
    const chartData = [
        { name: 'Critical', value: riskCounts['CRITICAL'] || 0, color: '#ef4444' },
        { name: 'High', value: riskCounts['HIGH'] || 0, color: '#f59e0b' },
        { name: 'Medium', value: riskCounts['MEDIUM'] || 0, color: '#3b82f6' },
        { name: 'Low', value: riskCounts['LOW'] || 0, color: '#10b981' },
        { name: 'Unknown', value: riskCounts['UNKNOWN'] || 0, color: '#6b7280' },
    ].filter(item => item.value > 0)

    // Calculate quantum vulnerability percentage
    const totalFindings = data.length
    const vulnerableCount = (riskCounts['CRITICAL'] || 0) + (riskCounts['HIGH'] || 0)
    const vulnerabilityPercent = totalFindings > 0
        ? Math.round((vulnerableCount / totalFindings) * 100)
        : 0

    const CustomTooltip = ({ active, payload }) => {
        if (active && payload && payload.length) {
            const item = payload[0]
            return (
                <div className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 shadow-xl">
                    <p className="text-white font-semibold">{item.name}</p>
                    <p className="text-slate-300">{item.value} finding{item.value !== 1 ? 's' : ''}</p>
                </div>
            )
        }
        return null
    }

    if (data.length === 0) {
        return (
            <div className="glass-card p-6">
                <div className="flex items-center gap-3 mb-4">
                    <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    <h3 className="text-lg font-semibold">Risk Analysis</h3>
                </div>
                <p className="text-slate-500 text-center py-8">No cryptographic findings to analyze.</p>
            </div>
        )
    }

    return (
        <div className="glass-card p-6">
            <div className="flex items-center gap-3 mb-4">
                <ShieldAlert className="w-6 h-6 text-amber-400" />
                <h3 className="text-lg font-semibold">Risk Distribution</h3>
            </div>

            {/* Chart */}
            <div className="h-64 relative">
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                        <Pie
                            data={chartData}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={90}
                            paddingAngle={2}
                            dataKey="value"
                            stroke="none"
                        >
                            {chartData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                        </Pie>
                        <Tooltip content={<CustomTooltip />} />
                    </PieChart>
                </ResponsiveContainer>

                {/* Center Label */}
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                    <div className="text-center">
                        <p className={`text-3xl font-bold ${vulnerabilityPercent > 50 ? 'text-red-400' : 'text-cyan-400'}`}>
                            {vulnerabilityPercent}%
                        </p>
                        <p className="text-xs text-slate-400">Vulnerable</p>
                    </div>
                </div>
            </div>

            {/* Legend */}
            <div className="flex flex-wrap justify-center gap-3 mt-4">
                {chartData.map((item, index) => (
                    <div key={index} className="flex items-center gap-2">
                        <span
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: item.color }}
                        />
                        <span className="text-sm text-slate-400">{item.name}: {item.value}</span>
                    </div>
                ))}
            </div>
        </div>
    )
}

export default RiskChart
