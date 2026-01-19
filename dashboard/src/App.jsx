import { useState, useEffect } from 'react'
import { Shield, AlertTriangle, FileText, Download, Radio, Activity } from 'lucide-react'
import GhostMonitor from './components/GhostMonitor'
import RiskChart from './components/RiskChart'
import AuditTable from './components/AuditTable'
import { generateEvidencePack } from './utils/pdfGenerator'
import './App.css'

function App() {
  const [ghostData, setGhostData] = useState(null)
  const [cbomData, setCbomData] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch Ghost Report
        const ghostRes = await fetch('/data/ghost_report.json')
        if (ghostRes.ok) {
          const ghost = await ghostRes.json()
          setGhostData(ghost)
        }

        // Fetch CBOM data
        const cbomRes = await fetch('/data/cbom_output.json')
        if (cbomRes.ok) {
          const cbom = await cbomRes.json()
          setCbomData(cbom)
        }

        setLoading(false)
      } catch (err) {
        console.error('Error loading data:', err)
        setError('Failed to load data. Ensure JSON files are in public/data/')
        setLoading(false)
      }
    }

    fetchData()
  }, [])

  const handleDownloadEvidence = () => {
    try {
      generateEvidencePack(cbomData, ghostData)
    } catch (err) {
      console.error('PDF generation failed:', err)
      alert('Failed to generate PDF. Check console for details.')
    }
  }

  // Calculate risk statistics
  const riskStats = cbomData.reduce((acc, item) => {
    const risk = item.risk || 'UNKNOWN'
    acc[risk] = (acc[risk] || 0) + 1
    return acc
  }, {})

  const totalFindings = cbomData.length
  const criticalCount = riskStats['CRITICAL'] || 0
  const highCount = riskStats['HIGH'] || 0

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Activity className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading Sentinel-PQC Data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen p-6 lg:p-8">
      {/* Header - Modern SaaS Style */}
      <header className="mb-10 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <Shield className="w-6 h-6 text-blue-500" />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-white">Sentinel <span className="text-zinc-500">PQC</span></h1>
          </div>
          <p className="text-zinc-500 text-sm font-medium">Post-Quantum Cryptography Orchestration</p>
        </div>


      </header>

      {/* Error Banner */}
      {error && (
        <div className="glass-card p-4 mb-6 border-amber-500/20 bg-amber-500/5 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-500" />
          <p className="text-amber-500 text-sm font-medium">{error}</p>
        </div>
      )}

      {/* Main Grid - Bento Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left Column - Ghost Monitor (8/12) */}
        <div className="lg:col-span-8 space-y-6">
          {/* Ghost Status Card */}
          <GhostMonitor data={ghostData} />

          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="glass-card p-4">
              <p className="text-zinc-500 text-xs font-mono uppercase mb-2">Total Findings</p>
              <p className="text-2xl font-bold text-white tracking-tight">{totalFindings}</p>
            </div>
            <div className="glass-card p-4">
              <p className="text-zinc-500 text-xs font-mono uppercase mb-2">Critical</p>
              <p className="text-2xl font-bold text-red-500 tracking-tight">{criticalCount}</p>
            </div>
            <div className="glass-card p-4">
              <p className="text-zinc-500 text-xs font-mono uppercase mb-2">High Risk</p>
              <p className="text-2xl font-bold text-orange-500 tracking-tight">{highCount}</p>
            </div>
            <div className="glass-card p-4">
              <p className="text-zinc-500 text-xs font-mono uppercase mb-2">Quantum Ready</p>
              <div className="flex items-end gap-2">
                <p className="text-2xl font-bold text-emerald-500 tracking-tight">
                  {Math.round(((riskStats['LOW'] || 0) / (totalFindings || 1)) * 100)}%
                </p>
              </div>
            </div>
          </div>

          {/* Audit Table */}
          <AuditTable data={cbomData} />
        </div>

        {/* Right Column - Actions & Charts (4/12) */}
        <div className="lg:col-span-4 space-y-6">
          {/* Risk Chart */}
          <RiskChart data={cbomData} />

          {/* Evidence Pack Action */}
          <div className="glass-card p-5">
            <div className="flex items-center gap-3 mb-3">
              <FileText className="w-5 h-5 text-blue-500" />
              <h3 className="text-sm font-semibold text-white">Compliance Export</h3>
            </div>
            <p className="text-zinc-400 text-xs leading-relaxed mb-4">
              Generate a specific NIST-compliant evidence package for auditing and compliance verification.
            </p>
            <button
              onClick={handleDownloadEvidence}
              className="w-full btn-primary flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg text-sm font-medium"
            >
              <Download className="w-4 h-4" />
              Download Evidence Pack
            </button>
          </div>

          {/* Live Monitor Status - Compact */}
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-white mb-4">System Components</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-zinc-500">Scanner Module</span>
                <span className="status-pill bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
                  <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></span>
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-zinc-500">Ghost Proxy</span>
                <span className="status-pill bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
                  <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
                  Listening
                </span>
              </div>
              <div className="pt-3 border-t border-zinc-800 flex items-center justify-between text-xs">
                <span className="text-zinc-600">Last Scan</span>
                <span className="text-zinc-400 font-mono">
                  {ghostData?.timestamp ? new Date(ghostData.timestamp).toLocaleTimeString() : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="mt-12 text-center text-slate-500 text-sm">
        <p>Sentinel-PQC • Post-Quantum Cryptography Orchestration Platform</p>
      </footer>
    </div>
  )
}

export default App
