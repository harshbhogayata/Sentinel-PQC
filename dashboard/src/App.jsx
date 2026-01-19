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
      {/* Header */}
      <header className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-10 h-10 text-cyan-400" />
          <h1 className="text-3xl font-bold gradient-text">Sentinel-PQC</h1>
        </div>
        <p className="text-slate-400">Post-Quantum Cryptography Migration Dashboard</p>
      </header>

      {/* Error Banner */}
      {error && (
        <div className="glass-card p-4 mb-6 border-amber-500/30 bg-amber-500/10">
          <p className="text-amber-400">{error}</p>
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left Column - Ghost Monitor (spans 2 cols on lg) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Ghost Status Card */}
          <GhostMonitor data={ghostData} />

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="glass-card p-4">
              <p className="text-slate-400 text-sm mb-1">Total Findings</p>
              <p className="text-2xl font-bold text-white">{totalFindings}</p>
            </div>
            <div className="glass-card p-4 border-red-500/30">
              <p className="text-slate-400 text-sm mb-1">Critical</p>
              <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
            </div>
            <div className="glass-card p-4 border-amber-500/30">
              <p className="text-slate-400 text-sm mb-1">High Risk</p>
              <p className="text-2xl font-bold text-amber-400">{highCount}</p>
            </div>
            <div className="glass-card p-4 border-cyan-500/30">
              <p className="text-slate-400 text-sm mb-1">Quantum Ready</p>
              <p className="text-2xl font-bold text-cyan-400">
                {Math.round(((riskStats['LOW'] || 0) / (totalFindings || 1)) * 100)}%
              </p>
            </div>
          </div>

          {/* Audit Table */}
          <AuditTable data={cbomData} />
        </div>

        {/* Right Column - Chart & Actions */}
        <div className="space-y-6">
          {/* Risk Chart */}
          <RiskChart data={cbomData} />

          {/* Evidence Pack Action */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-3 mb-4">
              <FileText className="w-6 h-6 text-cyan-400" />
              <h3 className="text-lg font-semibold">Compliance Export</h3>
            </div>
            <p className="text-slate-400 text-sm mb-4">
              Generate a NIST-compliant evidence package for auditors and compliance teams.
            </p>
            <button
              onClick={handleDownloadEvidence}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold py-3 px-4 rounded-xl transition-all duration-300 shadow-lg shadow-cyan-500/25"
            >
              <Download className="w-5 h-5" />
              Download NIST Evidence Pack
            </button>
          </div>

          {/* Live Monitor Status */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-3 mb-4">
              <Radio className="w-6 h-6 text-emerald-400" />
              <h3 className="text-lg font-semibold">System Status</h3>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Scanner Module</span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Ghost Proxy</span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
                  Listening
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Last Scan</span>
                <span className="text-slate-300">
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
