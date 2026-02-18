import { useState } from 'react'
import { Brain, Upload, Trash2, Info, ToggleLeft, ToggleRight, Sliders, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useMLModel } from '../hooks/useWails'

function MLDetection() {
  const { status, loading, predictions, selectAndLoadModel, unloadModel, setEnabled, setThreshold } = useMLModel()
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text })
    setTimeout(() => setMessage(null), 3000)
  }

  const handleLoadModel = async () => {
    const result = await selectAndLoadModel()
    if (result.success) {
      showMessage('success', result.message)
    } else if (result.message !== 'No file selected') {
      showMessage('error', result.message)
    }
  }

  const handleUnloadModel = async () => {
    const result = await unloadModel()
    if (result.success) {
      showMessage('success', result.message)
    } else {
      showMessage('error', result.message)
    }
  }

  const handleToggleEnabled = async () => {
    const result = await setEnabled(!status.enabled)
    if (!result.success) {
      showMessage('error', result.message)
    }
  }

  const handleThresholdChange = async (value: number) => {
    await setThreshold(value / 100)
  }

  const getLabelColor = (label: string) => {
    switch (label) {
      case 'ransomware': return 'text-red-400'
      case 'stealer': return 'text-orange-400'
      case 'benign': return 'text-green-400'
      default: return 'text-gray-400'
    }
  }

  const getLabelBg = (label: string) => {
    switch (label) {
      case 'ransomware': return 'bg-red-500/20 border-red-500/40'
      case 'stealer': return 'bg-orange-500/20 border-orange-500/40'
      case 'benign': return 'bg-green-500/20 border-green-500/40'
      default: return 'bg-gray-500/20 border-gray-500/40'
    }
  }

  const getStageColor = (stage: string) => {
    switch (stage) {
      case 'decision': return 'text-red-300'
      case 'error': return 'text-red-400'
      case 'predicted': return 'text-green-300'
      case 'skipped': return 'text-yellow-300'
      default: return 'text-gray-400'
    }
  }

  const formatDecision = (decision: string) => {
    switch (decision) {
      case 'terminate_eligible': return 'terminate-eligible'
      case 'alert_only': return 'alert-only'
      case 'none': return 'no decision'
      default: return decision || 'n/a'
    }
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Brain className="w-8 h-8 text-ps-primary" />
          <h1 className="text-3xl font-bold">ML Detection</h1>
        </div>
        <p className="text-gray-400">Machine learning-based threat detection using behavioral analysis</p>
      </div>

      {/* Message */}
      {message && (
        <div
          className={`mb-6 p-4 rounded-lg ${
            message.type === 'success'
              ? 'bg-green-500/20 border border-green-500/50 text-green-300'
              : 'bg-red-500/20 border border-red-500/50 text-red-300'
          }`}
        >
          {message.text}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column */}
        <div className="space-y-6">
          {/* Model Status Card */}
          <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Upload className="w-5 h-5 text-ps-primary" />
              Model Status
            </h3>

            {!status.loaded ? (
              <div className="text-center py-8">
                <Brain className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <h4 className="text-lg font-medium text-gray-400 mb-2">No Model Loaded</h4>
                <p className="text-sm text-gray-500 mb-6">
                  Load an ONNX model to enable ML-based detection.
                  <br />
                  Supported format: ONNX (Random Forest, 14 features)
                </p>
                <button
                  onClick={handleLoadModel}
                  disabled={loading}
                  className="flex items-center gap-2 px-6 py-3 bg-ps-primary rounded-lg hover:bg-ps-primary/80 transition-colors mx-auto disabled:opacity-50"
                >
                  <Upload className="w-4 h-4" />
                  {loading ? 'Loading...' : 'Load Model'}
                </button>
              </div>
            ) : (
              <div>
                <div className="space-y-3 mb-6">
                  <InfoRow label="Model Name" value={status.modelName} />
                  <InfoRow label="Model Type" value={status.modelType} />
                  <InfoRow label="File Path" value={status.filePath} mono />
                  <InfoRow label="Loaded At" value={new Date(status.loadedAt).toLocaleString()} />
                  <InfoRow label="Features" value={String(status.featureCount)} />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={handleLoadModel}
                    disabled={loading}
                    className="flex items-center gap-2 px-4 py-2 bg-ps-accent rounded-lg hover:bg-ps-accent/80 transition-colors disabled:opacity-50"
                  >
                    <Upload className="w-4 h-4" />
                    Load Different
                  </button>
                  <button
                    onClick={handleUnloadModel}
                    className="flex items-center gap-2 px-4 py-2 bg-red-600/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-600/30 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                    Unload
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* ML Detection Toggle */}
          <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              {status.enabled ? (
                <ToggleRight className="w-5 h-5 text-green-400" />
              ) : (
                <ToggleLeft className="w-5 h-5 text-gray-400" />
              )}
              ML Detection
            </h3>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Enable ML-based detection</p>
                <p className="text-xs text-gray-500">
                  {status.loaded
                    ? 'Run ML inference as the primary decision engine (ML-only mode)'
                    : 'Load a model first to enable ML detection'}
                </p>
              </div>
              <button
                onClick={handleToggleEnabled}
                disabled={!status.loaded}
                className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors ${
                  status.enabled ? 'bg-green-500' : 'bg-ps-accent'
                } ${!status.loaded ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <span
                  className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${
                    status.enabled ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
            {status.enabled && (
              <div className="mt-3 px-3 py-2 bg-green-500/10 border border-green-500/30 rounded-lg">
                <p className="text-xs text-green-400">ML detection is active — predictions will appear in Detection Results</p>
              </div>
            )}
          </div>

          {/* Feature List */}
          <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Info className="w-5 h-5 text-ps-primary" />
              Behavioral Features (14)
            </h3>
            <p className="text-xs text-gray-500 mb-4">
              Features extracted from process behavior for ML analysis:
            </p>
            <div className="space-y-2">
              {[
                { name: 'velocity', desc: 'File operations per minute (60s window)' },
                { name: 'file_count', desc: 'Total files created + modified' },
                { name: 'txt_file_count', desc: 'Number of .txt files created (ransom notes)' },
                { name: 'directory_count', desc: 'Unique directories touched by process' },
                { name: 'file_delete_count', desc: 'Total file deletions by process' },
                { name: 'is_signed', desc: 'Whether the executable is code-signed' },
                { name: 'extension_match', desc: 'Ratio of ransomware extension hits' },
                { name: 'extension_entropy', desc: 'Shannon entropy of extension distribution' },
                { name: 'shadow_copy_delete', desc: 'VSS shadow copy deletion detected' },
                { name: 'browser_credential_access', desc: 'Browser credential file access' },
                { name: 'browser_history_access', desc: 'Browser history file access' },
                { name: 'ssh_key_access', desc: 'SSH key file access (.ssh/)' },
                { name: 'lsass_access', desc: 'LSASS process memory access' },
                { name: 'system_info_queries', desc: 'System reconnaissance commands' },
              ].map((feature) => (
                <div key={feature.name} className="flex items-center justify-between py-2 border-b border-ps-accent/20 last:border-0">
                  <span className="text-sm font-mono text-ps-primary">{feature.name}</span>
                  <span className="text-xs text-gray-500 text-right max-w-[55%]">{feature.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Confidence Threshold */}
          <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Sliders className="w-5 h-5 text-ps-primary" />
              Confidence Threshold
            </h3>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-300">Minimum confidence for detection</span>
              <span className="text-ps-primary font-bold">
                {Math.round(status.confidenceThreshold * 100)}%
              </span>
            </div>
            <p className="text-xs text-gray-500 mb-3">
              Higher threshold reduces false positives but may miss subtle threats
            </p>
            <input
              type="range"
              min={10}
              max={100}
              step={5}
              value={Math.round(status.confidenceThreshold * 100)}
              onChange={(e) => handleThresholdChange(parseInt(e.target.value))}
              disabled={!status.loaded}
              className="w-full h-2 bg-ps-accent rounded-lg appearance-none cursor-pointer accent-ps-primary disabled:opacity-50"
            />
            <div className="flex justify-between text-xs text-gray-500 mt-1">
              <span>10% (Sensitive)</span>
              <span>100% (Strict)</span>
            </div>
          </div>

          {/* ML Detection Results */}
          <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-ps-primary" />
              Detection Results
              {predictions.length > 0 && (
                <span className="ml-auto text-xs text-gray-500">{predictions.length} predictions</span>
              )}
            </h3>

            {!status.enabled ? (
              <div className="flex items-start gap-3 p-4 bg-ps-accent/20 rounded-lg">
                <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-gray-300 mb-2">
                    ML detection will analyze process behavior patterns using the loaded model.
                  </p>
                  <p className="text-xs text-gray-500">
                    Load a model and enable detection to see real-time inference results.
                  </p>
                </div>
              </div>
            ) : predictions.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <ShieldCheck className="w-12 h-12 mx-auto mb-3 text-gray-600" />
                <p className="text-sm">Waiting for process activity...</p>
                <p className="text-xs text-gray-600 mt-1">All ML attempts (decision, skipped, benign, errors) appear here in real time</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto">
                {predictions.map((pred, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border ${getLabelBg(pred.label)}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        {pred.label !== 'benign' ? (
                          <ShieldAlert className={`w-4 h-4 ${getLabelColor(pred.label)}`} />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-green-400" />
                        )}
                        <span className="text-sm font-medium truncate max-w-[200px]">{pred.processName}</span>
                        <span className="text-xs text-gray-500">PID {pred.processId}</span>
                      </div>
                      <span className={`text-xs font-bold uppercase ${getLabelColor(pred.label)}`}>
                        {pred.label}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className={getStageColor(pred.stage)}>stage: {pred.stage || 'unknown'}</span>
                      <span className="text-gray-400">reason: {pred.reason || 'n/a'}</span>
                    </div>
                    <div className="text-xs text-gray-500 mb-1">
                      <span>decision: {formatDecision(pred.decision)}</span>
                      <span className="mx-2">|</span>
                      <span>score: {pred.decisionScore ?? 0}</span>
                      <span className="mx-2">|</span>
                      <span>auto-response: {pred.decisionAutoRespond ? 'yes' : 'no'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex gap-3 text-xs text-gray-500">
                        <span>B: {((pred.probabilities?.[0] ?? 0) * 100).toFixed(1)}%</span>
                        <span>R: {((pred.probabilities?.[1] ?? 0) * 100).toFixed(1)}%</span>
                        <span>S: {((pred.probabilities?.[2] ?? 0) * 100).toFixed(1)}%</span>
                        <span>T: {((pred.threshold ?? 0) * 100).toFixed(0)}%</span>
                      </div>
                      <span className="text-xs text-gray-600">
                        {new Date(pred.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    {pred.error && (
                      <div className="text-xs text-red-400 mt-1 truncate">
                        error: {pred.error}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

interface InfoRowProps {
  label: string
  value: string
  mono?: boolean
}

function InfoRow({ label, value, mono }: InfoRowProps) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-gray-500">{label}</span>
      <span className={`text-sm ${mono ? 'font-mono text-xs' : ''} truncate max-w-[60%] text-right`}>
        {value}
      </span>
    </div>
  )
}

export default MLDetection
