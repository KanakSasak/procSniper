import { useState, useEffect } from 'react'
import { Save, RotateCcw, Plus, X, Loader2, Settings, Shield, FileSearch, List } from 'lucide-react'
import { useConfiguration } from '../hooks/useWails'
import type { Config } from '../types'

function Configuration() {
  const { config, loading, saving, error, saveConfig } = useConfiguration()
  const [editedConfig, setEditedConfig] = useState<Config | null>(null)
  const [activeTab, setActiveTab] = useState<'thresholds' | 'response' | 'whitelist' | 'extensions'>('thresholds')
  const [newPath, setNewPath] = useState('')
  const [newProcess, setNewProcess] = useState('')
  const [newExtension, setNewExtension] = useState('')
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  useEffect(() => {
    if (config) {
      setEditedConfig(JSON.parse(JSON.stringify(config)))
    }
  }, [config])

  const handleSave = async () => {
    if (!editedConfig) return

    const result = await saveConfig(editedConfig)
    if (result.success) {
      setSaveMessage({ type: 'success', message: 'Configuration saved successfully!' })
    } else {
      setSaveMessage({ type: 'error', message: result.message })
    }
    setTimeout(() => setSaveMessage(null), 3000)
  }

  const handleReset = () => {
    if (config) {
      setEditedConfig(JSON.parse(JSON.stringify(config)))
    }
  }

  const addPath = () => {
    if (!editedConfig || !newPath.trim()) return
    setEditedConfig({
      ...editedConfig,
      whitelist: {
        ...editedConfig.whitelist,
        paths: [...editedConfig.whitelist.paths, newPath.trim()],
      },
    })
    setNewPath('')
  }

  const removePath = (index: number) => {
    if (!editedConfig) return
    setEditedConfig({
      ...editedConfig,
      whitelist: {
        ...editedConfig.whitelist,
        paths: editedConfig.whitelist.paths.filter((_, i) => i !== index),
      },
    })
  }

  const addProcess = () => {
    if (!editedConfig || !newProcess.trim()) return
    setEditedConfig({
      ...editedConfig,
      whitelist: {
        ...editedConfig.whitelist,
        processes: [...(editedConfig.whitelist.processes || []), newProcess.trim()],
      },
    })
    setNewProcess('')
  }

  const removeProcess = (index: number) => {
    if (!editedConfig) return
    setEditedConfig({
      ...editedConfig,
      whitelist: {
        ...editedConfig.whitelist,
        processes: (editedConfig.whitelist.processes || []).filter((_, i) => i !== index),
      },
    })
  }

  const addExtension = () => {
    if (!editedConfig || !newExtension.trim()) return
    const ext = newExtension.trim().toLowerCase()
    if (!ext.startsWith('.')) {
      setEditedConfig({
        ...editedConfig,
        ransomwareExtensions: [...editedConfig.ransomwareExtensions, '.' + ext],
      })
    } else {
      setEditedConfig({
        ...editedConfig,
        ransomwareExtensions: [...editedConfig.ransomwareExtensions, ext],
      })
    }
    setNewExtension('')
  }

  const removeExtension = (index: number) => {
    if (!editedConfig) return
    setEditedConfig({
      ...editedConfig,
      ransomwareExtensions: editedConfig.ransomwareExtensions.filter((_, i) => i !== index),
    })
  }

  if (loading || !editedConfig) {
    return (
      <div className="p-8 flex items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin text-ps-primary" />
      </div>
    )
  }

  const tabs = [
    { id: 'thresholds', label: 'Detection Thresholds', icon: FileSearch },
    { id: 'response', label: 'Response Settings', icon: Shield },
    { id: 'whitelist', label: 'Whitelist', icon: List },
    { id: 'extensions', label: 'Extensions', icon: Settings },
  ] as const

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold mb-2">Configuration</h1>
          <p className="text-gray-400">
            Version {editedConfig.version} - Last updated: {editedConfig.lastUpdated}
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-2 bg-ps-accent rounded-lg hover:bg-ps-accent/80 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            Reset
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 bg-ps-primary rounded-lg hover:bg-ps-primary/80 transition-colors disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save Changes
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="mb-4 p-4 bg-red-500/20 border border-red-500/50 rounded-lg text-red-300">
          {error}
        </div>
      )}
      {saveMessage && (
        <div className={`mb-4 p-4 rounded-lg ${
          saveMessage.type === 'success'
            ? 'bg-green-500/20 border border-green-500/50 text-green-300'
            : 'bg-red-500/20 border border-red-500/50 text-red-300'
        }`}>
          {saveMessage.message}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-ps-accent/30 pb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
              activeTab === tab.id
                ? 'bg-ps-primary text-white'
                : 'bg-ps-accent/30 text-gray-400 hover:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
        {activeTab === 'thresholds' && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold mb-4">Detection Thresholds</h3>

            <SliderInput
              label="High Entropy File Threshold"
              description="Number of high entropy files before adding entropy indicator"
              value={editedConfig.detectionThresholds.highEntropyFileThreshold}
              min={1}
              max={50}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  detectionThresholds: { ...editedConfig.detectionThresholds, highEntropyFileThreshold: value },
                })
              }
            />

            <SliderInput
              label="Ransomware Extension Threshold"
              description="Number of ransomware extension files before adding extension indicator"
              value={editedConfig.detectionThresholds.ransomwareExtensionFileThreshold}
              min={1}
              max={20}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  detectionThresholds: { ...editedConfig.detectionThresholds, ransomwareExtensionFileThreshold: value },
                })
              }
            />

            <SliderInput
              label="Rename to Ransomware Extension Threshold"
              description="Number of renames to ransomware extensions in 60s before immediate termination"
              value={editedConfig.detectionThresholds.ransomwareExtensionRenameThreshold}
              min={1}
              max={20}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  detectionThresholds: { ...editedConfig.detectionThresholds, ransomwareExtensionRenameThreshold: value },
                })
              }
            />

            <SliderInput
              label="Combined Threshold (Immediate Termination)"
              description="Files with BOTH high entropy AND ransomware extension before immediate termination"
              value={editedConfig.detectionThresholds.combinedEntropyAndExtensionThreshold}
              min={1}
              max={10}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  detectionThresholds: { ...editedConfig.detectionThresholds, combinedEntropyAndExtensionThreshold: value },
                })
              }
            />

            <SliderInput
              label="I/O Velocity Threshold (files/min)"
              description="File operations per minute that trigger critical velocity detection tier"
              value={editedConfig.detectionThresholds.ioVelocityThresholdPerMinute}
              min={10}
              max={500}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  detectionThresholds: { ...editedConfig.detectionThresholds, ioVelocityThresholdPerMinute: value },
                })
              }
            />
          </div>
        )}

        {activeTab === 'response' && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold mb-4">Response Settings</h3>

            <ToggleInput
              label="Auto-Terminate Enabled"
              description="Automatically terminate processes that exceed critical score threshold"
              value={editedConfig.responseSettings.autoTerminateEnabled}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, autoTerminateEnabled: value },
                })
              }
            />

            <SliderInput
              label="Critical Score Threshold"
              description="Threat score threshold for auto-termination"
              value={editedConfig.responseSettings.criticalScoreThreshold}
              min={20}
              max={100}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, criticalScoreThreshold: value },
                })
              }
            />

            <ToggleInput
              label="Immediate Response"
              description="Respond immediately upon detection without waiting for further indicators"
              value={editedConfig.responseSettings.immediateResponse}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, immediateResponse: value },
                })
              }
            />

            <ToggleInput
              label="Terminate on Extension Match"
              description="Kill process immediately when ransomware file extension is detected"
              value={editedConfig.responseSettings.terminateOnExtensionMatch}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, terminateOnExtensionMatch: value },
                })
              }
            />

            <ToggleInput
              label="Suspend Before Terminate"
              description="Suspend process threads before termination for forensic preservation"
              value={editedConfig.responseSettings.suspendBeforeTerminate}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, suspendBeforeTerminate: value },
                })
              }
            />

            <ToggleInput
              label="Investigation Mode"
              description="Disable auto-termination for investigation purposes (alerts only)"
              value={editedConfig.responseSettings.investigationMode}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, investigationMode: value },
                })
              }
            />

            <ToggleInput
              label="Quarantine Files"
              description="Move suspicious files to quarantine directory"
              value={editedConfig.responseSettings.quarantineFiles}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, quarantineFiles: value },
                })
              }
            />

            <TextInput
              label="Quarantine Directory"
              value={editedConfig.responseSettings.quarantineDirectory}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, quarantineDirectory: value },
                })
              }
            />

            <SelectInput
              label="Detection Mode"
              description="How threats are detected: rules only, ML only, or both combined"
              value={editedConfig.responseSettings.detectionMode || 'rules_only'}
              options={[
                { value: 'rules_only', label: 'Rules Only' },
                { value: 'hybrid', label: 'Hybrid (Rules + ML)' },
                { value: 'ml_only', label: 'ML Only' },
              ]}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, detectionMode: value },
                })
              }
            />

            <SelectInput
              label="Canary Response Action"
              description="Action taken when a canary (honeypot) file is compromised"
              value={editedConfig.responseSettings.canaryResponseAction || 'terminate'}
              options={[
                { value: 'terminate', label: 'Terminate (Default)' },
                { value: 'suspend', label: 'Suspend Only' },
                { value: 'alert_only', label: 'Alert Only' },
              ]}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  responseSettings: { ...editedConfig.responseSettings, canaryResponseAction: value },
                })
              }
            />
          </div>
        )}

        {activeTab === 'whitelist' && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold mb-4">Whitelist Configuration</h3>

            <ToggleInput
              label="Whitelist Enabled"
              description="Enable whitelisting to exclude specific paths from detection"
              value={editedConfig.whitelist.enabled}
              onChange={(value) =>
                setEditedConfig({
                  ...editedConfig,
                  whitelist: { ...editedConfig.whitelist, enabled: value },
                })
              }
            />

            {/* Path Whitelist */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Whitelisted Paths</label>
              <div className="flex gap-2 mb-4">
                <input
                  type="text"
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  placeholder="Enter path to whitelist..."
                  className="flex-1 px-4 py-2 bg-ps-accent/30 border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary"
                  onKeyDown={(e) => e.key === 'Enter' && addPath()}
                />
                <button
                  onClick={addPath}
                  className="flex items-center gap-2 px-4 py-2 bg-ps-primary rounded-lg hover:bg-ps-primary/80 transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  Add
                </button>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {editedConfig.whitelist.paths.map((path, index) => (
                  <div key={index} className="flex items-center justify-between bg-ps-accent/20 px-4 py-2 rounded-lg">
                    <span className="text-sm font-mono">{path}</span>
                    <button
                      onClick={() => removePath(index)}
                      className="text-red-400 hover:text-red-300"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))}
                {editedConfig.whitelist.paths.length === 0 && (
                  <p className="text-gray-500 text-center py-4">No whitelisted paths</p>
                )}
              </div>
            </div>

            {/* Process Whitelist */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Whitelisted Processes</label>
              <p className="text-xs text-gray-500 mb-3">
                Processes in this list are always excluded from auto-termination, regardless of path whitelist setting.
              </p>
              <div className="flex gap-2 mb-4">
                <input
                  type="text"
                  value={newProcess}
                  onChange={(e) => setNewProcess(e.target.value)}
                  placeholder="Enter process name (e.g., SearchProtocolHost.exe)"
                  className="flex-1 px-4 py-2 bg-ps-accent/30 border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary"
                  onKeyDown={(e) => e.key === 'Enter' && addProcess()}
                />
                <button
                  onClick={addProcess}
                  className="flex items-center gap-2 px-4 py-2 bg-ps-primary rounded-lg hover:bg-ps-primary/80 transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  Add
                </button>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {(editedConfig.whitelist.processes || []).map((proc, index) => (
                  <div key={index} className="flex items-center justify-between bg-ps-accent/20 px-4 py-2 rounded-lg">
                    <span className="text-sm font-mono">{proc}</span>
                    <button
                      onClick={() => removeProcess(index)}
                      className="text-red-400 hover:text-red-300"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))}
                {(!editedConfig.whitelist.processes || editedConfig.whitelist.processes.length === 0) && (
                  <p className="text-gray-500 text-center py-4">No whitelisted processes</p>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'extensions' && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold mb-4">
              Ransomware Extensions ({editedConfig.ransomwareExtensions.length})
            </h3>

            <div className="flex gap-2 mb-4">
              <input
                type="text"
                value={newExtension}
                onChange={(e) => setNewExtension(e.target.value)}
                placeholder="Enter extension (e.g., .locked)"
                className="flex-1 px-4 py-2 bg-ps-accent/30 border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary"
                onKeyDown={(e) => e.key === 'Enter' && addExtension()}
              />
              <button
                onClick={addExtension}
                className="flex items-center gap-2 px-4 py-2 bg-ps-primary rounded-lg hover:bg-ps-primary/80 transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add
              </button>
            </div>

            <div className="flex flex-wrap gap-2 max-h-64 overflow-y-auto">
              {editedConfig.ransomwareExtensions.map((ext, index) => (
                <div
                  key={index}
                  className="flex items-center gap-2 bg-ps-accent/30 px-3 py-1 rounded-full"
                >
                  <span className="text-sm font-mono">{ext}</span>
                  <button
                    onClick={() => removeExtension(index)}
                    className="text-red-400 hover:text-red-300"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

interface SliderInputProps {
  label: string
  description: string
  value: number
  min: number
  max: number
  onChange: (value: number) => void
}

function SliderInput({ label, description, value, min, max, onChange }: SliderInputProps) {
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="block text-sm font-medium text-gray-300">{label}</label>
        <span className="text-ps-primary font-bold">{value}</span>
      </div>
      <p className="text-xs text-gray-500 mb-2">{description}</p>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(parseInt(e.target.value))}
        className="w-full h-2 bg-ps-accent rounded-lg appearance-none cursor-pointer accent-ps-primary"
      />
      <div className="flex justify-between text-xs text-gray-500 mt-1">
        <span>{min}</span>
        <span>{max}</span>
      </div>
    </div>
  )
}

interface ToggleInputProps {
  label: string
  description: string
  value: boolean
  onChange: (value: boolean) => void
}

function ToggleInput({ label, description, value, onChange }: ToggleInputProps) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <label className="block text-sm font-medium text-gray-300">{label}</label>
        <p className="text-xs text-gray-500">{description}</p>
      </div>
      <button
        onClick={() => onChange(!value)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
          value ? 'bg-ps-primary' : 'bg-ps-accent'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            value ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  )
}

interface TextInputProps {
  label: string
  value: string
  onChange: (value: string) => void
}

function TextInput({ label, value, onChange }: TextInputProps) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-300 mb-2">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-4 py-2 bg-ps-accent/30 border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary"
      />
    </div>
  )
}

interface SelectOption {
  value: string
  label: string
}

interface SelectInputProps {
  label: string
  description: string
  value: string
  options: SelectOption[]
  onChange: (value: string) => void
}

function SelectInput({ label, description, value, options, onChange }: SelectInputProps) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-300 mb-1">{label}</label>
      <p className="text-xs text-gray-500 mb-2">{description}</p>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-4 py-2 bg-ps-accent/30 border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary text-white"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  )
}

export default Configuration
