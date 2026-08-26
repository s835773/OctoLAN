import React, { useState } from 'react';
import { INITIAL_ALERT_RULES, INITIAL_ALERT_EVENTS, DEFAULT_ALERT_CONFIG } from '../data/telemetryData';
import { AlertRule, AlertEvent, AlertConfig } from '../types';
import { 
  Bell, Mail, Send, CheckCircle2, AlertTriangle, ShieldAlert,
  Settings, ToggleLeft, ToggleRight, Sparkles, RefreshCw, Trash2,
  ExternalLink, Terminal, Shield, Inbox
} from 'lucide-react';

export const AlertsManager: React.FC = () => {
  const [rules, setRules] = useState<AlertRule[]>(INITIAL_ALERT_RULES);
  const [events, setEvents] = useState<AlertEvent[]>(INITIAL_ALERT_EVENTS);
  const [config, setConfig] = useState<AlertConfig>(DEFAULT_ALERT_CONFIG);
  const [activeTab, setActiveTab] = useState<'events' | 'rules' | 'settings'>('events');
  const [isSendingTest, setIsSendingTest] = useState(false);
  const [testSentMessage, setTestSentMessage] = useState<string | null>(null);

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const handleSendTestEmail = () => {
    setIsSendingTest(true);
    setTestSentMessage(null);

    setTimeout(() => {
      const newEvent: AlertEvent = {
        id: `evt-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        ruleId: 'rule-test-email',
        ruleName: 'Manual OcuLAN Diagnostic Test Dispatch',
        severity: 'Low',
        category: 'Diagnostic',
        targetDevice: 'OcuLAN Core Sensor (eth0)',
        targetIp: '192.168.1.5',
        message: `SMTP test alert delivered successfully to ${config.smtpTo} via ${config.smtpServer}:${config.smtpPort}.`,
        deliveredTo: [config.smtpTo, `Webhook: ${config.webhookFormat}`],
        status: 'Delivered',
        technicalDetails: `SMTP Handshake: TLS 1.3 / STARTTLS 250 OK | Message-ID: <${Date.now()}@oculan.internal>`
      };

      setEvents(prev => [newEvent, ...prev]);
      setIsSendingTest(false);
      setTestSentMessage(`Test alert email successfully dispatched to ${config.smtpTo}!`);
      setTimeout(() => setTestSentMessage(null), 5000);
    }, 800);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-[#238636] text-white flex items-center justify-center font-bold text-xs shadow-sm">
              <Bell className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm font-bold text-[#f0f6fc]">
              Real-Time Alert Dispatch & Notification Engine
            </h2>
          </div>
          <p className="text-xs text-[#8b949e] mt-1 max-w-3xl leading-relaxed">
            Continuous threat detection and notification dispatch for rogue MACs, unknown device joins, Spanning Tree loops, broadcast storm thresholds, and inter-VLAN boundary leaks.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSendTestEmail}
            disabled={isSendingTest}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition disabled:opacity-50"
          >
            <Send className={`w-3.5 h-3.5 ${isSendingTest ? 'animate-spin' : ''}`} />
            <span>Send Test Alert Email</span>
          </button>
        </div>
      </div>

      {/* Success Banner */}
      {testSentMessage && (
        <div className="bg-[#238636]/15 border border-[#238636]/40 p-3 rounded text-xs text-[#7ee787] flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#7ee787]" />
          <span>{testSentMessage}</span>
        </div>
      )}

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-[#30363d] pb-2">
        <button
          onClick={() => setActiveTab('events')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
            activeTab === 'events'
              ? 'bg-[#21262d] text-[#58a6ff] border border-[#30363d]'
              : 'text-[#8b949e] hover:text-[#c9d1d9]'
          }`}
        >
          <Inbox className="w-3.5 h-3.5" />
          <span>Delivered Alerts ({events.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
            activeTab === 'rules'
              ? 'bg-[#21262d] text-[#58a6ff] border border-[#30363d]'
              : 'text-[#8b949e] hover:text-[#c9d1d9]'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Detection Rules ({rules.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('settings')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
            activeTab === 'settings'
              ? 'bg-[#21262d] text-[#58a6ff] border border-[#30363d]'
              : 'text-[#8b949e] hover:text-[#c9d1d9]'
          }`}
        >
          <Settings className="w-3.5 h-3.5" />
          <span>SMTP & Webhook Config</span>
        </button>
      </div>

      {/* TAB 1: DELIVERED ALERTS LOG */}
      {activeTab === 'events' && (
        <div className="space-y-3">
          {events.map(event => (
            <div
              key={event.id}
              className="bg-[#161b22] border border-[#30363d] p-3.5 rounded space-y-2"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      event.severity === 'Critical' ? 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40' :
                      event.severity === 'High' ? 'bg-[#d29922]/20 text-[#d29922] border border-[#d29922]/40' :
                      'bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40'
                    }`}
                  >
                    {event.severity}
                  </span>
                  <span className="text-xs font-bold text-[#f0f6fc]">{event.ruleName}</span>
                </div>

                <div className="flex items-center gap-2 font-mono text-[11px] text-[#8b949e]">
                  <span>{event.timestamp}</span>
                  <span className="px-2 py-0.5 rounded bg-[#010409] text-[#7ee787] border border-[#30363d]">
                    ✓ {event.status}
                  </span>
                </div>
              </div>

              <p className="text-xs text-[#c9d1d9] leading-relaxed">
                {event.message}
              </p>

              <div className="bg-[#010409] p-2.5 rounded border border-[#30363d] text-[11px] font-mono space-y-1 text-[#8b949e]">
                <div className="flex flex-wrap items-center justify-between">
                  <span>Target: <strong className="text-[#58a6ff]">{event.targetDevice}</strong> ({event.targetIp})</span>
                  <span>Recipients: {event.deliveredTo.join(', ')}</span>
                </div>
                <div className="text-[#8b949e] truncate">{event.technicalDetails}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 2: DETECTION RULES */}
      {activeTab === 'rules' && (
        <div className="space-y-3">
          {rules.map(rule => (
            <div
              key={rule.id}
              className="bg-[#161b22] border border-[#30363d] p-3.5 rounded flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                    rule.severity === 'Critical' ? 'bg-[#da3633]/20 text-[#f85149]' :
                    rule.severity === 'High' ? 'bg-[#d29922]/20 text-[#d29922]' : 'bg-[#58a6ff]/20 text-[#58a6ff]'
                  }`}>
                    {rule.severity}
                  </span>
                  <h4 className="text-xs font-bold text-[#f0f6fc]">{rule.name}</h4>
                </div>
                <p className="text-[11px] text-[#8b949e]">{rule.triggerCondition}</p>
                <div className="text-[10px] text-[#8b949e] font-mono">
                  Channel: <strong className="text-[#c9d1d9]">{rule.channel}</strong> • Cooldown: {rule.cooldownMinutes} min {rule.lastTriggered && `• Triggered: ${rule.lastTriggered}`}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => toggleRule(rule.id)}
                  className={`px-3 py-1 rounded text-xs font-semibold transition ${
                    rule.enabled
                      ? 'bg-[#238636] text-white'
                      : 'bg-[#21262d] text-[#8b949e] border border-[#30363d]'
                  }`}
                >
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 3: SETTINGS (SMTP & WEBHOOK CONFIG) */}
      {activeTab === 'settings' && (
        <div className="bg-[#161b22] border border-[#30363d] p-4 rounded space-y-4">
          <div className="border-b border-[#30363d] pb-2">
            <h3 className="text-xs font-bold text-[#f0f6fc] uppercase tracking-wider">
              SMTP Relay & Alert Destination Configuration
            </h3>
            <span className="text-[11px] text-[#8b949e]">
              Configure where automated alerts from rogue device detections, storm thresholds, and port violations are dispatched.
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1">
              <label className="text-[#8b949e]">SMTP Server Hostname:</label>
              <input
                type="text"
                value={config.smtpServer}
                onChange={(e) => setConfig({ ...config, smtpServer: e.target.value })}
                className="w-full bg-[#010409] border border-[#30363d] text-[#f0f6fc] px-3 py-1.5 rounded focus:outline-none focus:border-[#58a6ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[#8b949e]">SMTP Port:</label>
              <input
                type="number"
                value={config.smtpPort}
                onChange={(e) => setConfig({ ...config, smtpPort: Number(e.target.value) })}
                className="w-full bg-[#010409] border border-[#30363d] text-[#f0f6fc] px-3 py-1.5 rounded focus:outline-none focus:border-[#58a6ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[#8b949e]">Sender Address (From):</label>
              <input
                type="email"
                value={config.smtpFrom}
                onChange={(e) => setConfig({ ...config, smtpFrom: e.target.value })}
                className="w-full bg-[#010409] border border-[#30363d] text-[#f0f6fc] px-3 py-1.5 rounded focus:outline-none focus:border-[#58a6ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[#8b949e]">Alert Recipient Email (To):</label>
              <input
                type="email"
                value={config.smtpTo}
                onChange={(e) => setConfig({ ...config, smtpTo: e.target.value })}
                className="w-full bg-[#010409] border border-[#30363d] text-[#7ee787] font-bold px-3 py-1.5 rounded focus:outline-none focus:border-[#58a6ff]"
              />
            </div>

            <div className="space-y-1 md:col-span-2">
              <label className="text-[#8b949e]">Webhook URL (Slack / Discord / Teams):</label>
              <input
                type="text"
                value={config.webhookUrl}
                onChange={(e) => setConfig({ ...config, webhookUrl: e.target.value })}
                className="w-full bg-[#010409] border border-[#30363d] text-[#f0f6fc] px-3 py-1.5 rounded focus:outline-none focus:border-[#58a6ff]"
              />
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              onClick={handleSendTestEmail}
              disabled={isSendingTest}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Save & Send Test Alert</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
