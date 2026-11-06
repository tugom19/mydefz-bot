import React, { useState } from 'react';
import { Activity, CheckCircle, Clock, ExternalLink, Play, RefreshCw, Server, Shield, XCircle } from 'lucide-react';
import type { CloudHeartbeatConfig, HeartbeatPingLog } from '../types/security';

interface CloudHeartbeatCardProps {
  heartbeat: CloudHeartbeatConfig | null;
  onUpdateConfig: (patch: Partial<CloudHeartbeatConfig>) => Promise<void>;
  onTriggerPingNow: () => Promise<HeartbeatPingLog | null>;
}

export const CloudHeartbeatCard: React.FC<CloudHeartbeatCardProps> = ({
  heartbeat,
  onUpdateConfig,
  onTriggerPingNow,
}) => {
  const [pinging, setPinging] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const isEnabled = heartbeat?.enabled !== false;
  const interval = heartbeat?.intervalMinutes || 3;
  const serviceType = heartbeat?.serviceType || 'self_ping';
  const lastPingStatus = heartbeat?.lastPingStatus || 'idle';
  const totalPings = heartbeat?.totalPingsSent || 0;
  const recentLogs = heartbeat?.recentLogs || [];

  const handlePing = async () => {
    setPinging(true);
    setStatusMsg(null);
    try {
      const res = await onTriggerPingNow();
      if (res?.status === 'ok') {
        setStatusMsg(`✅ Ping succeeded (${res.durationMs}ms) to ${res.targetUrl.slice(0, 40)}...`);
      } else {
        setStatusMsg(`⚠️ Ping finished: ${res?.error || 'Non-200 response'}`);
      }
    } catch {
      setStatusMsg('❌ Failed to trigger ping.');
    } finally {
      setPinging(false);
    }
  };

  const copyUrl = (text: string) => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard.writeText(text);
      setStatusMsg('📋 URL copied to clipboard!');
      setTimeout(() => setStatusMsg(null), 3500);
    }
  };

  const currentAppOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://ais-dev-m5cakb5ccpzubvsfq7x4oy-275514818767.asia-southeast1.run.app';
  const keepaliveEndpoint = `${currentAppOrigin}/`;

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-xl bg-sky-100 dark:bg-sky-950 text-sky-600 dark:text-sky-400">
              <Activity className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                Cloud Heartbeat &amp; Keepalive Monitor
                <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-mono font-medium ${
                  lastPingStatus === 'ok'
                    ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                    : lastPingStatus === 'failed'
                    ? 'bg-red-100 dark:bg-red-950/60 text-red-800 dark:text-red-300'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}>
                  {lastPingStatus === 'ok' ? '● Healthy' : lastPingStatus === 'failed' ? '● Degraded' : '○ Standby'}
                </span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Pings lightweight endpoints continuously to keep the Cloud Run server warm 24/7, eliminating cold-start delays.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={pinging}
            onClick={handlePing}
            className="min-h-[38px] px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-sky-600 hover:bg-sky-700 text-white transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            {pinging ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            <span>Ping Now</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="p-3 rounded-xl bg-sky-50 dark:bg-sky-950/50 border border-sky-200 dark:border-sky-800 text-xs font-medium text-sky-900 dark:text-sky-200">
          {statusMsg}
        </div>
      )}

      {/* Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 text-xs space-y-1">
          <span className="text-slate-500 dark:text-slate-400">Total Pings</span>
          <p className="text-base font-semibold font-mono text-slate-900 dark:text-slate-100">{totalPings}</p>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 text-xs space-y-1">
          <span className="text-slate-500 dark:text-slate-400">Interval</span>
          <p className="text-base font-semibold font-mono text-slate-900 dark:text-slate-100">Every {interval} min</p>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 text-xs space-y-1">
          <span className="text-slate-500 dark:text-slate-400">Last Ping Status</span>
          <p className="text-base font-semibold capitalize text-slate-900 dark:text-slate-100 flex items-center gap-1">
            {lastPingStatus === 'ok' ? (
              <CheckCircle className="w-4 h-4 text-emerald-500" />
            ) : lastPingStatus === 'failed' ? (
              <XCircle className="w-4 h-4 text-red-500" />
            ) : (
              <Clock className="w-4 h-4 text-slate-400" />
            )}
            <span>{lastPingStatus}</span>
          </p>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 text-xs space-y-1">
          <span className="text-slate-500 dark:text-slate-400">Auto Keepalive</span>
          <p className="text-base font-semibold text-emerald-600 dark:text-emerald-400">
            {isEnabled ? 'Active (24/7)' : 'Disabled'}
          </p>
        </div>
      </div>

      {/* Internal Keepalive Ping Config */}
      <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
            <Server className="w-4 h-4 text-sky-600" />
            Automated Internal Heartbeat Loop
          </label>
          <input
            type="checkbox"
            checked={isEnabled}
            onChange={(e) => void onUpdateConfig({ enabled: e.target.checked })}
            className="w-4 h-4 rounded text-sky-600 focus:ring-sky-500"
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div>
            <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
              Internal Ping Frequency
            </label>
            <select
              value={interval}
              onChange={(e) => void onUpdateConfig({ intervalMinutes: Number(e.target.value) })}
              className="w-full min-h-[38px] px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
            >
              <option value={1}>Every 1 Minute (High Aggressiveness)</option>
              <option value={2}>Every 2 Minutes (Recommended)</option>
              <option value={3}>Every 3 Minutes</option>
              <option value={5}>Every 5 Minutes (Standard)</option>
              <option value={10}>Every 10 Minutes</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
              Custom Webhook Ping URL (e.g. Cron-job.org / Healthchecks.io)
            </label>
            <input
              type="text"
              value={heartbeat?.webhookPingUrl || ''}
              placeholder="https://hc-ping.com/YOUR-UUID or Cron-job webhook"
              onChange={(e) => void onUpdateConfig({ webhookPingUrl: e.target.value })}
              className="w-full min-h-[38px] px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-mono text-[11px]"
            />
          </div>
        </div>
      </div>

      {/* External Free Monitor Integration Card (UptimeRobot / Cron-Job.org) */}
      <div className="p-4 rounded-xl bg-sky-50/70 dark:bg-sky-950/30 border border-sky-200 dark:border-sky-800/60 space-y-3 text-xs">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-sky-950 dark:text-sky-200 flex items-center gap-1.5">
            <ExternalLink className="w-4 h-4 text-sky-600" />
            Free External Pinger Integration (UptimeRobot &amp; Cron-job.org)
          </span>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-sky-200/60 dark:bg-sky-900/60 text-sky-900 dark:text-sky-200">
            Free 24/7 Warmup
          </span>
        </div>

        <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">
          To guarantee zero cold-starts when your phone is turned off, add this free lightweight keepalive URL to any external monitor:
        </p>

        <div className="flex items-center gap-2">
          <input
            type="text"
            readOnly
            value={keepaliveEndpoint}
            className="flex-1 min-h-[36px] px-3 py-1 font-mono text-[11px] rounded-lg border border-sky-200 dark:border-sky-800 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200 select-all"
          />
          <button
            type="button"
            onClick={() => copyUrl(keepaliveEndpoint)}
            className="min-h-[36px] px-3 py-1 rounded-lg text-xs font-semibold bg-sky-600 hover:bg-sky-700 text-white transition-colors shrink-0"
          >
            Copy URL
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-sky-900 dark:text-sky-300 font-medium">
          <a
            href="https://uptimerobot.com"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline flex items-center gap-1"
          >
            <span>UptimeRobot.com (Free 5-min Monitor)</span>
            <ExternalLink className="w-3 h-3" />
          </a>
          <span>·</span>
          <a
            href="https://cron-job.org"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline flex items-center gap-1"
          >
            <span>Cron-Job.org (Free Cron Pinger)</span>
            <ExternalLink className="w-3 h-3" />
          </a>
          <span>·</span>
          <a
            href="https://healthchecks.io"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline flex items-center gap-1"
          >
            <span>Healthchecks.io (Free Heartbeat Deadman)</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>

      {/* Recent Heartbeat Ping Log Table */}
      {recentLogs.length > 0 && (
        <div className="space-y-2 pt-2">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>Recent Heartbeat Dispatches ({recentLogs.length})</span>
            {heartbeat?.lastPingAt && (
              <span className="font-normal font-mono text-[11px] text-slate-500">
                Last ping: {new Date(heartbeat.lastPingAt).toLocaleTimeString()}
              </span>
            )}
          </div>

          <div className="max-h-48 overflow-y-auto rounded-xl border border-slate-200 dark:border-slate-800 divide-y divide-slate-100 dark:divide-slate-800/80">
            {recentLogs.slice(0, 10).map((log, i) => (
              <div key={`${log.timestamp}-${i}`} className="p-2.5 flex items-center justify-between gap-3 text-xs bg-slate-50/50 dark:bg-slate-950/40">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${log.status === 'ok' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                  <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 shrink-0">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="truncate text-slate-700 dark:text-slate-300 font-mono text-[11px]">
                    {log.targetUrl}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0 font-mono text-[11px]">
                  <span className={log.status === 'ok' ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}>
                    {log.httpStatus ? `HTTP ${log.httpStatus}` : log.status.toUpperCase()}
                  </span>
                  <span className="text-slate-400">·</span>
                  <span className="text-slate-500">{log.durationMs}ms</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
