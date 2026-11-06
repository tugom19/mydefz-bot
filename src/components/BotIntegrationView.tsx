import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Compass,
  RefreshCw,
  Send,
  Shield,
  Smartphone,
  Unlink,
} from 'lucide-react';
import {
  ThreatCategory,
  type BotInspectionDiagnostic,
  type BotPolicyConfig,
  type CloudHeartbeatConfig,
  type ConnectedTelegramChat,
  type HeartbeatPingLog,
  type ThreatEvent,
} from '../types/security';
import shieldBannerImg from '../assets/images/shield_architecture_banner_1793349287170.jpg';
import { CloudHeartbeatCard } from './CloudHeartbeatCard';
import { TelegramWeeklyReportCard } from './TelegramWeeklyReportCard';

interface BotIntegrationViewProps {
  botPolicy: BotPolicyConfig;
  hasServerBotToken: boolean;
  connectedChats: ConnectedTelegramChat[];
  recentInspections?: BotInspectionDiagnostic[];
  liveTelegramEvents: ThreatEvent[];
  watcherTotalReceived: number;
  watcherCleanIgnored: number;
  watcherLastError: string | null;
  lastPolledAt: number | null;
  cloudHeartbeat?: CloudHeartbeatConfig | null;
  onUpdateHeartbeatConfig?: (patch: Partial<CloudHeartbeatConfig>) => Promise<void>;
  onTriggerHeartbeatPingNow?: () => Promise<HeartbeatPingLog | null>;
  onPollNow: () => Promise<void>;
  onTriggerEndToEndAlertTest: () => Promise<void>;
  onNavigateShield: () => void;
  onUpdatePolicy: (patch: Partial<BotPolicyConfig>) => Promise<void>;
  onVerifyAndConnectBot: (tokenInput: string, clearWebhook: boolean) => Promise<{
    ok: boolean;
    message: string;
  }>;
  onDisconnectBot: () => Promise<void>;
  onSendTestPersonalWarning: (targetChatId: string) => Promise<{ ok: boolean; message: string }>;
  onDetectPersonalChatId: () => Promise<{ ok: boolean; chatId?: string; message: string }>;
  onRequestBrowserNotifications: () => Promise<string>;
}

export const BotIntegrationView: React.FC<BotIntegrationViewProps> = ({
  botPolicy,
  hasServerBotToken,
  connectedChats,
  recentInspections = [],
  liveTelegramEvents,
  watcherTotalReceived,
  watcherCleanIgnored,
  watcherLastError,
  lastPolledAt,
  cloudHeartbeat = null,
  onUpdateHeartbeatConfig,
  onTriggerHeartbeatPingNow,
  onPollNow,
  onTriggerEndToEndAlertTest,
  onNavigateShield,
  onUpdatePolicy,
  onVerifyAndConnectBot,
  onDisconnectBot,
  onSendTestPersonalWarning,
  onDetectPersonalChatId,
  onRequestBrowserNotifications,
}) => {
  const [tokenDraft, setTokenDraft] = useState(botPolicy.botToken);
  const [clearWebhookOnConnect, setClearWebhookOnConnect] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [detectingChat, setDetectingChat] = useState(false);
  const [sendingTestDm, setSendingTestDm] = useState(false);
  const [bannerFailed, setBannerFailed] = useState(false);

  useEffect(() => {
    if (botPolicy.botToken && !tokenDraft) {
      setTokenDraft(botPolicy.botToken);
    }
  }, [botPolicy.botToken, tokenDraft]);

  const handleConnectSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setVerifying(true);
    setStatusMessage(null);
    try {
      const res = await onVerifyAndConnectBot(tokenDraft, clearWebhookOnConnect);
      setStatusMessage({ ok: res.ok, text: res.message });
    } finally {
      setVerifying(false);
    }
  };

  const handleAutoDetectChatId = async () => {
    setDetectingChat(true);
    setStatusMessage(null);
    try {
      const res = await onDetectPersonalChatId();
      setStatusMessage({ ok: res.ok, text: res.message });
    } finally {
      setDetectingChat(false);
    }
  };

  const handleTestDm = async () => {
    if (!botPolicy.personalWarningChatId.trim()) {
      setStatusMessage({
        ok: false,
        text: 'Enter or auto-detect your Personal Telegram Chat ID first.',
      });
      return;
    }
    setSendingTestDm(true);
    setStatusMessage(null);
    try {
      const res = await onSendTestPersonalWarning(botPolicy.personalWarningChatId.trim());
      setStatusMessage({ ok: res.ok, text: res.message });
    } finally {
      setSendingTestDm(false);
    }
  };

  const handleEnableBrowserAlerts = async () => {
    const msg = await onRequestBrowserNotifications();
    setStatusMessage({ ok: true, text: msg });
  };

  return (
    <div className="space-y-8">
      {/* 2-Column Hero Split with items-stretch */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
        <div className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 flex flex-col justify-between space-y-6">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-400">
              <Smartphone className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
              <span>Telegram Bot API Bridge</span>
              <span aria-hidden="true">·</span>
              <span>Personal DM Warning Integration</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-50 [text-wrap:balance]">
              Connect Your Telegram Bot &amp; Personal Alert Channel
            </h1>
            <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
              Link a bot created via <span className="font-mono">@BotFather</span> to monitor group
              and direct chats in real time. Whenever SentinelGram detects a phishing link, scam
              offer, or infected attachment, it dispatches a warning straight to your personal
              Telegram inbox.
            </p>
          </div>

          <ol className="space-y-2.5 text-xs sm:text-sm text-slate-700 dark:text-slate-300 border-t border-slate-100 dark:border-slate-800 pt-5">
            <li>
              <span className="font-semibold text-slate-900 dark:text-slate-100">01.</span> Open{' '}
              <span className="font-mono">@BotFather</span> in Telegram, run{' '}
              <span className="font-mono">/newbot</span> (disable Group Privacy via{' '}
              <span className="font-mono">/setprivacy</span> to inspect group links).
            </li>
            <li>
              <span className="font-semibold text-slate-900 dark:text-slate-100">02.</span> Paste
              your Bot Token below — it is encrypted locally using your AES-256-GCM vault key.
            </li>
            <li>
              <span className="font-semibold text-slate-900 dark:text-slate-100">03.</span> Send{' '}
              <span className="font-mono">/start</span> to your bot from your Android Telegram app
              and click &ldquo;Auto-Detect My Chat ID&rdquo; to enable personal DM alerts.
            </li>
          </ol>
        </div>

        <div className="lg:col-span-5 rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-900 relative min-h-[240px]">
          {!bannerFailed ? (
            <img
              src={shieldBannerImg}
              alt="Isometric mobile cryptographic shield filtering incoming Telegram packets and file attachments"
              referrerPolicy="no-referrer"
              onError={() => setBannerFailed(true)}
              className="w-full h-full lg:h-full object-cover"
            />
          ) : (
            <div className="w-full h-full min-h-[240px] bg-gradient-to-br from-slate-900 via-slate-800 to-sky-950 p-6 flex flex-col items-center justify-center text-center text-white space-y-2">
              <Shield className="w-10 h-10 text-sky-400" />
              <p className="text-sm font-semibold">End-to-End Encrypted Telegram Bot Bridge</p>
              <p className="text-xs text-slate-300 max-w-xs">
                Real-time packet polling, local ML classification, and instant personal chat alerts.
              </p>
            </div>
          )}
          <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-slate-950/85 via-slate-950/45 to-transparent p-5 text-white">
            <p className="text-xs font-medium text-sky-300">Zero-Plaintext Storage</p>
            <p className="text-sm font-semibold">
              Bot credentials &amp; alert logs remain sealed with AES-256-GCM
            </p>
          </div>
        </div>
      </section>

      {statusMessage && (
        <div
          role="status"
          className={`p-4 rounded-2xl border text-sm font-medium ${
            statusMessage.ok
              ? 'bg-emerald-50/80 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/70 text-emerald-900 dark:text-emerald-200'
              : 'bg-red-50/80 dark:bg-red-950/40 border-red-200 dark:border-red-800/70 text-red-900 dark:text-red-200'
          }`}
        >
          {statusMessage.text}
        </div>
      )}

      {/* Connection Credentials & Personal DM Alert Setup */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        <form
          onSubmit={handleConnectSubmit}
          className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5"
        >
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                Telegram Bot API Credentials
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Verified directly against api.telegram.org/bot.../getMe
              </p>
            </div>
            {botPolicy.connected && (
              <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Connected</span>
              </span>
            )}
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="bot-token-input"
              className="block text-xs font-medium text-slate-700 dark:text-slate-300"
            >
              Bot API Token (@BotFather)
            </label>
            <input
              id="bot-token-input"
              type="password"
              autoComplete="off"
              value={tokenDraft}
              onChange={(e) => setTokenDraft(e.target.value)}
              placeholder={
                hasServerBotToken
                  ? 'Server environment token detected (or enter custom token)'
                  : '1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'
              }
              className="w-full min-h-[44px] px-3.5 py-2 text-sm font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>

          <label className="flex items-center gap-3 min-h-[40px] cursor-pointer text-xs text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={clearWebhookOnConnect}
              onChange={(e) => setClearWebhookOnConnect(e.target.checked)}
              className="w-4 h-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500"
            />
            <span>
              Automatically clear conflicting webhooks so real-time getUpdates polling works
            </span>
          </label>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={verifying || (!tokenDraft.trim() && !hasServerBotToken)}
              className="min-h-[44px] px-5 py-2.5 rounded-xl text-sm font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
            >
              {verifying ? 'Verifying with Telegram...' : 'Verify & Connect Bot'}
            </button>

            {botPolicy.connected && (
              <button
                type="button"
                onClick={onDisconnectBot}
                className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Unlink className="w-3.5 h-3.5" />
                <span>Disconnect</span>
              </button>
            )}
          </div>

          {botPolicy.connected && (
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-3">
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="font-semibold text-slate-900 dark:text-slate-100">
                  Live Telegram Bot Watcher Diagnostics
                </span>
                <button
                  type="button"
                  onClick={() => void onPollNow()}
                  className="text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1 font-medium whitespace-nowrap"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Sync Now</span>
                </button>
              </div>

              <div className="text-xs text-slate-600 dark:text-slate-400 space-y-1 font-mono tabular-nums">
                <div>
                  Bot Identity: {botPolicy.botFirstName} (@{botPolicy.botUsername}) · ID{' '}
                  {botPolicy.botId}
                </div>
                <div>
                  Threats &amp; Handshakes Logged: {watcherTotalReceived} · Clean / Voice Ignored
                  Silently: {watcherCleanIgnored}
                  {lastPolledAt
                    ? ` · Checked ${new Date(lastPolledAt).toLocaleTimeString()}`
                    : ''}
                </div>
                <div>
                  Personal Alert Target:{' '}
                  {botPolicy.personalWarningChatId
                    ? `Chat ID ${botPolicy.personalWarningChatId} (Linked)`
                    : 'Waiting — send /start to your bot in Telegram'}
                </div>
              </div>

              {watcherLastError && (
                <p className="text-xs text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/40 p-3 rounded-xl">
                  Telegram API Notice: {watcherLastError}
                </p>
              )}

              {botPolicy.canReadAllGroupMessages === false ? (
                <div className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-xs text-amber-900 dark:text-amber-200 space-y-1">
                  <p className="font-semibold flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>Group Privacy Mode is ON in @BotFather</span>
                  </p>
                  <p className="leading-relaxed">
                    Sending or forwarding files/links directly to @{botPolicy.botUsername} works
                    right now. To scan messages inside Telegram Groups automatically, either make @
                    {botPolicy.botUsername} a Group Admin or send{' '}
                    <span className="font-mono">/setprivacy</span> &rarr;{' '}
                    <span className="font-mono">Disable</span> in @BotFather, then click Verify
                    &amp; Connect Bot again.
                  </p>
                </div>
              ) : (
                <p className="text-xs text-emerald-700 dark:text-emerald-400 font-medium">
                  Group Privacy Disabled: @{botPolicy.botUsername} can inspect both direct/forwarded
                  messages and group chats automatically.
                </p>
              )}

              {/* 24/7 Cloud Uptime & Keepalive Info */}
              <div className="p-3 rounded-xl bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-800/60 text-xs space-y-1.5 text-sky-950 dark:text-sky-200">
                <div className="flex items-center justify-between">
                  <span className="font-semibold flex items-center gap-1.5">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                    24/7 Cloud Server &amp; Keepalive
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-sky-100 dark:bg-sky-900 text-sky-800 dark:text-sky-300">
                    Always-On Ready
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
                  When Chrome on Android is closed or your phone goes to sleep, Google Cloud scales idle dev containers down after inactivity (showing the <em>"application starting"</em> screen upon return).
                </p>
                <div className="p-2 rounded-lg bg-white/70 dark:bg-slate-900/70 border border-sky-100 dark:border-sky-900/50 space-y-1">
                  <p className="font-medium text-[11px] text-slate-800 dark:text-slate-200">
                    Keep It Running 24/7 (Free Ping URL):
                  </p>
                  <p className="font-mono text-[10px] select-all break-all text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-slate-950 p-1 rounded">
                    {typeof window !== 'undefined' ? `${window.location.origin}/` : 'https://ais-dev-m5cakb5ccpzubvsfq7x4oy-275514818767.asia-southeast1.run.app/'}
                  </p>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400">
                    Add this URL to any free 5-minute pinger (e.g., UptimeRobot.com or Cron-Job.org) to keep your cloud container awake 24 hours a day.
                  </p>
                </div>
              </div>

              {recentInspections.length > 0 && (
                <div className="pt-2.5 border-t border-slate-100 dark:border-slate-800/80 space-y-2">
                  <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                    Recent Live File &amp; Message Scans ({recentInspections.length})
                  </p>
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {recentInspections.slice(0, 8).map((item, idx) => (
                      <div
                        key={`${item.timestamp}-${idx}`}
                        className={`p-2.5 rounded-xl border text-xs space-y-0.5 ${
                          item.verdict === 'threat_blocked'
                            ? 'bg-red-50/70 dark:bg-red-950/30 border-red-200 dark:border-red-900/60 text-red-900 dark:text-red-200'
                            : 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 font-semibold">
                          <span className="truncate">
                            {item.verdict === 'threat_blocked' ? '⚠️ Threat' : '✅ Clean'} ·{' '}
                            {item.label}
                          </span>
                          <span className="font-mono tabular-nums shrink-0">
                            Risk {item.riskScore}/100
                          </span>
                        </div>
                        <div className="text-[11px] opacity-85">
                          {item.reason}
                          {item.repliedInTelegram ? ' · Replied in Telegram' : ''}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Personal DM Warning Integration */}
          <div className="pt-5 border-t border-slate-200 dark:border-slate-800 space-y-3">
            <div className="space-y-1">
              <label
                htmlFor="personal-chat-id"
                className="block text-sm font-semibold text-slate-900 dark:text-slate-100"
              >
                Personal Warning Chat ID (Direct Telegram Alert Target)
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Third-party personal warning channel: threats detected in any group or DM send an
                immediate private alert to this Telegram Chat ID.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                id="personal-chat-id"
                type="text"
                value={botPolicy.personalWarningChatId}
                onChange={(e) => onUpdatePolicy({ personalWarningChatId: e.target.value })}
                placeholder="e.g. 582910492"
                className="flex-1 min-h-[44px] px-3.5 py-2 text-sm font-mono tabular-nums bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
              <button
                type="button"
                disabled={!botPolicy.connected || detectingChat}
                onClick={handleAutoDetectChatId}
                className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0 disabled:opacity-50"
              >
                <Compass className="w-3.5 h-3.5" />
                <span>{detectingChat ? 'Scanning...' : 'Auto-Detect My Chat ID'}</span>
              </button>
            </div>

            <button
              type="button"
              disabled={!botPolicy.connected || sendingTestDm}
              onClick={handleTestDm}
              className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:opacity-90 transition-opacity flex items-center gap-2 whitespace-nowrap shrink-0 disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>
                {sendingTestDm
                  ? 'Sending Telegram Message...'
                  : 'Send Live Test Warning to My Telegram'}
              </span>
            </button>
          </div>
        </form>

        {/* Automated Response & Notification Policies */}
        <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
              Automated Response &amp; Real-Time Alert Rules
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Configure how SentinelGram responds when phishing links, malware files, or scams cross
              your risk threshold.
            </p>
          </div>

          <div className="space-y-2 pb-4 border-b border-slate-100 dark:border-slate-800">
            <div className="flex items-center justify-between text-xs">
              <label
                htmlFor="risk-threshold-slider"
                className="font-medium text-slate-700 dark:text-slate-300"
              >
                Automated Enforcement Risk Threshold
              </label>
              <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                {botPolicy.riskThreshold} / 100
              </span>
            </div>
            <input
              id="risk-threshold-slider"
              type="range"
              min={35}
              max={85}
              step={5}
              value={botPolicy.riskThreshold}
              onChange={(e) => onUpdatePolicy({ riskThreshold: Number(e.target.value) })}
              className="w-full accent-sky-600 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Lower values catch subtle social-engineering lures; higher values restrict alerts to
              high-certainty phishing and executable payloads.
            </p>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            <label className="py-3 flex items-center justify-between gap-4 cursor-pointer min-h-[52px]">
              <div>
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  Scam &amp; Virus Files Only (Ignore Voice Chats &amp; Normal Messages)
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Silently skips voice chats, voice messages, photos, videos, clean files, and
                  ordinary text — alerts only on scam files and virus attachments.
                </p>
              </div>
              <input
                type="checkbox"
                checked={botPolicy.onlyScamAndVirusFiles !== false}
                onChange={(e) =>
                  onUpdatePolicy({ onlyScamAndVirusFiles: e.target.checked })
                }
                className="w-5 h-5 rounded border-slate-300 text-sky-600 focus:ring-sky-500 shrink-0"
              />
            </label>

            <label className="py-3 flex items-center justify-between gap-4 cursor-pointer min-h-[52px]">
              <div>
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  Alert Only Inside My Bot (@{botPolicy.botUsername || 'bot'})
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Sends threat alerts privately inside your own bot chat ONLY — never sends or
                  replies inside your personal DMs or group chats.
                </p>
              </div>
              <input
                type="checkbox"
                checked={botPolicy.autoPersonalWarningOnThreat}
                onChange={(e) =>
                  onUpdatePolicy({
                    autoPersonalWarningOnThreat: e.target.checked,
                    autoReplyInGroupChats: false,
                    autoDeleteCriticalInGroups: false,
                  })
                }
                className="w-5 h-5 rounded border-slate-300 text-sky-600 focus:ring-sky-500 shrink-0"
              />
            </label>

            <label className="py-3 flex items-center justify-between gap-4 cursor-pointer min-h-[52px]">
              <div>
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  Privacy-Preserving Snippet Redaction
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Omit raw chat quotes from outgoing Telegram warnings so sensitive text stays only
                  in your local E2EE vault.
                </p>
              </div>
              <input
                type="checkbox"
                checked={botPolicy.e2eeRedactPreviewInWarnings}
                onChange={(e) =>
                  onUpdatePolicy({ e2eeRedactPreviewInWarnings: e.target.checked })
                }
                className="w-5 h-5 rounded border-slate-300 text-sky-600 focus:ring-sky-500 shrink-0"
              />
            </label>

            <label className="py-3 flex items-center justify-between gap-4 cursor-pointer min-h-[52px]">
              <div>
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  Acoustic Threat Chime
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Play a subtle synthesized warning tone when real-time suspicious links or files
                  arrive.
                </p>
              </div>
              <input
                type="checkbox"
                checked={botPolicy.soundAlertEnabled}
                onChange={(e) => onUpdatePolicy({ soundAlertEnabled: e.target.checked })}
                className="w-5 h-5 rounded border-slate-300 text-sky-600 focus:ring-sky-500 shrink-0"
              />
            </label>
          </div>

          <div className="pt-2 space-y-2.5">
            <button
              type="button"
              onClick={handleEnableBrowserAlerts}
              className="w-full min-h-[44px] px-4 py-2.5 rounded-xl text-xs font-semibold border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center justify-center gap-2 whitespace-nowrap"
            >
              <Bell className="w-4 h-4 text-sky-600 dark:text-sky-400" />
              <span>
                {botPolicy.browserNotificationsEnabled
                  ? 'Android / Browser Push Notifications Enabled'
                  : 'Enable Android & Browser Real-Time Push Alerts'}
              </span>
            </button>

            <button
              type="button"
              onClick={() => void onTriggerEndToEndAlertTest()}
              className="w-full min-h-[44px] px-4 py-2.5 rounded-xl text-xs font-semibold bg-red-600 text-white hover:bg-red-700 transition-colors flex items-center justify-center gap-2 whitespace-nowrap"
            >
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Test Full Alert Pipeline Now (Invoice.pdf.exe &rarr; App + Telegram)</span>
            </button>
          </div>
        </div>
      </div>

      {/* Cloud Heartbeat 24/7 Monitor Service Component */}
      <CloudHeartbeatCard
        heartbeat={cloudHeartbeat}
        onUpdateConfig={onUpdateHeartbeatConfig || (async () => {})}
        onTriggerPingNow={onTriggerHeartbeatPingNow || (async () => null)}
      />

      {/* Telegram Bot Command Center & Weekly Threat Report */}
      <TelegramWeeklyReportCard
        botUsername={botPolicy.botUsername || 'mydefz_bot'}
        personalChatId={botPolicy.personalWarningChatId || '334856454'}
      />

      {/* Live Connected Telegram Chats & Real-Time Packet Feed */}
      {botPolicy.connected && (
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Connected Chats & Group Permission Diagnostics */}
          <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                  Connected Telegram Chats &amp; Permissions
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Chats where @{botPolicy.botUsername} has received a command, join event, or
                  message.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void onPollNow()}
                className="min-h-[38px] px-3 py-1.5 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-1.5 shrink-0"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Refresh</span>
              </button>
            </div>

            {connectedChats.length === 0 ? (
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 space-y-2.5 leading-relaxed">
                <p className="font-semibold text-slate-900 dark:text-slate-100">
                  Waiting for first handshake from Telegram — why nothing showed yet:
                </p>
                <ul className="space-y-1.5 list-disc pl-4">
                  <li>
                    <strong>If you added @{botPolicy.botUsername} to a Telegram Group:</strong> Open
                    that group in Telegram and send{' '}
                    <span className="font-mono">/status@{botPolicy.botUsername}</span>,{' '}
                    <strong>and promote @{botPolicy.botUsername} to Group Admin</strong> (Group Info
                    &rarr; Administrators &rarr; Add Admin). Without Admin rights (or{' '}
                    <span className="font-mono">/setprivacy</span> &rarr;{' '}
                    <span className="font-mono">Disable</span> in @BotFather), Telegram blocks bots
                    from seeing normal group messages and files.
                  </li>
                  <li>
                    <strong>If testing 1-on-1 with your Bot:</strong> Open{' '}
                    <span className="font-mono">@{botPolicy.botUsername}</span> in Telegram and send{' '}
                    <span className="font-mono">/start</span> or type{' '}
                    <span className="font-mono">Invoice.pdf.exe</span>.
                  </li>
                  <li>
                    <strong>If someone sent you a private DM:</strong> Forward that DM or file to{' '}
                    <span className="font-mono">@{botPolicy.botUsername}</span> (or link{' '}
                    <span className="font-mono">@{botPolicy.botUsername}</span> under Telegram
                    Settings &rarr; Telegram Business &rarr; Chatbots).
                  </li>
                </ul>
              </div>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-slate-800 border-t border-slate-100 dark:border-slate-800">
                {connectedChats.map((c) => (
                  <div key={c.chatId} className="py-3.5 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">
                        {c.title}
                      </span>
                      <span
                        className={`text-xs font-semibold shrink-0 ${
                          c.canReadAllMessages
                            ? 'text-emerald-700 dark:text-emerald-400'
                            : 'text-amber-700 dark:text-amber-400'
                        }`}
                      >
                        {c.botStatus === 'left'
                          ? 'Removed'
                          : c.canReadAllMessages
                          ? 'Full Protection Active'
                          : 'Privacy Blocked (Needs Admin)'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                      Chat ID: {c.chatId} · Type: {c.chatType} · Role: {c.botStatus}
                    </p>
                    {!c.canReadAllMessages && c.botStatus !== 'left' && (
                      <p className="text-xs text-amber-800 dark:text-amber-300 pt-1">
                        Action needed: Promote @{botPolicy.botUsername} to Group Admin in Telegram
                        so it receives normal messages &amp; files in this group.
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Live Incoming Telegram Packets Feed */}
          <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                  Intercepted Telegram Threats &amp; Handshakes ({liveTelegramEvents.length})
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Only scam files, virus attachments, and connection status events are logged here
                  (voice chats and clean files are ignored silently).
                </p>
              </div>
              {liveTelegramEvents.length > 0 && (
                <button
                  type="button"
                  onClick={onNavigateShield}
                  className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline shrink-0"
                >
                  Open Live Shield &rarr;
                </button>
              )}
            </div>

            {liveTelegramEvents.length === 0 ? (
              <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-center space-y-1.5">
                <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
                  No live packets received yet
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Send <span className="font-mono">/start</span> or{' '}
                  <span className="font-mono">Invoice.pdf.exe</span> to @{botPolicy.botUsername} in
                  Telegram — it will appear here within ~2 seconds.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-slate-800 border-t border-slate-100 dark:border-slate-800">
                {liveTelegramEvents.slice(0, 6).map((evt) => {
                  const isThreat = evt.analysis.category !== ThreatCategory.Clean;
                  return (
                    <div key={evt.id} className="py-3 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                          {evt.chatTitle} · {evt.senderUsername || evt.senderName}
                        </span>
                        <span
                          className={`text-xs font-mono tabular-nums font-semibold shrink-0 ${
                            isThreat
                              ? 'text-red-600 dark:text-red-400'
                              : 'text-emerald-700 dark:text-emerald-400'
                          }`}
                        >
                          {isThreat
                            ? `${evt.analysis.category.toUpperCase()} (${evt.analysis.overallRiskScore}/100)`
                            : 'Verified / Handshake'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 dark:text-slate-300 line-clamp-2">
                        {evt.systemNotice || evt.messagePreview}
                      </p>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
};
