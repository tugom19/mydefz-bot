import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Copy,
  ExternalLink,
  FileWarning,
  Globe,
  Lock,
  Radio,
  RefreshCw,
  Search,
  Send,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import {
  ChatSourceType,
  EnforcementStatus,
  ThreatCategory,
  ThreatSeverity,
  type BotPolicyConfig,
  type EncryptedEnvelope,
  type ThreatEvent,
} from '../types/security';
import { THREAT_TEST_SCENARIOS } from '../services/seedEvents';
import {
  PROTECTED_FILE_EXTENSIONS,
  SUSPICIOUS_LURE_KEYWORDS,
  formatSuspiciousFileAlert,
} from '../services/localMlEngine';
import {
  checkFileMultiEngineIntel,
  checkUrlMultiEngineIntel,
  getFileScannerLinks,
  getUrlScannerLinks,
  type FileThreatIntelReport,
  type UrlThreatIntelReport,
} from '../services/threatIntelLinks';

interface LiveShieldViewProps {
  events: ThreatEvent[];
  rawEnvelopes: EncryptedEnvelope[];
  botPolicy: BotPolicyConfig;
  isPollingNow: boolean;
  lastPolledAt: number | null;
  onSimulateScenario: (scenarioIndex: number) => Promise<void>;
  onPollTelegramNow: () => Promise<void>;
  onToggleLivePolling: () => void;
  onDispatchTelegramAction: (
    event: ThreatEvent,
    action: 'personal_warning' | 'chat_reply' | 'delete_message'
  ) => Promise<{ ok: boolean; message: string }>;
  onNavigateTab: (tab: 'shield' | 'scanner' | 'bot' | 'analytics' | 'vault') => void;
  transportLabel?: string;
  serverPingMs?: number | null;
}

function formatRelativeTime(ts: number): string {
  const diffSec = Math.max(1, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

function categoryLabel(cat: ThreatCategory): string {
  switch (cat) {
    case ThreatCategory.Phishing:
      return 'Phishing Link';
    case ThreatCategory.Malware:
      return 'Malware File';
    case ThreatCategory.Scam:
      return 'Scam Pattern';
    case ThreatCategory.Spam:
      return 'Spam Filter';
    default:
      return 'Verified Clean';
  }
}

function enforcementLabel(status: EnforcementStatus): string {
  switch (status) {
    case EnforcementStatus.Quarantined:
      return 'Quarantined';
    case EnforcementStatus.PersonalWarned:
      return 'Personal DM Warned';
    case EnforcementStatus.ChatWarned:
      return 'Chat Reply Warned';
    case EnforcementStatus.Flagged:
      return 'Flagged for Review';
    default:
      return 'Allowed';
  }
}

function chatTypeLabel(type: ChatSourceType): string {
  switch (type) {
    case ChatSourceType.Private:
      return 'Private Chat';
    case ChatSourceType.Supergroup:
      return 'Supergroup';
    case ChatSourceType.Group:
      return 'Group Chat';
    case ChatSourceType.Channel:
      return 'Channel';
    default:
      return 'Local Scanner';
  }
}

export const LiveShieldView: React.FC<LiveShieldViewProps> = ({
  events,
  rawEnvelopes,
  botPolicy,
  isPollingNow,
  lastPolledAt,
  onSimulateScenario,
  onPollTelegramNow,
  onToggleLivePolling,
  onDispatchTelegramAction,
  onNavigateTab,
  transportLabel = 'Wi-Fi / Mobile Data',
  serverPingMs = null,
}) => {
  const [filter, setFilter] = useState<
    'all' | 'telegram_live' | 'phishing' | 'malware' | 'scam_spam' | 'clean'
  >('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [showCiphertext, setShowCiphertext] = useState(false);
  const [simulatingIdx, setSimulatingIdx] = useState<number | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [urlIntelReport, setUrlIntelReport] = useState<UrlThreatIntelReport | null>(null);
  const [checkingUrlIntel, setCheckingUrlIntel] = useState(false);
  const [fileIntelReport, setFileIntelReport] = useState<FileThreatIntelReport | null>(null);
  const [checkingFileIntel, setCheckingFileIntel] = useState(false);
  const [phoneTestFeedback, setPhoneTestFeedback] = useState<string | null>(null);

  const liveTelegramCount = useMemo(
    () =>
      events.filter((e) => e.eventOrigin === 'telegram_live' || e.id.startsWith('tg-')).length,
    [events]
  );

  const metrics = useMemo(() => {
    const total = events.length;
    const blocked = events.filter((e) => e.analysis.category !== ThreatCategory.Clean).length;
    const personalWarnings = events.filter((e) => e.personalWarningSent).length;
    const avgLatency =
      total > 0
        ? (events.reduce((acc, e) => acc + e.analysis.inferenceLatencyMs, 0) / total).toFixed(2)
        : '0.00';
    return { total, blocked, personalWarnings, avgLatency };
  }, [events]);

  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      const isLiveTg = evt.eventOrigin === 'telegram_live' || evt.id.startsWith('tg-');
      if (filter === 'telegram_live' && !isLiveTg) return false;
      if (filter === 'phishing' && evt.analysis.category !== ThreatCategory.Phishing) return false;
      if (filter === 'malware' && evt.analysis.category !== ThreatCategory.Malware) return false;
      if (
        filter === 'scam_spam' &&
        evt.analysis.category !== ThreatCategory.Scam &&
        evt.analysis.category !== ThreatCategory.Spam
      ) {
        return false;
      }
      if (filter === 'clean' && evt.analysis.category !== ThreatCategory.Clean) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const hay = `${evt.chatTitle} ${evt.senderName} ${evt.senderUsername} ${evt.messagePreview} ${
          evt.analysis.fileAnalysis?.fileName || ''
        }`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [events, filter, searchQuery]);

  const selectedEvent = useMemo(
    () => events.find((e) => e.id === selectedEventId) || null,
    [events, selectedEventId]
  );

  const selectedEnvelope = useMemo(() => {
    if (!selectedEvent) return null;
    const idx = events.findIndex((e) => e.id === selectedEvent.id);
    if (idx >= 0 && idx < rawEnvelopes.length) {
      return rawEnvelopes[idx];
    }
    return rawEnvelopes[0] || null;
  }, [events, rawEnvelopes, selectedEvent]);

  const handleRunScenario = async (idx: number) => {
    setSimulatingIdx(idx);
    try {
      await onSimulateScenario(idx);
    } finally {
      setSimulatingIdx(null);
    }
  };

  const handleManualAction = async (
    evt: ThreatEvent,
    action: 'personal_warning' | 'chat_reply' | 'delete_message'
  ) => {
    setBusyAction(action);
    setActionFeedback(null);
    try {
      const result = await onDispatchTelegramAction(evt, action);
      setActionFeedback(result.message);
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Top Status & Action Header */}
      <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-400">
            <Globe className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <span className="text-emerald-700 dark:text-emerald-400 font-semibold">
              Cloud Server Live ({transportLabel}
              {serverPingMs !== null ? ` · ${serverPingMs} ms` : ''})
            </span>
            <span aria-hidden="true">·</span>
            <span>Chrome Web Android Ready</span>
            {botPolicy.connected && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-sky-600 dark:text-sky-400 font-semibold">
                  @{botPolicy.botUsername} Tracking
                </span>
              </>
            )}
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-50 [text-wrap:balance]">
            Real-Time Telegram Threat Shield
          </h1>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
            Monitors your Telegram bot and group files 24/7 on the cloud server, streaming live
            scam/malware detections and instant updates straight to Chrome Web on Android over Wi-Fi
            or Mobile Data.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          {botPolicy.connected ? (
            <>
              <button
                type="button"
                onClick={onToggleLivePolling}
                className={`min-h-[44px] px-4 py-2.5 rounded-xl text-sm font-medium transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 ${
                  botPolicy.livePollingEnabled
                    ? 'bg-emerald-600 text-white hover:bg-emerald-700'
                    : 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:bg-slate-800 dark:hover:bg-white'
                }`}
              >
                <Radio className="w-4 h-4 shrink-0" />
                <span>
                  {botPolicy.livePollingEnabled ? 'Live Cloud Sync On' : 'Resume Cloud Sync'}
                </span>
              </button>
              <button
                type="button"
                onClick={onPollTelegramNow}
                disabled={isPollingNow}
                className="min-h-[44px] px-4 py-2.5 rounded-xl text-sm font-medium border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800/80 transition-colors whitespace-nowrap shrink-0 disabled:opacity-60 flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 shrink-0 ${isPollingNow ? 'animate-spin' : ''}`} />
                <span>{isPollingNow ? 'Syncing Server...' : 'Sync Live Now'}</span>
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={() => onNavigateTab('bot')}
              className="min-h-[44px] px-5 py-2.5 rounded-xl text-sm font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0 flex items-center gap-2"
            >
              <Send className="w-4 h-4 shrink-0" />
              <span>Connect Telegram Bot API</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => onNavigateTab('scanner')}
            className="min-h-[44px] px-4 py-2.5 rounded-xl text-sm font-medium border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800/80 transition-colors whitespace-nowrap shrink-0"
          >
            Scan Link or File
          </button>
        </div>
      </section>

      {/* Full-Width 4-Column KPI Summary Strip */}
      <section
        aria-label="Protection Metrics"
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 sm:divide-x divide-slate-200 dark:divide-slate-800"
      >
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Messages &amp; Files Inspected
          </p>
          <p className="text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {metrics.total}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {lastPolledAt ? `Last Bot sync ${formatRelativeTime(lastPolledAt)}` : 'Encrypted at rest'}
          </p>
        </div>

        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Threats Intercepted
          </p>
          <p className="text-2xl sm:text-3xl font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
            {metrics.blocked}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Phishing, malware &amp; scam blocks
          </p>
        </div>

        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Personal Warnings Dispatched
          </p>
          <p className="text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {metrics.personalWarnings}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Direct Telegram alert notifications
          </p>
        </div>

        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Mean Local ML Inference
          </p>
          <p className="text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {metrics.avgLatency} ms
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Zero cloud plaintext exposure
          </p>
        </div>
      </section>

      {/* Main 2-Column Workspace on Desktop, Thumb-Friendly Stack on Android */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left / Primary Column: Live Intercept Stream */}
        <div className="lg:col-span-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-5 border-b border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
                  Intercept &amp; Notification Feed
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Tap any chat event to inspect local ML feature weights, SHA-256 file hashes, or
                  send a Telegram warning.
                </p>
              </div>
              <div className="relative w-full sm:w-64">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter chat, sender, domain..."
                  aria-label="Filter threat events"
                  className="w-full min-h-[40px] pl-9 pr-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500"
                />
              </div>
            </div>

            {/* Interactive Segmented Filter Controls */}
            <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800/80 rounded-xl overflow-x-auto">
              {(
                [
                  { id: 'all', label: 'All Events' },
                  { id: 'telegram_live', label: `Live Telegram (${liveTelegramCount})` },
                  { id: 'phishing', label: 'Phishing Links' },
                  { id: 'malware', label: 'Malware Files' },
                  { id: 'scam_spam', label: 'Scam & Spam' },
                  { id: 'clean', label: 'Clean' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setFilter(tab.id)}
                  className={`min-h-[38px] px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 ${
                    filter === tab.id
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-50 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Event Tap List Rows */}
          {filteredEvents.length === 0 ? (
            <div className="p-10 text-center space-y-3">
              <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                {filter === 'telegram_live'
                  ? 'No live Telegram packets received yet.'
                  : 'No Telegram events match the active filter.'}
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                {filter === 'telegram_live'
                  ? 'Open your connected bot in Telegram and send /start, type a message, or forward a suspicious link or file — it will appear here in real time within ~2 seconds.'
                  : 'Reset your search query or trigger a realistic threat test packet from the verification bench to observe real-time classification and alerting.'}
              </p>
              <button
                type="button"
                onClick={() => {
                  setFilter('all');
                  setSearchQuery('');
                }}
                className="min-h-[44px] px-4 py-2 text-xs font-medium bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 rounded-xl hover:opacity-90 transition-opacity whitespace-nowrap shrink-0"
              >
                Reset Filters
              </button>
            </div>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {filteredEvents.map((evt) => {
                const isClean = evt.analysis.category === ThreatCategory.Clean;
                const isCriticalOrHigh =
                  evt.analysis.severity === ThreatSeverity.Critical ||
                  evt.analysis.severity === ThreatSeverity.High;
                const isLiveTelegram =
                  evt.eventOrigin === 'telegram_live' || evt.id.startsWith('tg-');

                return (
                  <button
                    key={evt.id}
                    type="button"
                    onClick={() => {
                      setSelectedEventId(evt.id);
                      setActionFeedback(null);
                      setShowCiphertext(false);
                      setUrlIntelReport(null);
                      setFileIntelReport(null);
                    }}
                    className="w-full text-left p-4 sm:px-5 sm:py-4 hover:bg-slate-50/90 dark:hover:bg-slate-800/40 transition-colors flex items-start gap-3.5 min-h-[68px]"
                  >
                    {/* Semantic Status Icon Container (36px circular) */}
                    <div
                      className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                        isClean
                          ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400'
                          : evt.analysis.category === ThreatCategory.Malware
                          ? 'bg-red-50 text-red-600 dark:bg-red-950/60 dark:text-red-400'
                          : isCriticalOrHigh
                          ? 'bg-red-50 text-red-600 dark:bg-red-950/60 dark:text-red-400'
                          : 'bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-400'
                      }`}
                    >
                      {isClean ? (
                        <CheckCircle2 className="w-4 h-4" />
                      ) : evt.analysis.category === ThreatCategory.Malware ? (
                        <FileWarning className="w-4 h-4" />
                      ) : isCriticalOrHigh ? (
                        <ShieldAlert className="w-4 h-4" />
                      ) : (
                        <AlertTriangle className="w-4 h-4" />
                      )}
                    </div>

                    {/* Stacked Content & Clean Unboxed Metadata */}
                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">
                          {evt.senderName}{' '}
                          {evt.senderUsername && (
                            <span className="font-normal text-slate-500 dark:text-slate-400">
                              {evt.senderUsername}
                            </span>
                          )}
                        </p>
                        <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 shrink-0">
                          {formatRelativeTime(evt.timestamp)}
                        </span>
                      </div>

                      <p className="text-sm text-slate-700 dark:text-slate-300 line-clamp-2 leading-snug">
                        {evt.analysis.fileAnalysis
                          ? `[Attachment: ${evt.analysis.fileAnalysis.fileName}] ${evt.messagePreview}`
                          : evt.messagePreview}
                      </p>

                      {/* Zero-Pill Unboxed Metadata Line */}
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500 dark:text-slate-400 pt-0.5">
                        {isLiveTelegram && (
                          <>
                            <span className="font-semibold text-sky-600 dark:text-sky-400">
                              Live Telegram
                            </span>
                            <span aria-hidden="true">·</span>
                          </>
                        )}
                        <span
                          className={`font-medium ${
                            isClean
                              ? 'text-emerald-700 dark:text-emerald-400'
                              : isCriticalOrHigh
                              ? 'text-red-600 dark:text-red-400'
                              : 'text-amber-700 dark:text-amber-400'
                          }`}
                        >
                          {categoryLabel(evt.analysis.category)}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono tabular-nums">
                          Risk {evt.analysis.overallRiskScore}/100
                        </span>
                        <span aria-hidden="true">·</span>
                        <span>{evt.chatTitle}</span>
                        <span aria-hidden="true">·</span>
                        <span>{chatTypeLabel(evt.chatType)}</span>
                        <span aria-hidden="true">·</span>
                        <span>{enforcementLabel(evt.enforcement)}</span>
                      </div>
                    </div>

                    <ChevronRight className="w-4 h-4 text-slate-400 shrink-0 self-center" />
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Live Threat Verification Bench & Protection Summary */}
        <aside className="lg:col-span-4 space-y-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="space-y-1">
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                Real-Time Alert Test Bench
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Test live Telegram bot detection from your phone or run an on-device simulation
                packet below.
              </p>
            </div>

            {/* 1-Tap Live Phone -> Telegram Bot End-to-End Test Helper */}
            <div className="bg-sky-50/80 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-800/80 rounded-xl p-3.5 space-y-2.5">
              <p className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Test Live Telegram Bot Detection (Safe EICAR Test):
              </p>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                Normal messages, photos, and voice chats are silently ignored. Send a harmless
                cybersecurity test file or trigger text to{' '}
                <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                  {botPolicy.botUsername ? `@${botPolicy.botUsername}` : 'your connected bot'}
                </span>{' '}
                in Telegram:
              </p>
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={async () => {
                    const eicarContent =
                      'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
                    const testFile = new File([eicarContent], 'eicar_virus_test.txt', {
                      type: 'text/plain',
                    });
                    try {
                      if (
                        typeof navigator.canShare === 'function' &&
                        navigator.canShare({ files: [testFile] })
                      ) {
                        await navigator.share({
                          files: [testFile],
                          title: 'SentinelGram Virus Test File',
                        });
                        setPhoneTestFeedback(
                          `Shared harmless EICAR test file — pick Telegram → ${
                            botPolicy.botUsername ? `@${botPolicy.botUsername}` : 'your bot'
                          } and watch the alert appear here in ~2s!`
                        );
                        return;
                      }
                    } catch {
                      // User cancelled share sheet or unsupported; fallback to download
                    }
                    const blob = new Blob([eicarContent], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'eicar_virus_test.txt';
                    a.click();
                    URL.revokeObjectURL(url);
                    setPhoneTestFeedback(
                      `Downloaded harmless eicar_virus_test.txt — attach & send it to ${
                        botPolicy.botUsername ? `@${botPolicy.botUsername}` : 'your bot'
                      } in Telegram!`
                    );
                  }}
                  className="w-full min-h-[40px] px-3 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors flex items-center justify-center gap-1.5"
                >
                  <Send className="w-3.5 h-3.5 shrink-0" />
                  <span>Share Harmless Virus Test File to Telegram</span>
                </button>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText('Invoice.pdf.exe');
                        setPhoneTestFeedback(
                          `Copied "Invoice.pdf.exe" — paste & send it to ${
                            botPolicy.botUsername ? `@${botPolicy.botUsername}` : 'your bot'
                          } in Telegram!`
                        );
                      } catch {
                        setPhoneTestFeedback('Type Invoice.pdf.exe to your bot in Telegram.');
                      }
                    }}
                    className="flex-1 min-h-[38px] px-3 py-1.5 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors flex items-center justify-center gap-1.5"
                  >
                    <Copy className="w-3.5 h-3.5 shrink-0" />
                    <span>Copy &ldquo;Invoice.pdf.exe&rdquo;</span>
                  </button>

                  {botPolicy.botUsername && (
                    <a
                      href={`https://t.me/${botPolicy.botUsername}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="min-h-[38px] px-3 py-1.5 rounded-xl text-xs font-semibold border border-sky-300 dark:border-sky-800 text-sky-700 dark:text-sky-300 bg-white dark:bg-slate-900 hover:bg-sky-50 dark:hover:bg-sky-950/60 transition-colors inline-flex items-center gap-1 shrink-0"
                    >
                      <span>Open @{botPolicy.botUsername}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              </div>
              {phoneTestFeedback && (
                <p className="text-[11px] font-medium text-emerald-700 dark:text-emerald-400 leading-relaxed">
                  {phoneTestFeedback}
                </p>
              )}
            </div>

            <div className="divide-y divide-slate-100 dark:divide-slate-800 border-t border-b border-slate-100 dark:border-slate-800">
              {THREAT_TEST_SCENARIOS.map((scn, idx) => (
                <div key={scn.label} className="py-3 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">
                      {scn.label}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                      {scn.chatTitle} · {scn.senderUsername}
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={simulatingIdx !== null}
                    onClick={() => handleRunScenario(idx)}
                    className="min-h-[40px] px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-sky-600 hover:text-white dark:hover:bg-sky-600 transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
                  >
                    {simulatingIdx === idx ? 'Testing...' : 'Trigger Alert'}
                  </button>
                </div>
              ))}
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400">
              {botPolicy.connected && botPolicy.personalWarningChatId
                ? `Connected: triggering a threat also dispatches a real Telegram warning DM to Chat ID ${botPolicy.personalWarningChatId}.`
                : 'Connect your Bot Token and Personal Chat ID in Bot & Alerts to receive live warnings inside the Telegram Android app.'}
            </p>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                Active Shield Policies
              </h3>
            </div>
            <div className="space-y-2.5 text-xs text-slate-600 dark:text-slate-400">
              <div className="flex items-center justify-between">
                <span>Live Bot Scan Scope</span>
                <span className="font-medium text-emerald-700 dark:text-emerald-400">
                  {botPolicy.onlyScamAndVirusFiles !== false
                    ? 'Scam & Virus Files Only'
                    : 'Files + Phishing Links'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Voice Chats &amp; Clean Files</span>
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  Silently Ignored
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Detection Sensitivity Threshold</span>
                <span className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                  Risk &ge; {botPolicy.riskThreshold}/100
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Personal Telegram Warning DM</span>
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  {botPolicy.autoPersonalWarningOnThreat ? 'Enabled' : 'Manual'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Automated Group Reply Warning</span>
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  {botPolicy.autoReplyInGroupChats ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>File Protection Signatures</span>
                <span className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                  {PROTECTED_FILE_EXTENSIONS.length} exts · {SUSPICIOUS_LURE_KEYWORDS.length} lures
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Shield Matrix Architecture</span>
                <span className="font-semibold text-sky-600 dark:text-sky-400">
                  14 Active Defense Layers
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Redirect Tracer &amp; Unshortener</span>
                <span className="font-medium text-emerald-700 dark:text-emerald-400">
                  Layer 11 (bit.ly/t.co/open redirects)
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Dynamic Cloud Sandboxing</span>
                <span className="font-medium text-emerald-700 dark:text-emerald-400">
                  Layer 12 (VirusTotal / Detonation)
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Social Engineering &amp; Wallet Filter</span>
                <span className="font-medium text-emerald-700 dark:text-emerald-400">
                  Layer 13 (Advance-Fee / Impersonation)
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Operational Defense &amp; 20MB Limit</span>
                <span className="font-medium text-emerald-700 dark:text-emerald-400">
                  Layer 14 (Anti-Flood &amp; Scam Channels)
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Multi-Engine Threat Feeds</span>
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  MalwareBazaar · URLhaus · MetaMask
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>E2EE Snippet Redaction in Alerts</span>
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  {botPolicy.e2eeRedactPreviewInWarnings ? 'Strict Redaction' : 'Standard Preview'}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('bot')}
              className="w-full min-h-[44px] mt-1 px-4 py-2 text-xs font-medium border border-slate-200 dark:border-slate-800 rounded-xl text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap"
            >
              Adjust Response Rules
            </button>
          </div>
        </aside>
      </div>

      {/* Forensic Event Inspector Bottom Sheet (Mobile) / Modal Drawer (Desktop) */}
      {selectedEvent && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/50 backdrop-blur-xs flex items-end sm:items-center justify-center p-0 sm:p-6"
          onClick={() => setSelectedEventId(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="forensic-dialog-title"
            className="w-full sm:max-w-2xl max-h-[88vh] bg-white dark:bg-slate-900 rounded-t-3xl sm:rounded-2xl border border-slate-200 dark:border-slate-800 flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Mobile Drag Handle */}
            <div className="sm:hidden w-10 h-1.5 bg-slate-300 dark:bg-slate-700 rounded-full mx-auto mt-3" />

            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {chatTypeLabel(selectedEvent.chatType)} · {selectedEvent.chatTitle}
                </p>
                <h3
                  id="forensic-dialog-title"
                  className="text-base font-semibold text-slate-900 dark:text-slate-50 truncate"
                >
                  {categoryLabel(selectedEvent.analysis.category)} — Risk{' '}
                  <span className="font-mono tabular-nums">
                    {selectedEvent.analysis.overallRiskScore}/100
                  </span>
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEventId(null)}
                aria-label="Close inspector"
                className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-xl text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-6 text-sm">
              {/* Sender & Message Payload */}
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <span>Sender: {selectedEvent.senderName}</span>
                  {selectedEvent.senderUsername && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono">{selectedEvent.senderUsername}</span>
                    </>
                  )}
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">
                    Inference {selectedEvent.analysis.inferenceLatencyMs} ms
                  </span>
                </div>
                <p className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 leading-relaxed break-words">
                  {selectedEvent.messagePreview || '(Media / file packet without text caption)'}
                </p>
              </div>

              {/* Local ML Explanation Signals */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                  On-Device ML &amp; Heuristic Evidence
                </h4>
                <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                  {selectedEvent.analysis.explanation.map((item, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-sky-600 dark:text-sky-400 font-bold">·</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* URL Lexical Breakdown & Multi-Engine Scam Intel if present */}
              {selectedEvent.analysis.urlAnalyses.length > 0 && (
                <div className="space-y-3 pt-3 border-t border-slate-100 dark:border-slate-800">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      Inspected Links ({selectedEvent.analysis.urlAnalyses.length}) &amp; Free Scam Scanners
                    </h4>
                    <button
                      type="button"
                      disabled={checkingUrlIntel}
                      onClick={async () => {
                        const targetUrl = selectedEvent.analysis.urlAnalyses[0]?.url;
                        if (!targetUrl) return;
                        setCheckingUrlIntel(true);
                        try {
                          const report = await checkUrlMultiEngineIntel(targetUrl);
                          setUrlIntelReport(report);
                        } catch {
                          setActionFeedback('Could not reach multi-engine threat intelligence endpoint.');
                        } finally {
                          setCheckingUrlIntel(false);
                        }
                      }}
                      className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-sky-600 hover:text-white dark:hover:bg-sky-600 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${checkingUrlIntel ? 'animate-spin' : ''}`} />
                      <span>
                        {checkingUrlIntel ? 'Querying Feeds...' : 'Run Multi-Engine Domain Check'}
                      </span>
                    </button>
                  </div>

                  {selectedEvent.analysis.urlAnalyses.map((u, idx) => (
                    <div key={idx} className="space-y-1 text-xs">
                      <p className="font-mono break-all text-slate-800 dark:text-slate-200">
                        {u.url}
                      </p>
                      <p className="text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                        Host: {u.hostname} · Link Risk: {u.riskScore}/100 · Entropy:{' '}
                        {u.shannonEntropy} bits
                        {u.impersonatedBrand ? ` · Impersonates: ${u.impersonatedBrand}` : ''}
                      </p>
                    </div>
                  ))}

                  {urlIntelReport && (
                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-slate-600 dark:text-slate-400">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          Live Feed Verdicts ({urlIntelReport.registrableDomain})
                        </span>
                        <span className="font-mono tabular-nums">
                          {urlIntelReport.domainAgeDays !== null
                            ? `RDAP Age: ${urlIntelReport.domainAgeDays}d`
                            : 'RDAP Age: n/a'}
                          {urlIntelReport.aggregatedRiskBoost > 0
                            ? ` · +${urlIntelReport.aggregatedRiskBoost} Risk Boost`
                            : ' · No Blocklist Hit'}
                        </span>
                      </div>
                      <div className="divide-y divide-slate-200/70 dark:divide-slate-800">
                        {urlIntelReport.engines.map((eng) => (
                          <div
                            key={eng.engineId}
                            className="py-1.5 flex items-start justify-between gap-3"
                          >
                            <div className="min-w-0">
                              <span className="font-medium text-slate-900 dark:text-slate-100">
                                {eng.engineName}
                              </span>
                              <span className="text-slate-500 dark:text-slate-400">
                                {' '}
                                · {eng.summary}
                              </span>
                            </div>
                            <a
                              href={eng.lookupUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={`shrink-0 font-mono hover:underline flex items-center gap-1 ${
                                eng.status === 'malicious'
                                  ? 'text-red-600 dark:text-red-400 font-semibold'
                                  : eng.status === 'suspicious'
                                  ? 'text-amber-600 dark:text-amber-400 font-semibold'
                                  : eng.status === 'clean' || eng.status === 'known_good'
                                  ? 'text-emerald-700 dark:text-emerald-400'
                                  : 'text-sky-600 dark:text-sky-400'
                              }`}
                            >
                              <span>{eng.status}</span>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                    {getUrlScannerLinks(selectedEvent.analysis.urlAnalyses[0].url).map((link) => (
                      <a
                        key={link.id}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="min-h-[40px] px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 hover:border-sky-500 dark:hover:border-sky-500 transition-colors flex items-center justify-between gap-2 text-xs"
                      >
                        <div className="min-w-0 truncate">
                          <span className="font-medium text-slate-900 dark:text-slate-100">
                            {link.name}
                          </span>
                          <span className="text-slate-500 dark:text-slate-400">
                            {' '}
                            · {link.badge}
                          </span>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400 shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* File Malware Inspection & Structured Telegram Alert if present */}
              {selectedEvent.analysis.fileAnalysis && (
                <div className="space-y-3 pt-3 border-t border-slate-100 dark:border-slate-800">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      Attachment Virus &amp; Multi-Engine Telemetry
                    </h4>
                    <div className="flex flex-wrap items-center gap-3">
                      <button
                        type="button"
                        disabled={checkingFileIntel}
                        onClick={async () => {
                          if (!selectedEvent.analysis.fileAnalysis) return;
                          setCheckingFileIntel(true);
                          try {
                            const report = await checkFileMultiEngineIntel({
                              sha256: selectedEvent.analysis.fileAnalysis.sha256,
                              fileName: selectedEvent.analysis.fileAnalysis.fileName,
                            });
                            setFileIntelReport(report);
                          } catch {
                            setActionFeedback('Could not reach multi-engine file hash lookup.');
                          } finally {
                            setCheckingFileIntel(false);
                          }
                        }}
                        className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-sky-600 hover:text-white dark:hover:bg-sky-600 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 disabled:opacity-50"
                      >
                        <Globe className={`w-3.5 h-3.5 ${checkingFileIntel ? 'animate-spin' : ''}`} />
                        <span>
                          {checkingFileIntel ? 'Checking Hash...' : 'Run Multi-Engine Hash Check'}
                        </span>
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          if (!selectedEvent.analysis.fileAnalysis) return;
                          const alertStr = formatSuspiciousFileAlert({
                            senderUsername: selectedEvent.senderUsername,
                            senderName: selectedEvent.senderName,
                            fileName: selectedEvent.analysis.fileAnalysis.fileName,
                            reason:
                              selectedEvent.analysis.fileAnalysis.primaryReason ||
                              'Suspicious executable payload',
                          });
                          await navigator.clipboard.writeText(alertStr);
                          setActionFeedback('Copied structured file warning alert to clipboard.');
                        }}
                        className="text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1 whitespace-nowrap"
                      >
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Alert</span>
                      </button>
                    </div>
                  </div>

                  {selectedEvent.analysis.fileAnalysis.riskScore >= 45 && (
                    <pre className="p-3.5 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono whitespace-pre-wrap leading-relaxed">
                      {formatSuspiciousFileAlert({
                        senderUsername: selectedEvent.senderUsername,
                        senderName: selectedEvent.senderName,
                        fileName: selectedEvent.analysis.fileAnalysis.fileName,
                        reason:
                          selectedEvent.analysis.fileAnalysis.primaryReason ||
                          'Executable file with double extension',
                      })}
                    </pre>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono tabular-nums text-slate-700 dark:text-slate-300">
                    <div>File: {selectedEvent.analysis.fileAnalysis.fileName}</div>
                    <div>MIME: {selectedEvent.analysis.fileAnalysis.mimeType}</div>
                    <div>Header Hex: {selectedEvent.analysis.fileAnalysis.magicHeaderHex}</div>
                    <div>Entropy: {selectedEvent.analysis.fileAnalysis.byteEntropy} bits/B</div>
                    <div className="sm:col-span-2 truncate">
                      SHA-256: {selectedEvent.analysis.fileAnalysis.sha256}
                    </div>
                  </div>

                  {fileIntelReport && (
                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-slate-600 dark:text-slate-400">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          Live SHA-256 Threat Feed Verdicts
                        </span>
                        <span className="font-mono tabular-nums">
                          {fileIntelReport.aggregatedRiskBoost > 0
                            ? `+${fileIntelReport.aggregatedRiskBoost} Malware Feed Boost`
                            : 'Checked Across Public IOC Feeds'}
                        </span>
                      </div>
                      <div className="divide-y divide-slate-200/70 dark:divide-slate-800">
                        {fileIntelReport.engines.map((eng) => (
                          <div
                            key={eng.engineId}
                            className="py-1.5 flex items-start justify-between gap-3"
                          >
                            <div className="min-w-0">
                              <span className="font-medium text-slate-900 dark:text-slate-100">
                                {eng.engineName}
                              </span>
                              <span className="text-slate-500 dark:text-slate-400">
                                {' '}
                                · {eng.summary}
                              </span>
                            </div>
                            <a
                              href={eng.lookupUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={`shrink-0 font-mono hover:underline flex items-center gap-1 ${
                                eng.status === 'malicious'
                                  ? 'text-red-600 dark:text-red-400 font-semibold'
                                  : eng.status === 'known_good'
                                  ? 'text-emerald-700 dark:text-emerald-400 font-semibold'
                                  : 'text-sky-600 dark:text-sky-400'
                              }`}
                            >
                              <span>{eng.status}</span>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="space-y-1.5 pt-1">
                    <p className="text-xs font-medium text-slate-600 dark:text-slate-400">
                      Free Multi-Engine File Hash Verification Portals:
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {getFileScannerLinks(selectedEvent.analysis.fileAnalysis.sha256).map(
                        (link) => (
                          <a
                            key={link.id}
                            href={link.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="min-h-[40px] px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 hover:border-sky-500 dark:hover:border-sky-500 transition-colors flex items-center justify-between gap-2 text-xs"
                          >
                            <div className="min-w-0 truncate">
                              <span className="font-medium text-slate-900 dark:text-slate-100">
                                {link.name}
                              </span>
                              <span className="text-slate-500 dark:text-slate-400">
                                {' '}
                                · {link.badge}
                              </span>
                            </div>
                            <ExternalLink className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400 shrink-0" />
                          </a>
                        )
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* E2EE Ciphertext Proof Toggle */}
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-600 dark:text-slate-400">
                    End-to-End Encrypted Storage Envelope (AES-256-GCM)
                  </span>
                  <button
                    type="button"
                    onClick={() => setShowCiphertext((v) => !v)}
                    className="text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
                  >
                    {showCiphertext ? 'Hide Raw Ciphertext' : 'Inspect At-Rest Ciphertext'}
                  </button>
                </div>
                {showCiphertext && selectedEnvelope && (
                  <pre className="p-3 rounded-xl bg-slate-950 text-slate-200 text-[11px] font-mono overflow-x-auto leading-relaxed">
                    {JSON.stringify(
                      {
                        algorithm: selectedEnvelope.algorithm,
                        keyFingerprint: selectedEnvelope.keyFingerprint,
                        ivBase64: selectedEnvelope.ivBase64,
                        ciphertextPreview: `${selectedEnvelope.ciphertextBase64.slice(0, 96)}...`,
                      },
                      null,
                      2
                    )}
                  </pre>
                )}
              </div>

              {actionFeedback && (
                <p className="text-xs font-medium text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/50 p-3 rounded-xl">
                  {actionFeedback}
                </p>
              )}
            </div>

            {/* Action Bar */}
            <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 flex flex-wrap items-center justify-between gap-3">
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => handleManualAction(selectedEvent, 'personal_warning')}
                className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>
                  {busyAction === 'personal_warning'
                    ? 'Sending Alert...'
                    : 'Send Personal Telegram Warning'}
                </span>
              </button>

              <div className="flex items-center gap-2">
                {selectedEvent.telegramMessageId && (
                  <>
                    <button
                      type="button"
                      disabled={busyAction !== null}
                      onClick={() => handleManualAction(selectedEvent, 'chat_reply')}
                      className="min-h-[44px] px-3.5 py-2 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
                    >
                      Warn in Chat
                    </button>
                    <button
                      type="button"
                      disabled={busyAction !== null}
                      onClick={() => handleManualAction(selectedEvent, 'delete_message')}
                      className="min-h-[44px] px-3.5 py-2 rounded-xl text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 disabled:opacity-50"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Delete Msg</span>
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
