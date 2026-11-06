/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Cpu,
  Lock,
  Moon,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  Sun,
  Wifi,
  X,
} from 'lucide-react';
import {
  ChatSourceType,
  EnforcementStatus,
  ThreatCategory,
  ThreatSeverity,
  type BotInspectionDiagnostic,
  type BotPolicyConfig,
  type CloudHeartbeatConfig,
  type ConnectedTelegramChat,
  type EncryptedEnvelope,
  type HeartbeatPingLog,
  type MlAnalysisResult,
  type ThreatEvent,
  type TrainingSample,
} from './types/security';
import { cryptoVault, type VaultStateSummary } from './services/cryptoVault';
import { formatSuspiciousFileAlert, localMlEngine } from './services/localMlEngine';
import {
  DEFAULT_BOT_POLICY,
  THREAT_TEST_SCENARIOS,
  generateInitialBaselineEvents,
} from './services/seedEvents';
import { LiveShieldView } from './components/LiveShieldView';
import { ScannerMlView } from './components/ScannerMlView';
import { BotIntegrationView } from './components/BotIntegrationView';
import { AnalyticsReportView } from './components/AnalyticsReportView';
import { VaultPrivacyView } from './components/VaultPrivacyView';
import {
  OfflineIndicator,
  PWAInstallBanner,
  PWAInstallButton,
} from './components/PWAInstallPrompt';
import { useLiveNetworkStatus, usePWAInstall } from './hooks/usePWAInstall';

type ActiveTab = 'shield' | 'scanner' | 'bot' | 'analytics' | 'vault';

function playSubtleAlertChime() {
  try {
    const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc.frequency.setValueAtTime(880, ctx.currentTime + 0.09); // A5
    gain.gain.setValueAtTime(0.06, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.29);
  } catch {
    // Ignore audio context autoplay restrictions gracefully
  }
}

function formatWarningMessage(evt: ThreatEvent, redactPreview: boolean): string {
  if (evt.analysis.fileAnalysis && evt.analysis.fileAnalysis.riskScore >= 45) {
    return formatSuspiciousFileAlert({
      senderUsername: evt.senderUsername,
      senderName: evt.senderName,
      fileName: evt.analysis.fileAnalysis.fileName,
      reason: evt.analysis.fileAnalysis.primaryReason,
      sourceChatLabel: `${evt.chatTitle} (${evt.chatType})`,
    });
  }

  const categoryUpper = evt.analysis.category.toUpperCase();
  const urlsInfo =
    evt.analysis.urlAnalyses.length > 0
      ? `\nFlagged Host: ${evt.analysis.urlAnalyses.map((u) => u.hostname.replace(/\./g, '[.]')).join(', ')}`
      : '';
  const snippetLine = redactPreview
    ? '\nContent Preview: [Redacted by SentinelGram E2EE Policy]'
    : `\nSnippet: "${evt.messagePreview.slice(0, 140)}"`;

  return (
    `⚠️ Suspicious ${categoryUpper} Detected\n\n` +
    `User: ${evt.senderUsername || evt.senderName}\n` +
    `Chat: ${evt.chatTitle} (${evt.chatType})\n` +
    `Risk Score: ${evt.analysis.overallRiskScore}/100` +
    urlsInfo +
    snippetLine +
    `\nReason: ${evt.analysis.explanation[0] || 'Suspicious ML pattern'}\n\n` +
    `Recommendation:\nDo NOT click untrusted links or share verification codes.`
  );
}

export default function App() {
  const pwa = usePWAInstall();
  const network = useLiveNetworkStatus();
  const isOnline = network.isOnline;
  const [activeTab, setActiveTab] = useState<ActiveTab>('shield');
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    return localStorage.getItem('sentinelgram_theme') === 'dark';
  });

  const [booting, setBooting] = useState(true);
  const [vaultSummary, setVaultSummary] = useState<VaultStateSummary>({
    initialized: false,
    locked: false,
    passphraseProtected: false,
    aesKeyFingerprint: '',
    ecdhPublicKeyFingerprint: '',
    encryptedRecordCount: 0,
  });
  const [unlockPassphrase, setUnlockPassphrase] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);

  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [rawEnvelopes, setRawEnvelopes] = useState<EncryptedEnvelope[]>([]);
  const [botPolicy, setBotPolicy] = useState<BotPolicyConfig>(DEFAULT_BOT_POLICY);
  const [customSamples, setCustomSamples] = useState<TrainingSample[]>([]);
  const [modelVersionTick, setModelVersionTick] = useState(0);
  const [hasServerBotToken, setHasServerBotToken] = useState(false);

  const [isPollingNow, setIsPollingNow] = useState(false);
  const [lastPolledAt, setLastPolledAt] = useState<number | null>(null);
  const [watcherTotalReceived, setWatcherTotalReceived] = useState(0);
  const [watcherCleanIgnored, setWatcherCleanIgnored] = useState(0);
  const [watcherLastError, setWatcherLastError] = useState<string | null>(null);
  const [connectedChats, setConnectedChats] = useState<ConnectedTelegramChat[]>([]);
  const [recentInspections, setRecentInspections] = useState<BotInspectionDiagnostic[]>([]);
  const watcherSeqRef = useRef<number>(0);
  const seenUpdateIdsRef = useRef<Set<number>>(new Set());
  const eventsRef = useRef<ThreatEvent[]>([]);
  const serverBootIdRef = useRef<string | null>(null);
  const [serverPingMs, setServerPingMs] = useState<number | null>(null);
  const [serverUpdateAvailable, setServerUpdateAvailable] = useState(false);

  // Real-time floating alert notification banner + live Telegram sync notice
  const [liveAlertEvent, setLiveAlertEvent] = useState<ThreatEvent | null>(null);
  const [liveSyncNotice, setLiveSyncNotice] = useState<{
    tone: 'emerald' | 'amber';
    title: string;
    detail: string;
  } | null>(null);
  const [incomingSharedPayload, setIncomingSharedPayload] = useState<{
    text: string;
    analysis: MlAnalysisResult;
  } | null>(null);

  // Cloud Heartbeat 24/7 Monitor State
  const [cloudHeartbeat, setCloudHeartbeat] = useState<CloudHeartbeatConfig | null>(null);

  const syncHeartbeatStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/heartbeat/status', { cache: 'no-store' });
      const data = await res.json();
      if (data?.ok && data.heartbeat) {
        setCloudHeartbeat(data.heartbeat);
      }
    } catch {
      // Non-fatal
    }
  }, []);

  const handleUpdateHeartbeatConfig = useCallback(async (patch: Partial<CloudHeartbeatConfig>) => {
    try {
      const res = await fetch('/api/heartbeat/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const data = await res.json();
      if (data?.ok && data.heartbeat) {
        setCloudHeartbeat(data.heartbeat);
      }
    } catch {
      // Non-fatal
    }
  }, []);

  const handleTriggerHeartbeatPingNow = useCallback(async (): Promise<HeartbeatPingLog | null> => {
    try {
      const res = await fetch('/api/heartbeat/ping-now', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (data?.ok && data.heartbeat) {
        setCloudHeartbeat(data.heartbeat);
      }
      return data?.entry || null;
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('sentinelgram_theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const hydrateUnlockedVaultData = useCallback(async () => {
    const [storedConfig, storedSamples] = await Promise.all([
      cryptoVault.loadEncryptedConfig<BotPolicyConfig>(),
      cryptoVault.loadCustomSamples<TrainingSample>(),
    ]);

    if (storedSamples.length > 0) {
      setCustomSamples(storedSamples);
      localMlEngine.resetAndTrainBase(storedSamples);
      setModelVersionTick((v) => v + 1);
    }

    const strictFilesDefault = storedConfig ? storedConfig.onlyScamAndVirusFiles !== false : true;
    if (storedConfig) {
      const migratedThresholdOnce =
        localStorage.getItem('sentinelgram_threshold_v2_migrated') === '1';
      const migratedBotOnlyAlertOnce =
        localStorage.getItem('sentinelgram_bot_only_alert_v1') === '1';
      const normalizedThreshold =
        !migratedThresholdOnce && storedConfig.riskThreshold === 60
          ? 50
          : storedConfig.riskThreshold;
      if (!migratedThresholdOnce) {
        localStorage.setItem('sentinelgram_threshold_v2_migrated', '1');
      }
      if (!migratedBotOnlyAlertOnce) {
        localStorage.setItem('sentinelgram_bot_only_alert_v1', '1');
      }
      const upgradedConfig: BotPolicyConfig = {
        ...storedConfig,
        onlyScamAndVirusFiles: strictFilesDefault,
        riskThreshold: normalizedThreshold,
        autoPersonalWarningOnThreat: migratedBotOnlyAlertOnce
          ? storedConfig.autoPersonalWarningOnThreat
          : true,
        autoReplyInGroupChats: false,
        autoDeleteCriticalInGroups: false,
      };
      setBotPolicy(upgradedConfig);
      if (
        (storedConfig.onlyScamAndVirusFiles === undefined ||
          normalizedThreshold !== storedConfig.riskThreshold ||
          !migratedBotOnlyAlertOnce ||
          storedConfig.autoReplyInGroupChats ||
          storedConfig.autoDeleteCriticalInGroups) &&
        cryptoVault.isUnlocked()
      ) {
        void cryptoVault.saveEncryptedConfig(upgradedConfig);
      }
    }

    let loadedEvents = await cryptoVault.loadEncryptedList<ThreatEvent>();
    if (loadedEvents.length === 0 && cryptoVault.readRawEnvelopes().length === 0) {
      loadedEvents = await generateInitialBaselineEvents();
      const envs = await cryptoVault.saveEncryptedList(loadedEvents);
      setRawEnvelopes(envs);
    } else {
      // Purge any previously logged clean voice/media/message items from live Telegram feed
      const cleanedEvents = loadedEvents.filter((evt) => {
        const isLiveTg = evt.eventOrigin === 'telegram_live' || evt.id.startsWith('tg-');
        if (!isLiveTg) return true;
        if (evt.systemNotice) return true;
        return evt.analysis.category !== ThreatCategory.Clean;
      });
      if (cleanedEvents.length !== loadedEvents.length && cryptoVault.isUnlocked()) {
        loadedEvents = cleanedEvents;
        const envs = await cryptoVault.saveEncryptedList(loadedEvents);
        setRawEnvelopes(envs);
      } else {
        setRawEnvelopes(cryptoVault.readRawEnvelopes());
      }
    }

    const sortedLoaded = loadedEvents.sort((a, b) => b.timestamp - a.timestamp);
    for (const item of sortedLoaded) {
      if (typeof item.telegramUpdateId === 'number') {
        seenUpdateIdsRef.current.add(item.telegramUpdateId);
      }
    }
    eventsRef.current = sortedLoaded;
    setEvents(sortedLoaded);
    setVaultSummary(cryptoVault.getSummary());
  }, []);

  useEffect(() => {
    eventsRef.current = events;
  }, [events]);

  // Keep server-side continuous Bot Watcher synced with current botPolicy (including right after page reload or reconnecting!)
  useEffect(() => {
    if (!isOnline || !botPolicy.connected || vaultSummary.locked) return;
    fetch('/api/telegram/sync-watcher', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        botToken: botPolicy.botToken,
        enabled: botPolicy.livePollingEnabled,
        personalWarningChatId: botPolicy.personalWarningChatId,
        autoPersonalWarningOnThreat: botPolicy.autoPersonalWarningOnThreat,
        autoReplyInGroupChats: botPolicy.autoReplyInGroupChats,
        autoDeleteCriticalInGroups: botPolicy.autoDeleteCriticalInGroups,
        e2eeRedactPreviewInWarnings: botPolicy.e2eeRedactPreviewInWarnings,
        onlyScamAndVirusFiles: botPolicy.onlyScamAndVirusFiles !== false,
        riskThreshold: botPolicy.riskThreshold,
      }),
    })
      .then((r) => r.json())
      .then((d) => {
        if (!d?.ok) return;
        if (typeof d.totalUpdatesReceived === 'number') {
          setWatcherTotalReceived(d.totalUpdatesReceived);
        }
        if (typeof d.cleanIgnoredCount === 'number') {
          setWatcherCleanIgnored(d.cleanIgnoredCount);
        }
        if (Array.isArray(d.connectedChats)) {
          setConnectedChats(d.connectedChats);
        }
        if (Array.isArray(d.recentInspections)) {
          setRecentInspections(d.recentInspections);
        }
        setWatcherLastError(d.lastError || null);
        if (
          typeof d.canReadAllGroupMessages === 'boolean' &&
          d.canReadAllGroupMessages !== botPolicy.canReadAllGroupMessages
        ) {
          setBotPolicy((prev) => {
            const next = { ...prev, canReadAllGroupMessages: d.canReadAllGroupMessages };
            if (cryptoVault.isUnlocked()) void cryptoVault.saveEncryptedConfig(next);
            return next;
          });
        }
        if (d.detectedPersonalChatId && !botPolicy.personalWarningChatId) {
          setBotPolicy((prev) => {
            const next = { ...prev, personalWarningChatId: String(d.detectedPersonalChatId) };
            if (cryptoVault.isUnlocked()) void cryptoVault.saveEncryptedConfig(next);
            return next;
          });
        }
      })
      .catch(() => {});
  }, [
    botPolicy.connected,
    botPolicy.botToken,
    botPolicy.livePollingEnabled,
    botPolicy.personalWarningChatId,
    botPolicy.autoPersonalWarningOnThreat,
    botPolicy.autoReplyInGroupChats,
    botPolicy.autoDeleteCriticalInGroups,
    botPolicy.e2eeRedactPreviewInWarnings,
    botPolicy.onlyScamAndVirusFiles,
    botPolicy.riskThreshold,
    botPolicy.canReadAllGroupMessages,
    isOnline,
    vaultSummary.locked,
  ]);

  const syncCloudServerStatus = useCallback(async (allowAutoConnect = false) => {
    if (typeof navigator !== 'undefined' && !navigator.onLine) return;
    const t0 = performance.now();
    try {
      const envRes = await fetch('/api/telegram/env-status', { cache: 'no-store' });
      const d = await envRes.json();
      setServerPingMs(Math.max(1, Math.round(performance.now() - t0)));

      if (d?.serverLive?.bootId) {
        if (serverBootIdRef.current && serverBootIdRef.current !== d.serverLive.bootId) {
          setServerUpdateAvailable(true);
        } else {
          serverBootIdRef.current = String(d.serverLive.bootId);
        }
      }

      if (d?.hasServerBotToken) {
        setHasServerBotToken(true);
      }

      const srv = d?.activeBotSummary;
      if (srv?.connected) {
        if (typeof srv.totalUpdatesReceived === 'number') {
          setWatcherTotalReceived(srv.totalUpdatesReceived);
        }
        if (typeof srv.cleanIgnoredCount === 'number') {
          setWatcherCleanIgnored(srv.cleanIgnoredCount);
        }
        if (Array.isArray(srv.connectedChats)) {
          setConnectedChats(srv.connectedChats);
        }
        if (Array.isArray(srv.recentInspections)) {
          setRecentInspections(srv.recentInspections);
        }
        const manualDisc = localStorage.getItem('sentinelgram_manual_disconnect') === '1';
        if (allowAutoConnect && !manualDisc) {
          setBotPolicy((prev) => {
            if (prev.connected && prev.botUsername) return prev;
            const next: BotPolicyConfig = {
              ...prev,
              botUsername: srv.botUsername || prev.botUsername || 'telegram_bot',
              botId: srv.botId ?? prev.botId,
              canReadAllGroupMessages: Boolean(srv.canReadAllGroupMessages),
              personalWarningChatId:
                prev.personalWarningChatId ||
                (srv.detectedPersonalChatId ? String(srv.detectedPersonalChatId) : ''),
              connected: true,
              livePollingEnabled: true,
            };
            if (cryptoVault.isUnlocked()) {
              void cryptoVault.saveEncryptedConfig(next);
            }
            return next;
          });
        }
      }
    } catch {
      // Transient Wi-Fi / Mobile Data handoff; retried automatically
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const summary = await cryptoVault.initialize();
        if (!mounted) return;
        setVaultSummary(summary);
        if (!summary.locked) {
          await hydrateUnlockedVaultData();
        }

        // Sync live Cloud Server status & active Telegram Bot watcher immediately over Wi-Fi / Mobile Data
        if (mounted) {
          await syncCloudServerStatus(!summary.locked);
          await syncHeartbeatStatus();
        }

        // Handle Android Share Sheet (Share -> SentinelGram) incoming text/URL
        if (mounted && !summary.locked && typeof window !== 'undefined') {
          const params = new URLSearchParams(window.location.search);
          const sharedParts = [params.get('title'), params.get('text'), params.get('url')]
            .map((s) => (s || '').trim())
            .filter(Boolean);
          if (sharedParts.length > 0) {
            const combinedShared = sharedParts.join(' ');
            window.history.replaceState({}, '', window.location.pathname);
            const sharedEval = await localMlEngine.evaluateEvent({ text: combinedShared });
            setIncomingSharedPayload({ text: combinedShared, analysis: sharedEval });
            setActiveTab('scanner');
            const sharedEvt: ThreatEvent = {
              id: `share-${Date.now()}`,
              eventOrigin: 'local_scan',
              timestamp: Date.now(),
              chatId: 'android-share',
              chatTitle: 'Android Share Inspect',
              chatType: ChatSourceType.LocalScan,
              senderName: 'Shared Content',
              senderUsername: '',
              messagePreview: combinedShared,
              analysis: sharedEval,
              enforcement:
                sharedEval.category === ThreatCategory.Clean
                  ? EnforcementStatus.Allowed
                  : EnforcementStatus.Flagged,
              personalWarningSent: false,
              encryptedAtRest: true,
            };
            if (sharedEval.category !== ThreatCategory.Clean) {
              setLiveAlertEvent(sharedEvt);
            }
            const nextEvents = [sharedEvt, ...eventsRef.current].slice(0, 250);
            eventsRef.current = nextEvents;
            setEvents(nextEvents);
            if (cryptoVault.isUnlocked()) {
              const envs = await cryptoVault.saveEncryptedList(nextEvents);
              setRawEnvelopes(envs);
            }
          }
        }
      } finally {
        if (mounted) setBooting(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [hydrateUnlockedVaultData, syncCloudServerStatus]);

  const persistEvents = useCallback(async (updated: ThreatEvent[]) => {
    const sorted = [...updated].sort((a, b) => b.timestamp - a.timestamp).slice(0, 250);
    eventsRef.current = sorted;
    setEvents(sorted);
    if (cryptoVault.isUnlocked()) {
      const envs = await cryptoVault.saveEncryptedList(sorted);
      setRawEnvelopes(envs);
      setVaultSummary(cryptoVault.getSummary());
    }
  }, []);

  const handleUpdatePolicy = useCallback(async (patch: Partial<BotPolicyConfig>) => {
    setBotPolicy((prev) => {
      const next = { ...prev, ...patch };
      if (cryptoVault.isUnlocked()) {
        void cryptoVault.saveEncryptedConfig(next);
      }
      return next;
    });
  }, []);

  const triggerRealtimeAlertOutputs = useCallback(
    (evt: ThreatEvent, policySnapshot: BotPolicyConfig) => {
      if (evt.analysis.overallRiskScore < policySnapshot.riskThreshold) return;
      if (evt.analysis.category === ThreatCategory.Clean) return;

      setLiveAlertEvent(evt);

      if (policySnapshot.soundAlertEnabled) {
        playSubtleAlertChime();
      }

      if (
        policySnapshot.browserNotificationsEnabled &&
        'Notification' in window &&
        Notification.permission === 'granted'
      ) {
        try {
          new Notification(`SentinelGram: ${evt.analysis.category.toUpperCase()} Blocked`, {
            body: `${evt.chatTitle} — Risk ${evt.analysis.overallRiskScore}/100: ${
              evt.analysis.explanation[0] || ''
            }`,
          });
        } catch {
          // Ignore notification constructor limits inside restricted sandboxes
        }
      }
    },
    []
  );

  const dispatchTelegramAction = useCallback(
    async (
      evt: ThreatEvent,
      action: 'personal_warning' | 'chat_reply' | 'delete_message',
      policyOverride?: BotPolicyConfig
    ): Promise<{ ok: boolean; message: string }> => {
      const cfg = policyOverride || botPolicy;
      if (!cfg.connected) {
        return {
          ok: false,
          message: 'Connect your Telegram Bot API token first in Bot & Alerts.',
        };
      }

      if (action === 'personal_warning') {
        if (!cfg.personalWarningChatId.trim()) {
          return {
            ok: false,
            message: 'Configure your Personal Warning Chat ID in Bot & Alerts first.',
          };
        }
        const warningText = formatWarningMessage(evt, cfg.e2eeRedactPreviewInWarnings);
        const resp = await fetch('/api/telegram/respond', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            botToken: cfg.botToken,
            action: 'personal_warning',
            targetChatId: cfg.personalWarningChatId.trim(),
            text: warningText,
          }),
        });
        const data = await resp.json();
        if (!data.ok) {
          return { ok: false, message: data.error || 'Failed to send personal Telegram warning.' };
        }
        return {
          ok: true,
          message: `Personal warning delivered to Telegram Chat ID ${cfg.personalWarningChatId}.`,
        };
      }

      if (action === 'chat_reply') {
        const replyText =
          evt.analysis.fileAnalysis && evt.analysis.fileAnalysis.riskScore >= 45
            ? formatSuspiciousFileAlert({
                senderUsername: evt.senderUsername,
                senderName: evt.senderName,
                fileName: evt.analysis.fileAnalysis.fileName,
                reason: evt.analysis.fileAnalysis.primaryReason,
              })
            : `⚠️ Security Warning: SentinelGram local ML flagged this message as ${evt.analysis.category.toUpperCase()} ` +
              `(Risk ${evt.analysis.overallRiskScore}/100). Do not open unfamiliar links or share login codes.`;
        const resp = await fetch('/api/telegram/respond', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            botToken: cfg.botToken,
            action: 'chat_reply',
            targetChatId: evt.chatId,
            messageId: evt.telegramMessageId,
            text: replyText,
          }),
        });
        const data = await resp.json();
        return data.ok
          ? { ok: true, message: 'Automated warning reply posted in Telegram chat.' }
          : { ok: false, message: data.error || 'Unable to reply in Telegram chat.' };
      }

      const delResp = await fetch('/api/telegram/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          botToken: cfg.botToken,
          action: 'delete_message',
          targetChatId: evt.chatId,
          messageId: evt.telegramMessageId,
        }),
      });
      const delData = await delResp.json();
      return delData.ok
        ? { ok: true, message: 'Malicious message deleted from Telegram group.' }
        : { ok: false, message: delData.error || 'Unable to delete Telegram message.' };
    },
    [botPolicy]
  );

  const pollTelegramUpdatesOnce = useCallback(
    async (forceImmediate = false) => {
      if (
        (typeof navigator !== 'undefined' && !navigator.onLine) ||
        !botPolicy.connected ||
        !cryptoVault.isUnlocked()
      ) {
        return;
      }
      setIsPollingNow(true);
      try {
        const resp = await fetch('/api/telegram/updates', {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            botToken: botPolicy.botToken,
            sinceSeq: watcherSeqRef.current,
            forceImmediate,
          }),
        });
        const data = await resp.json();
        setLastPolledAt(Date.now());

        if (!data.ok) {
          setWatcherLastError(data.error || 'Unable to fetch Telegram updates.');
          return;
        }

        setWatcherLastError(data.lastError || null);
        if (typeof data.totalUpdatesReceived === 'number') {
          setWatcherTotalReceived(data.totalUpdatesReceived);
        }
        if (typeof data.cleanIgnoredCount === 'number') {
          setWatcherCleanIgnored(data.cleanIgnoredCount);
        }
        if (Array.isArray(data.connectedChats)) {
          setConnectedChats(data.connectedChats);
        }
        if (Array.isArray(data.recentInspections)) {
          setRecentInspections(data.recentInspections);
        }
        if (data.detectedPersonalChatId && !botPolicy.personalWarningChatId) {
          await handleUpdatePolicy({
            personalWarningChatId: String(data.detectedPersonalChatId),
          });
        }
        if (typeof data.latestSeq === 'number') {
          watcherSeqRef.current = data.latestSeq;
        }

        if (!Array.isArray(data.updates) || data.updates.length === 0) {
          return;
        }

        const newlyEvaluated: ThreatEvent[] = [];

        for (const upd of data.updates) {
          if (typeof upd.updateId === 'number') {
            if (seenUpdateIdsRef.current.has(upd.updateId)) continue;
            seenUpdateIdsRef.current.add(upd.updateId);
          }

          const isSystemHandshake =
            upd.eventKind === 'bot_command' ||
            upd.eventKind === 'group_joined' ||
            upd.eventKind === 'business_connected';

          const analysis = isSystemHandshake
            ? {
                category: ThreatCategory.Clean,
                severity: ThreatSeverity.Safe,
                confidence: 99,
                overallRiskScore: 4,
                inferenceLatencyMs: 0.4,
                classProbabilities: { clean: 0.99, phishing: 0.004, scam: 0.003, spam: 0.003 },
                topContributingTokens: [],
                urlAnalyses: [],
                fileAnalysis: null,
                explanation: [
                  String(
                    upd.systemNotice ||
                      'Live Telegram bot connection handshake verified and synced.'
                  ),
                ],
              }
            : await localMlEngine.evaluateEvent({
                text: upd.text || '',
                explicitUrls: Array.isArray(upd.explicitUrls) ? upd.explicitUrls : [],
                attachment: upd.attachment
                  ? {
                      fileName: String(upd.attachment.fileName || 'attachment'),
                      mimeType: String(upd.attachment.mimeType || 'application/octet-stream'),
                      fileSize: Number(upd.attachment.fileSize || 0),
                      headerHexOverride:
                        typeof upd.attachment.headerHex === 'string'
                          ? upd.attachment.headerHex
                          : undefined,
                      sha256Override:
                        typeof upd.attachment.sha256 === 'string'
                          ? upd.attachment.sha256
                          : undefined,
                      deepInspectionSignals: Array.isArray(upd.attachment.deepSignals)
                        ? upd.attachment.deepSignals
                        : undefined,
                      deepInspectionRiskBoost:
                        typeof upd.attachment.deepRiskBoost === 'number'
                          ? upd.attachment.deepRiskBoost
                          : undefined,
                    }
                  : null,
              });

          // Merge authoritative server deep-inspection verdict so server-flagged scam/malware files are guaranteed to surface
          if (!isSystemHandshake && upd.serverVerdict?.isThreat) {
            const srvScore = Number(upd.serverVerdict.riskScore || 0);
            if (srvScore > analysis.overallRiskScore) {
              analysis.overallRiskScore = srvScore;
            }
            if (analysis.category === ThreatCategory.Clean) {
              analysis.category =
                upd.serverVerdict.category === 'malware'
                  ? ThreatCategory.Malware
                  : upd.serverVerdict.category === 'phishing'
                  ? ThreatCategory.Phishing
                  : upd.serverVerdict.category === 'spam'
                  ? ThreatCategory.Spam
                  : ThreatCategory.Scam;
            }
            if (analysis.overallRiskScore >= 85) analysis.severity = ThreatSeverity.Critical;
            else if (analysis.overallRiskScore >= 68) analysis.severity = ThreatSeverity.High;
            else if (analysis.overallRiskScore >= 45) analysis.severity = ThreatSeverity.Medium;
            if (
              typeof upd.serverVerdict.reason === 'string' &&
              upd.serverVerdict.reason &&
              !analysis.explanation.includes(upd.serverVerdict.reason)
            ) {
              analysis.explanation.unshift(upd.serverVerdict.reason);
            }
          }

          const mappedChatType =
            upd.chatType === 'supergroup'
              ? ChatSourceType.Supergroup
              : upd.chatType === 'group'
              ? ChatSourceType.Group
              : upd.chatType === 'channel'
              ? ChatSourceType.Channel
              : ChatSourceType.Private;

          const isThreat =
            !isSystemHandshake &&
            (Boolean(upd.serverVerdict?.isThreat) ||
              (analysis.category !== ThreatCategory.Clean &&
                analysis.overallRiskScore >= botPolicy.riskThreshold));

          // Ignore clean files, voice chats, and benign messages so only scam/virus threats (and /start handshakes) surface
          if (!isSystemHandshake && !isThreat) {
            continue;
          }

          let enforcement: EnforcementStatus =
            upd.serverEnforcement === 'quarantined'
              ? EnforcementStatus.Quarantined
              : upd.serverEnforcement === 'personal_warned'
              ? EnforcementStatus.PersonalWarned
              : upd.serverEnforcement === 'chat_warned'
              ? EnforcementStatus.ChatWarned
              : isThreat
              ? EnforcementStatus.Flagged
              : EnforcementStatus.Allowed;

          let personalSent = Boolean(upd.serverPersonalWarningSent);

          const eventObj: ThreatEvent = {
            id: `tg-${upd.updateId}-${Date.now()}`,
            telegramUpdateId: upd.updateId,
            telegramMessageId: upd.messageId,
            eventOrigin: 'telegram_live',
            systemNotice: typeof upd.systemNotice === 'string' ? upd.systemNotice : undefined,
            timestamp: upd.timestamp || Date.now(),
            chatId: String(upd.chatId || ''),
            chatTitle: String(upd.chatTitle || 'Telegram Chat'),
            chatType: mappedChatType,
            senderName: String(upd.senderName || 'Telegram User'),
            senderUsername: String(upd.senderUsername || ''),
            messagePreview: String(upd.text || ''),
            analysis,
            enforcement,
            personalWarningSent: personalSent,
            encryptedAtRest: true,
          };

          if (isThreat) {
            setLiveSyncNotice(null);
            triggerRealtimeAlertOutputs(eventObj, botPolicy);

            if (!upd.serverAutoResponded) {
              const targetDmChat = botPolicy.personalWarningChatId.trim();
              if (botPolicy.autoPersonalWarningOnThreat && targetDmChat) {
                const dmRes = await dispatchTelegramAction(eventObj, 'personal_warning', {
                  ...botPolicy,
                  personalWarningChatId: targetDmChat,
                });
                if (dmRes.ok) {
                  personalSent = true;
                  enforcement = EnforcementStatus.PersonalWarned;
                }
              }
            }
          } else if (isSystemHandshake) {
            const needsAdminWarn =
              typeof upd.systemNotice === 'string' &&
              upd.systemNotice.toLowerCase().includes('promote');
            setLiveSyncNotice({
              tone: needsAdminWarn ? 'amber' : 'emerald',
              title: needsAdminWarn
                ? `Telegram Group Linked — Action Needed in "${eventObj.chatTitle}"`
                : `Live Telegram Bot Connected: ${eventObj.chatTitle}`,
              detail:
                upd.systemNotice ||
                `Silent Scam & Virus File Shield active in ${eventObj.chatTitle}.`,
            });
          }

          eventObj.enforcement = enforcement;
          eventObj.personalWarningSent = personalSent;
          newlyEvaluated.push(eventObj);
        }

        if (newlyEvaluated.length > 0) {
          await persistEvents([...newlyEvaluated, ...eventsRef.current]);
        }
      } catch {
        // Transient network hiccups retried automatically on next interval
      } finally {
        setIsPollingNow(false);
      }
    },
    [
      botPolicy,
      dispatchTelegramAction,
      handleUpdatePolicy,
      persistEvents,
      triggerRealtimeAlertOutputs,
    ]
  );

  useEffect(() => {
    if (
      !isOnline ||
      !botPolicy.connected ||
      !botPolicy.livePollingEnabled ||
      vaultSummary.locked
    ) {
      return;
    }
    void pollTelegramUpdatesOnce(false);
    const timer = window.setInterval(() => {
      void pollTelegramUpdatesOnce(false);
    }, 2500);
    const pingTimer = window.setInterval(() => {
      void syncCloudServerStatus(false);
      void syncHeartbeatStatus();
    }, 15000);

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        void syncCloudServerStatus(true);
        void syncHeartbeatStatus();
        void pollTelegramUpdatesOnce(true);
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.clearInterval(timer);
      window.clearInterval(pingTimer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [
    botPolicy.connected,
    botPolicy.livePollingEnabled,
    isOnline,
    network.networkTick,
    pollTelegramUpdatesOnce,
    syncCloudServerStatus,
    vaultSummary.locked,
  ]);

  const handleSimulateScenario = async (scenarioIndex: number) => {
    const scn = THREAT_TEST_SCENARIOS[scenarioIndex];
    if (!scn) return;

    const analysis = await localMlEngine.evaluateEvent({
      text: scn.text,
      attachment: scn.attachment,
    });

    let personalSent = false;
    let enforcement =
      analysis.category === ThreatCategory.Clean
        ? EnforcementStatus.Allowed
        : EnforcementStatus.Flagged;

    const simulatedEvt: ThreatEvent = {
      id: `sim-${Date.now()}`,
      eventOrigin: 'simulation',
      timestamp: Date.now(),
      chatId: 'sim-chat',
      chatTitle: scn.chatTitle,
      chatType: scn.chatType,
      senderName: scn.senderName,
      senderUsername: scn.senderUsername,
      messagePreview: scn.text,
      analysis,
      enforcement,
      personalWarningSent: false,
      encryptedAtRest: true,
    };

    triggerRealtimeAlertOutputs(simulatedEvt, botPolicy);

    if (
      analysis.category !== ThreatCategory.Clean &&
      botPolicy.connected &&
      botPolicy.autoPersonalWarningOnThreat &&
      botPolicy.personalWarningChatId.trim()
    ) {
      const dmRes = await dispatchTelegramAction(simulatedEvt, 'personal_warning', botPolicy);
      if (dmRes.ok) {
        personalSent = true;
        enforcement = EnforcementStatus.PersonalWarned;
      }
    } else if (analysis.overallRiskScore >= 85) {
      enforcement = EnforcementStatus.Quarantined;
    }

    simulatedEvt.personalWarningSent = personalSent;
    simulatedEvt.enforcement = enforcement;

    await persistEvents([simulatedEvt, ...events]);
  };

  const handleRecordScanAsEvent = async (text: string, analysis: MlAnalysisResult) => {
    const scanEvt: ThreatEvent = {
      id: `scan-${Date.now()}`,
      eventOrigin: 'local_scan',
      timestamp: Date.now(),
      chatId: 'local-workbench',
      chatTitle: 'Manual Security Scan',
      chatType: ChatSourceType.LocalScan,
      senderName: 'Local Administrator',
      senderUsername: '',
      messagePreview: text,
      analysis,
      enforcement:
        analysis.category === ThreatCategory.Clean
          ? EnforcementStatus.Allowed
          : EnforcementStatus.Flagged,
      personalWarningSent: false,
      encryptedAtRest: true,
    };

    if (analysis.category !== ThreatCategory.Clean) {
      triggerRealtimeAlertOutputs(scanEvt, botPolicy);
    }
    await persistEvents([scanEvt, ...events]);
  };

  const handleAddTrainingSample = async (
    text: string,
    label: 'clean' | 'phishing' | 'scam' | 'spam'
  ) => {
    const sample: TrainingSample = {
      id: `usr-${Date.now()}`,
      text,
      label,
      addedByUser: true,
      createdAt: Date.now(),
    };
    localMlEngine.ingestSample(sample);
    const nextSamples = [sample, ...customSamples];
    setCustomSamples(nextSamples);
    setModelVersionTick((v) => v + 1);
    if (cryptoVault.isUnlocked()) {
      await cryptoVault.saveCustomSamples(nextSamples);
    }
  };

  const handleVerifyAndConnectBot = async (
    tokenInput: string,
    clearWebhook: boolean
  ): Promise<{ ok: boolean; message: string }> => {
    const cleanedToken = tokenInput.trim().replace(/^bot(?=\d+:)/i, '');
    const resp = await fetch('/api/telegram/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ botToken: cleanedToken, clearWebhook }),
    });
    const data = await resp.json();
    if (!data.ok || !data.bot) {
      return { ok: false, message: data.error || 'Could not authenticate Telegram Bot token.' };
    }
    watcherSeqRef.current = 0;
    localStorage.removeItem('sentinelgram_manual_disconnect');
    if (Array.isArray(data.connectedChats)) {
      setConnectedChats(data.connectedChats);
    }
    await handleUpdatePolicy({
      botToken: cleanedToken,
      botUsername: data.bot.username || 'telegram_bot',
      botFirstName: data.bot.first_name || 'Shield Bot',
      botId: data.bot.id || null,
      canReadAllGroupMessages: Boolean(data.bot.can_read_all_group_messages),
      personalWarningChatId:
        botPolicy.personalWarningChatId ||
        (data.detectedPersonalChatId ? String(data.detectedPersonalChatId) : ''),
      connected: true,
      livePollingEnabled: true,
    });
    return {
      ok: true,
      message: `Connected to @${data.bot.username}. Send /start or Invoice.pdf.exe to @${data.bot.username} in Telegram (or send /status@${data.bot.username} in your group) to see live feedback immediately!`,
    };
  };

  const handleDisconnectBot = async () => {
    localStorage.setItem('sentinelgram_manual_disconnect', '1');
    if (botPolicy.botToken || hasServerBotToken) {
      void fetch('/api/telegram/sync-watcher', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ botToken: botPolicy.botToken, enabled: false }),
      }).catch(() => {});
    }
    setConnectedChats([]);
    await handleUpdatePolicy({
      botToken: '',
      botUsername: '',
      botFirstName: '',
      botId: null,
      canReadAllGroupMessages: undefined,
      connected: false,
      livePollingEnabled: false,
    });
  };

  const handleDetectPersonalChatId = async (): Promise<{
    ok: boolean;
    chatId?: string;
    message: string;
  }> => {
    const resp = await fetch('/api/telegram/updates', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        botToken: botPolicy.botToken,
        sinceSeq: 0,
        forceImmediate: true,
      }),
    });
    const data = await resp.json();
    if (!data.ok) {
      return { ok: false, message: data.error || 'Could not query Telegram updates.' };
    }

    if (data.detectedPersonalChatId) {
      await handleUpdatePolicy({ personalWarningChatId: String(data.detectedPersonalChatId) });
      return {
        ok: true,
        chatId: String(data.detectedPersonalChatId),
        message: `Linked your personal Telegram Chat ID (${data.detectedPersonalChatId}).`,
      };
    }

    const privateMsg = Array.isArray(data.updates)
      ? [...data.updates]
          .reverse()
          .find((u: { chatType?: string; chatId?: string }) => u.chatType === 'private' && u.chatId)
      : null;

    if (privateMsg?.chatId) {
      await handleUpdatePolicy({ personalWarningChatId: String(privateMsg.chatId) });
      return {
        ok: true,
        chatId: String(privateMsg.chatId),
        message: `Detected your personal Telegram Chat ID (${privateMsg.chatId} — ${privateMsg.senderName}).`,
      };
    }

    const cachedPrivateEvt = eventsRef.current.find(
      (e) =>
        e.id.startsWith('tg-') &&
        e.chatType === ChatSourceType.Private &&
        /^-?\d+$/.test(e.chatId)
    );
    if (cachedPrivateEvt) {
      await handleUpdatePolicy({ personalWarningChatId: cachedPrivateEvt.chatId });
      return {
        ok: true,
        chatId: cachedPrivateEvt.chatId,
        message: `Linked your personal Telegram Chat ID (${cachedPrivateEvt.chatId}).`,
      };
    }

    return {
      ok: false,
      message: `No direct messages received yet. Open @${botPolicy.botUsername} in Telegram, send /start (or any message), and it will link automatically!`,
    };
  };

  const handleSendTestPersonalWarning = async (targetChatId: string) => {
    const resp = await fetch('/api/telegram/respond', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        botToken: botPolicy.botToken,
        action: 'personal_warning',
        targetChatId,
        text:
          '[SentinelGram Shield Verification]\n' +
          'Your personal Telegram warning channel is active and end-to-end encrypted locally.\n' +
          'Suspicious links, scam lures, and malware attachments will trigger real-time alerts here.',
      }),
    });
    const data = await resp.json();
    if (!data.ok) {
      return { ok: false, message: data.error || 'Failed to send test warning message.' };
    }
    return {
      ok: true,
      message: `Delivered real-time test warning to your Telegram app (Chat ID ${targetChatId}).`,
    };
  };

  const handleRequestBrowserNotifications = async (): Promise<string> => {
    if (!('Notification' in window)) {
      return 'Web Notifications are not supported by this browser viewport; in-app real-time banners remain active.';
    }
    const perm = await Notification.requestPermission();
    if (perm === 'granted') {
      await handleUpdatePolicy({ browserNotificationsEnabled: true });
      return 'Android & Browser real-time push notifications granted and active.';
    }
    return 'Notification permission was declined by browser settings; in-app real-time banners remain active.';
  };

  // Locked E2EE Vault Gate
  if (!booting && vaultSummary.locked) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center p-6">
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setUnlockError(null);
            try {
              const summary = await cryptoVault.unlockWithPassphrase(unlockPassphrase);
              setVaultSummary(summary);
              setUnlockPassphrase('');
              await hydrateUnlockedVaultData();
            } catch (err) {
              setUnlockError(err instanceof Error ? err.message : 'Failed to unlock vault.');
            }
          }}
          className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 space-y-5"
        >
          <div className="w-11 h-11 rounded-2xl bg-sky-50 dark:bg-sky-950/70 text-sky-600 dark:text-sky-400 flex items-center justify-center">
            <Lock className="w-5 h-5" />
          </div>
          <div className="space-y-1.5">
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-50">
              SentinelGram E2EE Vault Locked
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Enter your PBKDF2 passphrase to unwrap AES-256-GCM key{' '}
              <span className="font-mono">{vaultSummary.aesKeyFingerprint.slice(0, 12)}...</span>{' '}
              in local memory.
            </p>
          </div>
          <input
            type="password"
            required
            value={unlockPassphrase}
            onChange={(e) => setUnlockPassphrase(e.target.value)}
            placeholder="Master vault passphrase..."
            className="w-full min-h-[44px] px-3.5 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
          />
          {unlockError && (
            <p className="text-xs text-red-600 dark:text-red-400 font-medium">{unlockError}</p>
          )}
          <button
            type="submit"
            className="w-full min-h-[44px] px-5 py-2.5 rounded-xl text-sm font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors"
          >
            Unlock Encrypted Vault
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 pb-20 md:pb-10">
      {/* Desktop Top Bar — Strict 3-Zone Contract (Brand — 5 Nav Links — 1 Primary Action) */}
      <header className="hidden md:flex items-center justify-between gap-8 px-6 lg:px-10 py-4 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 sticky top-0 z-30">
        <button
          type="button"
          onClick={() => setActiveTab('shield')}
          className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-50 whitespace-nowrap shrink-0 font-display"
        >
          SentinelGram
        </button>

        <nav aria-label="Primary Navigation" className="flex items-center gap-7 text-sm font-medium">
          {(
            [
              { id: 'shield', label: 'Live Shield' },
              { id: 'scanner', label: 'Scanner & ML' },
              { id: 'bot', label: 'Bot & Alerts' },
              { id: 'analytics', label: 'Analytics' },
              { id: 'vault', label: 'E2EE Vault' },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
                activeTab === item.id
                  ? 'border-sky-600 text-slate-900 dark:text-slate-50 font-semibold'
                  : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => setActiveTab('bot')}
            className="min-h-[40px] px-4 py-2 text-xs font-semibold text-white bg-sky-600 rounded-xl hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0"
          >
            {botPolicy.connected ? `@${botPolicy.botUsername}` : 'Connect Bot'}
          </button>
        </div>
      </header>

      {/* Mobile Android-Style Compact Top App Bar (48px height to respect <=15% total sticky cap) */}
      <header className="md:hidden sticky top-0 z-30 h-12 px-3.5 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-base font-bold tracking-tight text-slate-900 dark:text-slate-50 font-display truncate">
            SentinelGram
          </span>
          <button
            type="button"
            onClick={() => {
              void syncCloudServerStatus(true);
              void pollTelegramUpdatesOnce(true);
            }}
            title="Tap to sync live Cloud Server over Wi-Fi / Mobile Data"
            className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-400 shrink-0"
          >
            <RefreshCw className={`w-3 h-3 ${isPollingNow ? 'animate-spin' : ''}`} />
            <span>{isOnline ? network.transportLabel : 'Offline'}</span>
          </button>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <PWAInstallButton pwa={pwa} compactMobile transportLabel={network.transportLabel} />
          <button
            type="button"
            onClick={() => setDarkMode((d) => !d)}
            aria-label="Toggle color theme"
            className="min-h-[44px] min-w-[40px] flex items-center justify-center text-slate-600 dark:text-slate-300"
          >
            {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* Live Cloud Server Update Notification Banner (Instant Update Over Wi-Fi / Mobile Data) */}
      {serverUpdateAvailable && (
        <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-3">
          <div className="bg-sky-600 text-white rounded-xl px-4 py-2.5 flex items-center justify-between gap-3 text-xs font-medium">
            <div className="flex items-center gap-2 min-w-0">
              <Wifi className="w-4 h-4 shrink-0" />
              <span className="truncate">
                New Cloud Server update deployed — reload to apply immediately via{' '}
                {network.transportLabel}.
              </span>
            </div>
            <button
              type="button"
              onClick={() => {
                const url = new URL(window.location.href);
                url.searchParams.set('_live', String(Date.now()));
                window.location.replace(url.toString());
              }}
              className="min-h-[34px] px-3 py-1 rounded-lg bg-white text-sky-700 font-semibold whitespace-nowrap shrink-0 hover:bg-sky-50 transition-colors"
            >
              Update Now
            </button>
          </div>
        </div>
      )}

      {/* Real-Time Suspicious Link / Attachment Alert Toast */}
      {liveAlertEvent && (
        <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-4">
          <div
            role="alert"
            className="bg-red-600 text-white rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm transition-opacity duration-150"
          >
            <div className="flex items-start gap-3 min-w-0">
              <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5" />
              <div className="min-w-0 space-y-0.5">
                <p className="text-sm font-semibold">
                  Real-Time Threat Blocked: {liveAlertEvent.analysis.category.toUpperCase()} (Risk{' '}
                  <span className="font-mono tabular-nums">
                    {liveAlertEvent.analysis.overallRiskScore}/100
                  </span>
                  )
                </p>
                <p className="text-xs text-red-100 truncate">
                  {liveAlertEvent.chatTitle} · {liveAlertEvent.senderName} —{' '}
                  {liveAlertEvent.analysis.fileAnalysis
                    ? `${liveAlertEvent.analysis.fileAnalysis.fileName} (${liveAlertEvent.analysis.fileAnalysis.primaryReason})`
                    : liveAlertEvent.analysis.explanation[0]}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  setActiveTab('shield');
                  setLiveAlertEvent(null);
                }}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-white text-red-700 hover:bg-red-50 transition-colors whitespace-nowrap"
              >
                Inspect Event
              </button>
              <button
                type="button"
                aria-label="Dismiss alert"
                onClick={() => setLiveAlertEvent(null)}
                className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl hover:bg-red-700 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Real-Time Telegram Handshake / Group Join / Clean Scan Feedback Banner */}
      {!liveAlertEvent && liveSyncNotice && (
        <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-4">
          <div
            role="status"
            className={`rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border ${
              liveSyncNotice.tone === 'amber'
                ? 'bg-amber-50 dark:bg-amber-950/60 border-amber-300 dark:border-amber-800 text-amber-950 dark:text-amber-100'
                : 'bg-emerald-50 dark:bg-emerald-950/60 border-emerald-300 dark:border-emerald-800 text-emerald-950 dark:text-emerald-100'
            }`}
          >
            <div className="flex items-start gap-3 min-w-0">
              {liveSyncNotice.tone === 'amber' ? (
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
              ) : (
                <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5 text-emerald-600 dark:text-emerald-400" />
              )}
              <div className="min-w-0 space-y-0.5">
                <p className="text-sm font-semibold">{liveSyncNotice.title}</p>
                <p className="text-xs opacity-90 leading-relaxed">{liveSyncNotice.detail}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  setActiveTab('shield');
                  setLiveSyncNotice(null);
                }}
                className="min-h-[38px] px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 whitespace-nowrap"
              >
                View Live Feed
              </button>
              <button
                type="button"
                aria-label="Dismiss notice"
                onClick={() => setLiveSyncNotice(null)}
                className="min-h-[38px] min-w-[38px] flex items-center justify-center rounded-xl hover:bg-black/5 dark:hover:bg-white/10 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Workspace Utility Strip (Desktop Cloud Sync, Theme & Vault Fingerprint) */}
      <div className="hidden md:block border-b border-slate-200/70 dark:border-slate-800/70 bg-slate-100/60 dark:bg-slate-900/40">
        <div className="max-w-7xl mx-auto px-6 lg:px-8 py-2 flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
          <div className="flex items-center gap-2 font-mono tabular-nums">
            <span className="text-emerald-700 dark:text-emerald-400 font-sans font-semibold">
              Cloud Server Online ({network.transportLabel}
              {serverPingMs !== null ? ` · ${serverPingMs} ms` : ''})
            </span>
            <span aria-hidden="true">·</span>
            <span>Vault AES-256 Key: {vaultSummary.aesKeyFingerprint.slice(0, 16)}</span>
            <span aria-hidden="true">·</span>
            <span>{vaultSummary.encryptedRecordCount} Encrypted Records</span>
          </div>
          <div className="flex items-center gap-4">
            <PWAInstallButton pwa={pwa} transportLabel={network.transportLabel} />
            {vaultSummary.passphraseProtected && (
              <button
                type="button"
                onClick={() => setVaultSummary(cryptoVault.lockVault())}
                className="hover:text-slate-900 dark:hover:text-slate-100 transition-colors font-medium"
              >
                Lock Vault
              </button>
            )}
            <button
              type="button"
              onClick={() => setDarkMode((d) => !d)}
              className="flex items-center gap-1.5 hover:text-slate-900 dark:hover:text-slate-100 transition-colors font-medium"
            >
              {darkMode ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
              <span>{darkMode ? 'Light Theme' : 'Dark Theme'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {!booting && <PWAInstallBanner pwa={pwa} transportLabel={network.transportLabel} />}
        {booting ? (
          <div className="space-y-4">
            <div className="h-24 rounded-2xl bg-slate-200/60 dark:bg-slate-800/50" />
            <div className="h-96 rounded-2xl bg-slate-200/60 dark:bg-slate-800/50" />
          </div>
        ) : activeTab === 'shield' ? (
          <LiveShieldView
            events={events}
            rawEnvelopes={rawEnvelopes}
            botPolicy={botPolicy}
            isPollingNow={isPollingNow}
            lastPolledAt={lastPolledAt}
            transportLabel={network.transportLabel}
            serverPingMs={serverPingMs}
            onSimulateScenario={handleSimulateScenario}
            onPollTelegramNow={async () => {
              await syncCloudServerStatus(true);
              await pollTelegramUpdatesOnce(true);
            }}
            onToggleLivePolling={() =>
              void handleUpdatePolicy({ livePollingEnabled: !botPolicy.livePollingEnabled })
            }
            onDispatchTelegramAction={(evt, act) => dispatchTelegramAction(evt, act)}
            onNavigateTab={setActiveTab}
          />
        ) : activeTab === 'scanner' ? (
          <ScannerMlView
            onRecordScanAsEvent={handleRecordScanAsEvent}
            onAddTrainingSample={handleAddTrainingSample}
            modelVersionTick={modelVersionTick}
            incomingSharedPayload={incomingSharedPayload}
          />
        ) : activeTab === 'bot' ? (
          <BotIntegrationView
            botPolicy={botPolicy}
            hasServerBotToken={hasServerBotToken}
            connectedChats={connectedChats}
            recentInspections={recentInspections}
            liveTelegramEvents={events.filter(
              (e) => e.eventOrigin === 'telegram_live' || e.id.startsWith('tg-')
            )}
            watcherTotalReceived={watcherTotalReceived}
            watcherCleanIgnored={watcherCleanIgnored}
            watcherLastError={watcherLastError}
            lastPolledAt={lastPolledAt}
            cloudHeartbeat={cloudHeartbeat}
            onUpdateHeartbeatConfig={handleUpdateHeartbeatConfig}
            onTriggerHeartbeatPingNow={handleTriggerHeartbeatPingNow}
            onPollNow={() => pollTelegramUpdatesOnce(true)}
            onTriggerEndToEndAlertTest={() => handleSimulateScenario(0)}
            onNavigateShield={() => setActiveTab('shield')}
            onUpdatePolicy={handleUpdatePolicy}
            onVerifyAndConnectBot={handleVerifyAndConnectBot}
            onDisconnectBot={handleDisconnectBot}
            onSendTestPersonalWarning={handleSendTestPersonalWarning}
            onDetectPersonalChatId={handleDetectPersonalChatId}
            onRequestBrowserNotifications={handleRequestBrowserNotifications}
          />
        ) : activeTab === 'analytics' ? (
          <AnalyticsReportView
            events={events}
            onExportEncryptedVault={() => setActiveTab('vault')}
          />
        ) : (
          <VaultPrivacyView
            vaultSummary={vaultSummary}
            rawEnvelopes={rawEnvelopes}
            onSetPassphrase={async (pass) => {
              const s = await cryptoVault.enablePassphraseProtection(pass);
              setVaultSummary(s);
            }}
            onRemovePassphrase={async () => {
              const s = await cryptoVault.removePassphraseProtection();
              setVaultSummary(s);
            }}
            onLockVault={() => setVaultSummary(cryptoVault.lockVault())}
            onRotateKey={async () => {
              const s = await cryptoVault.rotateMasterKey(events, botPolicy, customSamples);
              setRawEnvelopes(cryptoVault.readRawEnvelopes());
              setVaultSummary(s);
            }}
            onExportBundleWithPassphrase={async (pass) => {
              const json = await cryptoVault.exportPortableEncryptedBundle(
                { events, customSamples },
                pass
              );
              const blob = new Blob([json], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `sentinelgram-backup-${Date.now()}.tgs-vault.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
            onImportBundleWithPassphrase={async (jsonText, pass) => {
              const payload = await cryptoVault.importPortableEncryptedBundle<{
                events?: ThreatEvent[];
                customSamples?: TrainingSample[];
              }>(jsonText, pass);
              const importedEvents = Array.isArray(payload.events) ? payload.events : [];
              if (importedEvents.length > 0) {
                const mergedMap = new Map<string, ThreatEvent>();
                for (const item of [...importedEvents, ...events]) {
                  mergedMap.set(item.id, item);
                }
                await persistEvents(Array.from(mergedMap.values()));
              }
              return importedEvents.length;
            }}
            onWipeResetVault={async () => {
              cryptoVault.wipeAllVaultStorage();
              const s = await cryptoVault.initialize();
              setVaultSummary(s);
              setBotPolicy(DEFAULT_BOT_POLICY);
              setCustomSamples([]);
              localMlEngine.resetAndTrainBase([]);
              setModelVersionTick((v) => v + 1);
              const seeds = await generateInitialBaselineEvents();
              await persistEvents(seeds);
            }}
          />
        )}
      </main>

      {/* Quiet Desktop Footer */}
      <footer className="hidden md:block border-t border-slate-200 dark:border-slate-800 py-5 px-8 text-xs text-slate-500 dark:text-slate-400">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <span>SentinelGram Shield — Third-Party Telegram Bot API Security Companion</span>
          <span>End-to-End Encrypted Local Vault (Web Crypto AES-256-GCM)</span>
        </div>
      </footer>

      {/* Mobile Android Ergonomic Fixed Bottom Tab Bar (56px height) */}
      <nav
        aria-label="Mobile Bottom Navigation"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-14 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-t border-slate-200 dark:border-slate-800 grid grid-cols-5 items-center"
      >
        {(
          [
            { id: 'shield', label: 'Shield', Icon: Shield },
            { id: 'scanner', label: 'ML Scan', Icon: Cpu },
            { id: 'bot', label: 'Bot Alert', Icon: Send },
            { id: 'analytics', label: 'Reports', Icon: BarChart3 },
            { id: 'vault', label: 'E2EE', Icon: Lock },
          ] as const
        ).map(({ id, label, Icon }) => {
          const active = activeTab === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => setActiveTab(id)}
              className={`min-h-[44px] flex flex-col items-center justify-center transition-colors ${
                active
                  ? 'text-sky-600 dark:text-sky-400 font-semibold'
                  : 'text-slate-500 dark:text-slate-400'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="text-[10px] tracking-tight mt-0.5 whitespace-nowrap">{label}</span>
            </button>
          );
        })}
      </nav>

      <OfflineIndicator isOnline={isOnline} />
    </div>
  );
}
