import React, { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import {
  Check,
  Copy,
  ExternalLink,
  Globe,
  RefreshCw,
  Smartphone,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import {
  buildAndroidChromeIntentUrl,
  type PWAInstallState,
} from '../hooks/usePWAInstall';

const DEFAULT_SHARED_URL =
  'https://ais-pre-m5cakb5ccpzubvsfq7x4oy-275514818767.asia-southeast1.run.app';
const DEFAULT_DEV_URL =
  'https://ais-dev-m5cakb5ccpzubvsfq7x4oy-275514818767.asia-southeast1.run.app';

function resolveLiveWebUrls(): { sharedUrl: string; ownerUrl: string } {
  if (typeof window === 'undefined') {
    return { sharedUrl: DEFAULT_SHARED_URL, ownerUrl: DEFAULT_DEV_URL };
  }
  const origin = window.location.origin;
  if (origin.includes('ais-dev-')) {
    return {
      sharedUrl: origin.replace('ais-dev-', 'ais-pre-'),
      ownerUrl: origin,
    };
  }
  if (origin.includes('ais-pre-')) {
    return {
      sharedUrl: origin,
      ownerUrl: origin.replace('ais-pre-', 'ais-dev-'),
    };
  }
  return { sharedUrl: origin, ownerUrl: origin };
}

interface AndroidChromeModalProps {
  open: boolean;
  onClose: () => void;
  pwa: PWAInstallState;
  transportLabel?: string;
}

const AndroidChromeLiveModal: React.FC<AndroidChromeModalProps> = ({
  open,
  onClose,
  pwa,
  transportLabel = 'Wi-Fi / Mobile Data',
}) => {
  const [copied, setCopied] = useState(false);
  const { sharedUrl, ownerUrl } = resolveLiveWebUrls();
  const hasSeparateUrls = sharedUrl !== ownerUrl;
  const [linkMode, setLinkMode] = useState<'owner' | 'shared'>('owner');

  if (!open) return null;

  const targetWebUrl = linkMode === 'owner' ? ownerUrl : sharedUrl;
  const chromeIntentHref = buildAndroidChromeIntentUrl(targetWebUrl);

  const handleCopyUrl = async () => {
    try {
      await navigator.clipboard.writeText(targetWebUrl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch {
      // Ignore clipboard permission restrictions gracefully
    }
  };

  const handleHardRefreshFromServer = () => {
    const url = new URL(window.location.href);
    url.searchParams.set('_live', String(Date.now()));
    window.location.replace(url.toString());
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="chrome-live-modal-title"
      className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto"
    >
      <div className="w-full max-w-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 space-y-5 shadow-xl my-auto">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <img
              src="/pwa-192x192.png"
              alt="SentinelGram Shield"
              className="w-11 h-11 rounded-xl shrink-0"
            />
            <div>
              <h2
                id="chrome-live-modal-title"
                className="text-base font-bold text-slate-900 dark:text-slate-50"
              >
                Chrome Web Android · Live Cloud Server
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Always online · Real-time tracking &amp; instant updates via Wi-Fi or Mobile Data
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close live Android Chrome connection dialog"
            className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* If opened inside Telegram's internal browser on Android -> 1-tap open in real Chrome Web */}
        {pwa.isAndroid && pwa.isAndroidWebView && (
          <div className="bg-amber-50 dark:bg-amber-950/50 border border-amber-300 dark:border-amber-800 rounded-xl p-4 space-y-3">
            <p className="text-xs font-bold text-amber-950 dark:text-amber-100">
              Telegram In-App Preview Detected — Switch to Chrome Web on Android
            </p>
            <p className="text-xs text-amber-900 dark:text-amber-200 leading-relaxed">
              Launch directly in <strong>Google Chrome on Android</strong> so live server tracking
              and instant updates stay active over Wi-Fi and Mobile Data.
            </p>
            <a
              href={chromeIntentHref}
              className="w-full min-h-[44px] px-4 py-2.5 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors inline-flex items-center justify-center gap-2"
            >
              <ExternalLink className="w-4 h-4" />
              <span>Open Live in Google Chrome (Android)</span>
            </a>
          </div>
        )}

        {/* Live Cloud Connection Status & Instant Update via Wi-Fi / Mobile Data */}
        <div className="bg-emerald-50/70 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-0.5 text-xs">
            <p className="font-semibold text-emerald-950 dark:text-emerald-100 flex items-center gap-1.5">
              <Wifi className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span>Connected via {transportLabel} (Zero Offline Cache)</span>
            </p>
            <p className="text-emerald-800 dark:text-emerald-300/90 text-[11px] leading-relaxed">
              Every open or refresh pulls the latest live build &amp; Telegram bot telemetry straight
              from your cloud server.
            </p>
          </div>
          <button
            type="button"
            onClick={handleHardRefreshFromServer}
            className="min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-700 text-white hover:bg-emerald-800 transition-colors inline-flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Pull Latest Update</span>
          </button>
        </div>

        {/* QR Code & Direct Chrome Web Android Link */}
        <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex flex-col sm:flex-row items-center gap-4">
            <div className="bg-white p-2.5 rounded-xl border border-slate-200 shrink-0">
              <QRCodeSVG value={targetWebUrl} size={116} level="M" />
            </div>
            <div className="space-y-2 min-w-0 w-full">
              <p className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Open Live in Chrome Web on Your Android Phone
              </p>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                Scan with your Android camera or open this URL in <strong>Chrome on Android</strong>{' '}
                over Wi-Fi or 4G/5G mobile data. Your cloud server runs 24/7 watching Telegram and
                streams live detections immediately to Chrome.
              </p>

              {hasSeparateUrls && (
                <div className="flex items-center gap-1.5 pt-0.5">
                  <button
                    type="button"
                    onClick={() => setLinkMode('owner')}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                      linkMode === 'owner'
                        ? 'bg-sky-600 text-white'
                        : 'bg-slate-200/70 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    My Google Account Link
                  </button>
                  <button
                    type="button"
                    onClick={() => setLinkMode('shared')}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                      linkMode === 'shared'
                        ? 'bg-sky-600 text-white'
                        : 'bg-slate-200/70 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    Shared Public Link
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 pt-1">
            <code className="flex-1 text-[11px] font-mono text-slate-700 dark:text-slate-300 truncate bg-white dark:bg-slate-900 px-2.5 py-2 rounded-lg border border-slate-200 dark:border-slate-800">
              {targetWebUrl}
            </code>
            <button
              type="button"
              onClick={() => void handleCopyUrl()}
              className="min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors inline-flex items-center gap-1.5 shrink-0"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy URL'}</span>
            </button>
          </div>

          {hasSeparateUrls && (
            <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
              {linkMode === 'owner'
                ? 'Opens straight in Android Chrome when signed into the same Google account.'
                : 'Works on any phone without Google login once Share (Public) is enabled.'}
            </p>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 space-y-1.5">
            <p className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
              <span>24/7 Cloud Server Tracking</span>
            </p>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              Your Telegram bot watcher and multi-engine threat lookups run continuously on the
              server and sync live to Android Chrome every 2.5s.
            </p>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 space-y-1.5">
            <p className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
              <Smartphone className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
              <span>Optional Chrome Shortcut</span>
            </p>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              Bookmark in Android Chrome or tap <strong>⋮ → Add to Home screen</strong> for 1-tap
              launch — always loads live over Wi-Fi or Mobile Data.
            </p>
          </div>
        </div>

        <div className="flex items-center justify-between gap-2 pt-1">
          {pwa.isInstallable ? (
            <button
              type="button"
              onClick={() => void pwa.install()}
              className="min-h-[42px] px-4 py-2 rounded-xl text-xs font-semibold border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              Pin Chrome Home Shortcut
            </button>
          ) : (
            <span />
          )}
          <button
            type="button"
            onClick={onClose}
            className="min-h-[42px] px-5 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:opacity-90 transition-opacity"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

interface PWAInstallButtonProps {
  pwa: PWAInstallState;
  compactMobile?: boolean;
  transportLabel?: string;
}

export const PWAInstallButton: React.FC<PWAInstallButtonProps> = ({
  pwa,
  compactMobile = false,
  transportLabel,
}) => {
  const [modalOpen, setModalOpen] = useState(false);

  if (pwa.isAndroid && pwa.isAndroidWebView) {
    const chromeHref = buildAndroidChromeIntentUrl();
    return (
      <a
        href={chromeHref}
        className="min-h-[36px] px-2.5 py-1 rounded-lg text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
      >
        <ExternalLink className="w-3.5 h-3.5 shrink-0" />
        <span>Open in Chrome</span>
      </a>
    );
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setModalOpen(true)}
        className={
          compactMobile
            ? 'min-h-[36px] px-2.5 py-1 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0'
            : 'inline-flex items-center gap-1.5 text-sky-600 dark:text-sky-400 hover:text-sky-700 dark:hover:text-sky-300 font-semibold transition-colors whitespace-nowrap'
        }
      >
        <Smartphone className="w-3.5 h-3.5 shrink-0" />
        <span>{compactMobile ? 'Android Link' : 'Open on Android Chrome'}</span>
      </button>

      <AndroidChromeLiveModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        pwa={pwa}
        transportLabel={transportLabel}
      />
    </>
  );
};

interface PWAInstallBannerProps {
  pwa: PWAInstallState;
  transportLabel?: string;
}

export const PWAInstallBanner: React.FC<PWAInstallBannerProps> = ({ pwa, transportLabel }) => {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem('sentinelgram_live_web_banner_dismissed') === '1';
    } catch {
      return false;
    }
  });
  const [modalOpen, setModalOpen] = useState(false);

  // If the user is ALREADY running in Chrome Web on Android (top-level), don't show a setup banner
  const alreadyOnAndroidChromeWeb = pwa.isAndroid && !pwa.isAndroidWebView && !pwa.isInIframe;
  if (dismissed || alreadyOnAndroidChromeWeb) return null;

  const chromeIntentHref = buildAndroidChromeIntentUrl();

  const handleDismiss = () => {
    setDismissed(true);
    try {
      sessionStorage.setItem('sentinelgram_live_web_banner_dismissed', '1');
    } catch {
      // Ignore storage restrictions
    }
  };

  return (
    <>
      <section
        aria-label="Run Live on Android Chrome Web"
        className="mb-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div className="flex items-start gap-3.5 min-w-0">
          <img
            src="/pwa-192x192.png"
            alt="SentinelGram Shield"
            className="w-11 h-11 rounded-xl shrink-0"
          />
          <div className="min-w-0 space-y-0.5">
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-50">
              {pwa.isAndroid && pwa.isAndroidWebView
                ? 'Switch from Telegram Preview to Google Chrome on Android'
                : 'Run & Track Live on Chrome Web Android (Wi-Fi / Mobile Data)'}
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              {pwa.isAndroid && pwa.isAndroidWebView
                ? 'Open directly in Google Chrome on Android to track live Cloud Server Telegram detections and receive instant updates over Wi-Fi or 4G/5G.'
                : 'Cloud-connected web companion — open in Chrome on Android over Wi-Fi or Mobile Data to track 24/7 server detections and get instant updates with zero offline cache.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {pwa.isAndroid && pwa.isAndroidWebView ? (
            <a
              href={chromeIntentHref}
              className="min-h-[42px] px-4 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open in Chrome</span>
            </a>
          ) : (
            <button
              type="button"
              onClick={() => setModalOpen(true)}
              className="min-h-[42px] px-4 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
            >
              <Smartphone className="w-3.5 h-3.5" />
              <span>Android Chrome QR &amp; Link</span>
            </button>
          )}
          <button
            type="button"
            onClick={handleDismiss}
            aria-label="Dismiss Android Chrome banner"
            className="min-h-[42px] min-w-[42px] flex items-center justify-center rounded-xl text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </section>

      <AndroidChromeLiveModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        pwa={pwa}
        transportLabel={transportLabel}
      />
    </>
  );
};

interface OfflineIndicatorProps {
  isOnline: boolean;
}

export const OfflineIndicator: React.FC<OfflineIndicatorProps> = ({ isOnline }) => {
  if (isOnline) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-16 md:bottom-4 left-4 right-4 sm:right-auto z-50 bg-amber-950 text-amber-100 border border-amber-700 px-3.5 py-2.5 rounded-xl shadow-lg flex items-center gap-2.5 text-xs font-medium max-w-md"
    >
      <WifiOff className="w-4 h-4 text-amber-400 shrink-0" />
      <span>
        Wi-Fi / Mobile Data Disconnected — Reconnect to resume live Cloud Server Telegram tracking
        &amp; updates
      </span>
    </div>
  );
};
