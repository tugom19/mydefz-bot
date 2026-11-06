import { useCallback, useEffect, useState } from 'react';

export interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{
    outcome: 'accepted' | 'dismissed';
    platform: string;
  }>;
  prompt(): Promise<void>;
}

interface NavigatorConnection extends EventTarget {
  readonly type?: string;
  readonly effectiveType?: string;
  readonly rtt?: number;
  readonly downlink?: number;
}

declare global {
  interface Window {
    __sentinelDeferredPrompt?: BeforeInstallPromptEvent | null;
  }
  interface Navigator {
    connection?: NavigatorConnection;
    mozConnection?: NavigatorConnection;
    webkitConnection?: NavigatorConnection;
  }
}

export interface PWAInstallState {
  isInstallable: boolean;
  isInstalled: boolean;
  isIOS: boolean;
  isAndroid: boolean;
  isMobileDevice: boolean;
  isAndroidWebView: boolean;
  isInIframe: boolean;
  manifestReady: boolean;
  install: () => Promise<'accepted' | 'dismissed' | 'unavailable'>;
}

export interface LiveNetworkInfo {
  isOnline: boolean;
  transportLabel: string;
  rttMs: number | null;
  networkTick: number;
}

export function buildAndroidChromeIntentUrl(targetHref?: string): string {
  try {
    const raw = targetHref || (typeof window !== 'undefined' ? window.location.href : '');
    const parsed = new URL(raw);
    return `intent://${parsed.host}${parsed.pathname}${parsed.search}#Intent;scheme=${parsed.protocol.replace(
      ':',
      ''
    )};package=com.android.chrome;S.browser_fallback_url=${encodeURIComponent(parsed.href)};end`;
  } catch {
    return targetHref || '/';
  }
}

function readConnectionDetails(): { transportLabel: string; rttMs: number | null } {
  if (typeof navigator === 'undefined') {
    return { transportLabel: 'Wi-Fi / Mobile Data', rttMs: null };
  }
  if (!navigator.onLine) {
    return { transportLabel: 'Disconnected', rttMs: null };
  }
  const conn =
    navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (!conn) {
    return { transportLabel: 'Wi-Fi / Mobile Data', rttMs: null };
  }

  const rawType = (conn.type || '').toLowerCase();
  const eff = (conn.effectiveType || '').toUpperCase();
  const rttMs = typeof conn.rtt === 'number' && conn.rtt > 0 ? conn.rtt : null;

  if (rawType === 'wifi') {
    return { transportLabel: 'Wi-Fi', rttMs };
  }
  if (rawType === 'cellular') {
    return {
      transportLabel: eff ? `Mobile Data (${eff})` : 'Mobile Data',
      rttMs,
    };
  }
  if (rawType === 'ethernet') {
    return { transportLabel: 'LAN / Wi-Fi', rttMs };
  }
  if (eff) {
    return { transportLabel: `Live (${eff})`, rttMs };
  }
  return { transportLabel: 'Wi-Fi / Mobile Data', rttMs };
}

export function usePWAInstall(): PWAInstallState {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(() => {
    if (typeof window !== 'undefined' && window.__sentinelDeferredPrompt) {
      return window.__sentinelDeferredPrompt;
    }
    return null;
  });
  const [isInstalled, setIsInstalled] = useState(false);
  const [isIOS, setIsIOS] = useState(false);
  const [isAndroid, setIsAndroid] = useState(false);
  const [isAndroidWebView, setIsAndroidWebView] = useState(false);
  const [isInIframe, setIsInIframe] = useState(false);
  const [manifestReady, setManifestReady] = useState(false);

  const checkManifestReadiness = useCallback(async () => {
    if (typeof window === 'undefined') return;
    try {
      const resp = await fetch('/manifest.webmanifest', {
        credentials: 'include',
        cache: 'no-store',
      });
      if (resp.ok) {
        const contentType = resp.headers.get('content-type') || '';
        if (contentType.includes('json') || contentType.includes('manifest')) {
          setManifestReady(true);
        }
      }
    } catch {
      // Ignore transient network errors
    }
  }, []);

  useEffect(() => {
    const standalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as Navigator & { standalone?: boolean }).standalone === true;

    if (standalone) {
      setIsInstalled(true);
    }

    const ua = window.navigator.userAgent || '';
    const uaLower = ua.toLowerCase();

    const iosDetected =
      /iphone|ipad|ipod/.test(uaLower) ||
      (window.navigator.platform === 'MacIntel' && window.navigator.maxTouchPoints > 1);
    const cleanIOS = iosDetected && !('MSStream' in window);
    const androidDetected = /android/.test(uaLower);

    // Detect in-app webviews on Android (Telegram, WhatsApp, Instagram, Facebook, System WebView)
    const webViewDetected =
      androidDetected &&
      (/; wv\)|\bwv\b|telegram|fban|fbav|instagram|line\/|micromessenger|snapchat/i.test(ua) ||
        (!/chrome\/\d+/i.test(ua) && !/firefox\/\d+/i.test(ua)));

    setIsIOS(cleanIOS);
    setIsAndroid(androidDetected);
    setIsAndroidWebView(webViewDetected);

    try {
      setIsInIframe(window.self !== window.top);
    } catch {
      setIsInIframe(true);
    }

    if (window.__sentinelDeferredPrompt) {
      setDeferredPrompt(window.__sentinelDeferredPrompt);
    }

    void checkManifestReadiness();

    const mediaQuery = window.matchMedia('(display-mode: standalone)');
    const handleDisplayChange = (evt: MediaQueryListEvent) => {
      if (evt.matches) {
        setIsInstalled(true);
        window.__sentinelDeferredPrompt = null;
        setDeferredPrompt(null);
      }
    };
    mediaQuery.addEventListener('change', handleDisplayChange);

    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      const promptEvt = e as BeforeInstallPromptEvent;
      window.__sentinelDeferredPrompt = promptEvt;
      setDeferredPrompt(promptEvt);
    };

    const handleEarlyPromptReady = () => {
      if (window.__sentinelDeferredPrompt) {
        setDeferredPrompt(window.__sentinelDeferredPrompt);
      }
    };

    const handleAppInstalled = () => {
      setIsInstalled(true);
      window.__sentinelDeferredPrompt = null;
      setDeferredPrompt(null);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('sentinel-pwa-prompt-ready', handleEarlyPromptReady);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      mediaQuery.removeEventListener('change', handleDisplayChange);
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      window.removeEventListener('sentinel-pwa-prompt-ready', handleEarlyPromptReady);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, [checkManifestReadiness]);

  const install = async (): Promise<'accepted' | 'dismissed' | 'unavailable'> => {
    const activePrompt = deferredPrompt || window.__sentinelDeferredPrompt || null;
    if (!activePrompt) return 'unavailable';
    await activePrompt.prompt();
    const { outcome } = await activePrompt.userChoice;
    if (outcome === 'accepted') {
      window.__sentinelDeferredPrompt = null;
      setDeferredPrompt(null);
      setIsInstalled(true);
    }
    return outcome;
  };

  return {
    isInstallable: Boolean(deferredPrompt) && !isInstalled,
    isInstalled,
    isIOS,
    isAndroid,
    isMobileDevice: isAndroid || isIOS,
    isAndroidWebView,
    isInIframe,
    manifestReady,
    install,
  };
}

export function useLiveNetworkStatus(): LiveNetworkInfo {
  const [isOnline, setIsOnline] = useState<boolean>(() =>
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );
  const [details, setDetails] = useState<{ transportLabel: string; rttMs: number | null }>(() =>
    readConnectionDetails()
  );
  const [networkTick, setNetworkTick] = useState(0);

  useEffect(() => {
    const syncNetworkState = () => {
      const nowOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;
      setIsOnline(nowOnline);
      setDetails(readConnectionDetails());
      if (nowOnline) {
        setNetworkTick((t) => t + 1);
      }
    };

    window.addEventListener('online', syncNetworkState);
    window.addEventListener('offline', syncNetworkState);

    const conn =
      typeof navigator !== 'undefined'
        ? navigator.connection || navigator.mozConnection || navigator.webkitConnection
        : undefined;
    conn?.addEventListener?.('change', syncNetworkState);

    return () => {
      window.removeEventListener('online', syncNetworkState);
      window.removeEventListener('offline', syncNetworkState);
      conn?.removeEventListener?.('change', syncNetworkState);
    };
  }, []);

  return {
    isOnline,
    transportLabel: details.transportLabel,
    rttMs: details.rttMs,
    networkTick,
  };
}

export function useOnlineStatus(): boolean {
  const { isOnline } = useLiveNetworkStatus();
  return isOnline;
}
