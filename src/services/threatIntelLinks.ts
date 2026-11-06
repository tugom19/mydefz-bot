export interface ExternalScannerLink {
  id: string;
  name: string;
  provider: string;
  badge: string;
  url: string;
  description: string;
}

export interface EngineCheckEntry {
  engineId: string;
  engineName: string;
  status: 'malicious' | 'suspicious' | 'clean' | 'known_good' | 'unrated' | 'portal_ready';
  summary: string;
  lookupUrl: string;
  latencyMs?: number;
}

export interface UrlThreatIntelReport {
  ok: boolean;
  targetUrl: string;
  hostname: string;
  registrableDomain: string;
  aggregatedRiskBoost: number;
  domainAgeDays: number | null;
  registeredAt: string | null;
  engines: EngineCheckEntry[];
  checkedAt: number;
}

export interface FileThreatIntelReport {
  ok: boolean;
  sha256: string;
  fileName: string;
  aggregatedRiskBoost: number;
  engines: EngineCheckEntry[];
  checkedAt: number;
}

export function extractCleanHostname(rawUrlOrHost: string): string {
  const trimmed = rawUrlOrHost.trim();
  if (!trimmed) return '';
  try {
    const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    return new URL(withProto).hostname.toLowerCase();
  } catch {
    return trimmed.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  }
}

export function getFileScannerLinks(sha256: string): ExternalScannerLink[] {
  const cleanHash = (sha256 || '').trim().toLowerCase();
  return [
    {
      id: 'metadefender',
      name: 'OPSWAT MetaDefender',
      provider: 'metadefender.opswat.com',
      badge: '30+ AV + CDR',
      url: `https://metadefender.opswat.com/results/file/${cleanHash}`,
      description: 'Multi-engine malware scan & Deep CDR document sanitization lookup',
    },
    {
      id: 'malwarebazaar',
      name: 'abuse.ch MalwareBazaar',
      provider: 'bazaar.abuse.ch (auth.abuse.ch)',
      badge: 'Zero-Cost IOC',
      url: `https://bazaar.abuse.ch/sample/${cleanHash}/`,
      description: 'Community-driven dropper, trojan, stealer & APK sample hash repository',
    },
    {
      id: 'threatfox',
      name: 'abuse.ch ThreatFox',
      provider: 'threatfox.abuse.ch',
      badge: 'C2 & Payload IOC',
      url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${cleanHash}`,
      description: 'Indicators of Compromise (IOC) & botnet payload hash intelligence',
    },
    {
      id: 'virustotal',
      name: 'VirusTotal',
      provider: 'virustotal.com',
      badge: '70+ Engines',
      url: `https://www.virustotal.com/gui/file/${cleanHash}`,
      description: 'Global multi-antivirus signature & behavioral file hash report',
    },
    {
      id: 'hybrid_analysis',
      name: 'Hybrid Analysis',
      provider: 'hybrid-analysis.com',
      badge: 'Falcon Sandbox',
      url: `https://www.hybrid-analysis.com/sample/${cleanHash}`,
      description: 'CrowdStrike Falcon free automated malware detonation sandbox',
    },
    {
      id: 'kaspersky_opentip',
      name: 'Kaspersky OpenTIP',
      provider: 'opentip.kaspersky.com',
      badge: 'Threat Portal',
      url: `https://opentip.kaspersky.com/${cleanHash}/`,
      description: 'Free file hash & heuristic reputation lookup without registration',
    },
    {
      id: 'jotti',
      name: "Jotti's Malware Scan",
      provider: 'virusscan.jotti.org',
      badge: 'Free Multi-AV',
      url: 'https://virusscan.jotti.org/',
      description: 'Independent European free multi-engine file upload scanner',
    },
  ];
}

export function getUrlScannerLinks(rawUrl: string): ExternalScannerLink[] {
  const host = extractCleanHostname(rawUrl);
  const encHost = encodeURIComponent(host);
  return [
    {
      id: 'metadefender_domain',
      name: 'OPSWAT MetaDefender',
      provider: 'metadefender.opswat.com',
      badge: 'Domain & Scam Intel',
      url: `https://metadefender.opswat.com/results/domain/${encHost}`,
      description: 'Checks domain reputation across 30+ commercial anti-phishing & scam feeds',
    },
    {
      id: 'urlhaus',
      name: 'abuse.ch URLhaus',
      provider: 'urlhaus.abuse.ch (auth.abuse.ch)',
      badge: 'Malware URLs',
      url: `https://urlhaus.abuse.ch/browse.php?search=${encHost}`,
      description: 'Tracks live websites distributing exe, apk, bat, and stealer payloads',
    },
    {
      id: 'threatfox_domain',
      name: 'abuse.ch ThreatFox',
      provider: 'threatfox.abuse.ch',
      badge: 'C2 & Scam Hosts',
      url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encHost}`,
      description: 'Hunts phishing infrastructure, wallet drainer hosts, and C2 servers',
    },
    {
      id: 'urlscan',
      name: 'urlscan.io Sandbox',
      provider: 'urlscan.io',
      badge: 'Live DOM & Screenshot',
      url: `https://urlscan.io/search/#domain%3A${encHost}`,
      description: 'Inspects rendered page screenshots, TLS certificates, and brand spoofing',
    },
    {
      id: 'kaspersky_url',
      name: 'Kaspersky OpenTIP',
      provider: 'opentip.kaspersky.com',
      badge: 'Phishing Check',
      url: `https://opentip.kaspersky.com/${encHost}/`,
      description: 'Evaluates phishing, scam, and malicious link reputation',
    },
    {
      id: 'talos',
      name: 'Cisco Talos / PhishTank',
      provider: 'talosintelligence.com',
      badge: 'Web Reputation',
      url: `https://talosintelligence.com/reputation_center/lookup?search=${encHost}`,
      description: 'Enterprise web categorization & PhishTank anti-phishing telemetry',
    },
    {
      id: 'virustotal_domain',
      name: 'VirusTotal Domain',
      provider: 'virustotal.com',
      badge: '90+ Blocklists',
      url: `https://www.virustotal.com/gui/domain/${encHost}`,
      description: 'Aggregates phishing, scam, and malware blocklist detections',
    },
  ];
}

export async function checkUrlMultiEngineIntel(url: string): Promise<UrlThreatIntelReport> {
  const resp = await fetch('/api/threat-intel/check-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  return (await resp.json()) as UrlThreatIntelReport;
}

export async function checkFileMultiEngineIntel(params: {
  sha256: string;
  fileName: string;
}): Promise<FileThreatIntelReport> {
  const resp = await fetch('/api/threat-intel/check-file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return (await resp.json()) as FileThreatIntelReport;
}
