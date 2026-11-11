export enum ThreatCategory {
  Clean = 'clean',
  Phishing = 'phishing',
  Scam = 'scam',
  Malware = 'malware',
  Spam = 'spam',
}

export enum ThreatSeverity {
  Safe = 'safe',
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
}

export enum ChatSourceType {
  Private = 'private',
  Group = 'group',
  Supergroup = 'supergroup',
  Channel = 'channel',
  LocalScan = 'local_scan',
}

export enum EnforcementStatus {
  Allowed = 'allowed',
  PersonalWarned = 'personal_warned',
  ChatWarned = 'chat_warned',
  Quarantined = 'quarantined',
  Flagged = 'flagged',
}

export interface UrlFeatureAnalysis {
  url: string;
  resolvedUrl?: string;
  hostname: string;
  riskScore: number; // 0 to 100
  shannonEntropy: number;
  impersonatedBrand: string | null;
  isPunycodeHomograph: boolean;
  isIpLiteral: boolean;
  hasSuspiciousTld: boolean;
  isShortener: boolean;
  subdomainDepth: number;
  signals: string[];
}

export interface FileFeatureAnalysis {
  fileName: string;
  mimeType: string;
  fileSize: number;
  sha256: string;
  magicHeaderHex: string;
  byteEntropy: number; // 0 to 8.0 bits/byte
  riskScore: number; // 0 to 100
  hasDoubleExtension: boolean;
  hasRtloSpoofing: boolean;
  hasExecutableHeader: boolean;
  mimeMismatch: boolean;
  matchedProtectedExtension: string | null;
  matchedLureKeywords: string[];
  primaryReason: string;
  virusTotalUrl: string;
  signals: string[];
}

export interface MlClassProbabilities {
  clean: number;
  phishing: number;
  scam: number;
  spam: number;
}

export interface MlAnalysisResult {
  category: ThreatCategory;
  severity: ThreatSeverity;
  confidence: number; // 0 to 100
  overallRiskScore: number; // 0 to 100
  inferenceLatencyMs: number;
  classProbabilities: MlClassProbabilities;
  topContributingTokens: Array<{ token: string; weight: number; targetClass: string }>;
  urlAnalyses: UrlFeatureAnalysis[];
  fileAnalysis: FileFeatureAnalysis | null;
  explanation: string[];
}

export interface ConnectedTelegramChat {
  chatId: string;
  title: string;
  chatType: 'private' | 'group' | 'supergroup' | 'channel' | 'business';
  botStatus: 'administrator' | 'member' | 'business_connected' | 'direct_chat' | 'left';
  canReadAllMessages: boolean;
  canDeleteMessages: boolean;
  lastActivityAt: number;
}

export interface BotInspectionDiagnostic {
  timestamp: number;
  chatTitle: string;
  chatType: string;
  itemType: 'file' | 'message';
  label: string;
  mimeType?: string;
  fileSize?: number;
  sha256Prefix?: string;
  headerHex?: string;
  riskScore: number;
  verdict: 'threat_blocked' | 'clean_verified';
  reason: string;
  repliedInTelegram: boolean;
}

export interface ThreatEvent {
  id: string;
  telegramUpdateId?: number;
  telegramMessageId?: number;
  eventOrigin?: 'telegram_live' | 'simulation' | 'local_scan' | 'seed';
  systemNotice?: string;
  timestamp: number;
  chatId: string;
  chatTitle: string;
  chatType: ChatSourceType;
  senderName: string;
  senderUsername: string;
  messagePreview: string;
  analysis: MlAnalysisResult;
  enforcement: EnforcementStatus;
  personalWarningSent: boolean;
  encryptedAtRest: boolean;
}

export interface EncryptedEnvelope {
  version: 1;
  algorithm: 'AES-256-GCM';
  ivBase64: string;
  ciphertextBase64: string;
  keyFingerprint: string;
  encryptedAt: number;
}

export interface BotPolicyConfig {
  botToken: string;
  botUsername: string;
  botFirstName: string;
  botId: number | null;
  canReadAllGroupMessages?: boolean;
  connected: boolean;
  livePollingEnabled: boolean;
  personalWarningChatId: string;
  autoPersonalWarningOnThreat: boolean;
  autoReplyInGroupChats: boolean;
  autoDeleteCriticalInGroups: boolean;
  e2eeRedactPreviewInWarnings: boolean;
  browserNotificationsEnabled: boolean;
  soundAlertEnabled: boolean;
  onlyScamAndVirusFiles?: boolean;
  riskThreshold: number; // 40 to 90
}

export interface TrainingSample {
  id: string;
  text: string;
  label: 'clean' | 'phishing' | 'scam' | 'spam';
  addedByUser: boolean;
  createdAt: number;
}

export interface HeartbeatPingLog {
  timestamp: number;
  targetUrl: string;
  serviceType: 'cronjob_org' | 'uptimerobot' | 'healthchecks_io' | 'webhook_ping' | 'self_ping';
  status: 'ok' | 'failed';
  httpStatus?: number;
  durationMs: number;
  responsePreview?: string;
  error?: string;
}

export interface CloudHeartbeatConfig {
  enabled: boolean;
  intervalMinutes: number; // 2, 3, 5, 10
  serviceType: 'cronjob_org' | 'uptimerobot' | 'healthchecks_io' | 'webhook_ping' | 'self_ping';
  webhookPingUrl: string;
  cronjobExecutionKey?: string;
  selfTargetUrl: string;
  autoKeepaliveSelf: boolean;
  detectedRenderUrl?: string;
  isRenderDetected?: boolean;
  externalRelayActive?: boolean;
  lastRelayAt?: number | null;
  lastPingAt: number | null;
  lastPingStatus: 'ok' | 'failed' | 'idle';
  totalPingsSent: number;
  recentLogs: HeartbeatPingLog[];
}

