import {
  ThreatCategory,
  ThreatSeverity,
  type FileFeatureAnalysis,
  type MlAnalysisResult,
  type MlClassProbabilities,
  type TrainingSample,
  type UrlFeatureAnalysis,
} from '../types/security';
import { sha256HexFromBuffer, sha256HexFromString } from './cryptoVault';

type nbLabel = 'clean' | 'phishing' | 'scam' | 'spam';

const INITIAL_TRAINING_CORPUS: Array<{ label: nbLabel; text: string }> = [
  // Clean daily Telegram messages
  { label: 'clean', text: 'Hey team, are we still meeting at 3pm to review the Android release notes?' },
  { label: 'clean', text: 'I uploaded the Q3 architecture slides to the shared folder, let me know your thoughts.' },
  { label: 'clean', text: 'Thanks for sending over the restaurant address! See everyone tonight at 7.' },
  { label: 'clean', text: 'Can someone check the build pipeline? Unit tests passed on main branch.' },
  { label: 'clean', text: 'Happy birthday! Hope you have a relaxing weekend with family.' },
  { label: 'clean', text: 'Here is the official documentation link https://core.telegram.org/bots/api for webhook setup.' },
  { label: 'clean', text: 'Just landed at the airport, heading to the hotel in 20 minutes.' },
  { label: 'clean', text: 'Did you finish reading the quarterly financial summary PDF from accounting?' },
  { label: 'clean', text: 'Let us keep the group chat focused on engineering updates and bug reports.' },
  { label: 'clean', text: 'Morning! Coffee machine on the 4th floor is working again.' },
  { label: 'clean', text: 'Please review pull request 142 when you have a moment today.' },
  { label: 'clean', text: 'Dinner was great, let us split the bill tomorrow.' },

  // Phishing & credential / wallet harvesting patterns
  { label: 'phishing', text: 'URGENT: Your Telegram account will be terminated in 24 hours due to suspicious login. Verify session immediately at https://telegram-security-verify.xyz/auth' },
  { label: 'phishing', text: 'Telegram Support Alert: Unusual login attempt detected. Enter your 5-digit SMS login code and 2FA password to keep your account active.' },
  { label: 'phishing', text: 'Claim your official TON Keeper 500 TON reward allocation! Connect wallet seed phrase now: https://tonkeeper-airdrop-claim.top/connect' },
  { label: 'phishing', text: 'MetaMask Security Notice: Smart contract approval required to prevent wallet freeze. Validate recovery phrase at http://metamask-restore-node.cfd/sync' },
  { label: 'phishing', text: 'Someone gifted you 12 months of Telegram Premium! Sign in with your phone number and login OTP code at https://t-me-premium-gift.sbs/redeem' },
  { label: 'phishing', text: 'Binance Compliance: Your withdrawal access is suspended. Complete KYC wallet signature verification at https://binance-aml-portal.click/login' },
  { label: 'phishing', text: 'Steam Community Trade Offer: Confirm your inventory item transfer before link expires http://steamcommunlty-trade.xyz/offer' },
  { label: 'phishing', text: 'PayPal Billing Department: Unauthorized transaction of $489.99 pending. Cancel now by logging in at https://paypa1-dispute-center.top/signin' },
  { label: 'phishing', text: 'Vote for my niece in the photography contest! Log in with your Telegram code on this portal: https://contest-vote-tg.xyz/auth' },
  { label: 'phishing', text: 'Session expired: re-authenticate your cloud password and verification code immediately to avoid permanent account deletion.' },

  // Scam, Pig-butchering, Fake Investment, Impersonation
  { label: 'scam', text: 'Guaranteed 18% daily profit with our automated crypto arbitrage VIP signal group! Send 200 USDT to double your balance in 4 hours.' },
  { label: 'scam', text: 'Hello dear, sorry I messaged the wrong number on Telegram, my assistant gave me this contact. By the way I trade gold futures in Singapore.' },
  { label: 'scam', text: 'Part-time remote job! Earn $350 to $800 daily just liking YouTube videos and completing simple merchant tasks on Telegram. Message HR manager now!' },
  { label: 'scam', text: 'Admin impersonation: Send 0.5 ETH to the liquidity validation address and receive 2.0 ETH instant giveaway return from the foundation.' },
  { label: 'scam', text: 'Congratulations! Your Telegram username won 2,500 USDT in the mystery box raffle. Pay a small $35 gas activation fee to withdraw funds.' },
  { label: 'scam', text: 'Insider pump signal starting in 15 minutes! Guaranteed 10x token launch, zero risk, DM me for private presale wallet address.' },
  { label: 'scam', text: 'Recovery specialist: Lost crypto to scammers? Our cyber team can recover 100% of stolen Bitcoin for an upfront $150 retainer fee.' },
  { label: 'scam', text: 'Urgent help needed, I am stuck abroad and lost my bank card, please wire $400 via gift cards or USDT right away, do not call.' },
  { label: 'scam', text: 'VIP forex mentorship: Turn $100 into $5,000 in 48 hours! Account management with 99.8% win rate guaranteed payout.' },

  // Bulk Spam & Unsolicited Promotion
  { label: 'spam', text: 'JOIN FAST!! Best adult channels & leaked VIP rooms free access limited slots click invite link now!!' },
  { label: 'spam', text: 'Buy 50,000 cheap Telegram channel subscribers, views, and auto-reactions instant delivery lowest SMM panel prices!' },
  { label: 'spam', text: ' CASINO BONUS 500% FREE SPINS NO DEPOSIT REQUIRED! Play slots and crash games instant crypto cashout!' },
  { label: 'spam', text: ' forwarding to 20 groups: Mass DM blast software & scraper bot available for sale, message @bulk_sender_promo' },
  { label: 'spam', text: 'FREE NITRO & PREMIUM ACCOUNTS GENERATOR 2026 WORKING 100% JOIN OUR CHANNEL BEFORE DELETED!' },
  { label: 'spam', text: 'Click my referral link to get free tap-to-earn coins! Spamming invite code to everyone in group!' },
];

const PROTECTED_BRANDS = [
  'telegram',
  'tonkeeper',
  'binance',
  'metamask',
  'coinbase',
  'paypal',
  'google',
  'apple',
  'microsoft',
  'steam',
  'steamcommunity',
  'whatsapp',
  'trustwallet',
  'bybit',
];

const OFFICIAL_SAFE_DOMAINS = new Set([
  'telegram.org',
  'core.telegram.org',
  't.me',
  'tonkeeper.com',
  'binance.com',
  'metamask.io',
  'coinbase.com',
  'paypal.com',
  'google.com',
  'apple.com',
  'microsoft.com',
  'steampowered.com',
  'steamcommunity.com',
  'github.com',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'cfd', 'sbs', 'click', 'tk', 'ml', 'ga', 'cf', 'gq',
  'zip', 'mov', 'icu', 'buzz', 'rest', 'cam', 'monster', 'cyou', 'shop', 'live',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'is.gd', 'rebrand.ly', 'shorturl.at', 'ow.ly',
]);

export const PROTECTED_FILE_EXTENSIONS = [
  '.exe',
  '.scr',
  '.bat',
  '.cmd',
  '.com',
  '.msi',
  '.ps1',
  '.vbs',
  '.js',
  '.jar',
  '.apk',
  '.iso',
] as const;

export const SUSPICIOUS_LURE_KEYWORDS = [
  'invoice',
  'payment',
  'crypto',
  'wallet',
  'premium',
  'free',
  'crack',
  'hack',
  'generator',
  'activator',
  'keygen',
  'seed',
  'bonus',
  'airdrop',
  'stealer',
  'spoofer',
  'cheat',
  'loader',
  'bypass',
  'mnemonic',
  'private_key',
  'telegram',
  'update',
  'verify',
  'kyc',
  'customs',
  'dhl',
  'usdt',
  'binance',
  'metamask',
  'tonkeeper',
  'bybit',
  'okx',
  'giveaway',
  'voucher',
] as const;

const HIGH_CERTAINTY_WAREZ_SCAM_KEYWORDS = new Set([
  'crack', 'hack', 'generator', 'activator', 'keygen', 'seed', 'airdrop',
  'stealer', 'spoofer', 'cheat', 'loader', 'bypass', 'mnemonic', 'private_key',
]);

const PROTECTED_EXT_NO_DOT = new Set(
  PROTECTED_FILE_EXTENSIONS.map((e) => e.slice(1).toLowerCase())
);

const DANGEROUS_EXTENSIONS = new Set([
  ...PROTECTED_EXT_NO_DOT,
  'pif', 'msp', 'mst', 'dll', 'sys', 'drv', 'ocx', 'cpl',
  'xapk', 'apks', 'apkm', 'aab', 'dex', 'ipa', 'mobileconfig',
  'dmg', 'pkg', 'app', 'command', 'deb', 'rpm', 'elf', 'bin', 'run', 'appimage',
  'gadget', 'application', 'appref-ms', 'xbap',
  'psm1', 'psd1', 'vbe', 'jse', 'mjs', 'cjs', 'wsf', 'wsh', 'hta', 'lnk', 'scf',
  'library-ms', 'searchconnector-ms', 'settingcontent-ms',
  'inf', 'reg', 'msc', 'chm', 'hlp', 'jnlp', 'py', 'pyw', 'sh', 'bash', 'zsh', 'pl', 'rb', 'php', 'swf',
  'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'xlsb', 'pptm', 'potm', 'ppam', 'ppsm',
  'accde', 'accdr', 'iqy', 'slk', 'one', 'onetoc2',
  'img', 'vhd', 'vhdx', 'udf', 'nrg', 'url', 'website',
]);

const HTML_PHISH_EXTENSIONS = new Set([
  'html', 'htm', 'shtml', 'xhtml', 'mhtml', 'mht', 'svg', 'xsl', 'xslt',
]);

const ARCHIVE_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'zst', 'cab', 'ace', 'arj', 'lzh',
]);

function parseBrowserZipEntries(bytes: Uint8Array): { entryNames: string[]; isEncrypted: boolean } {
  const names = new Set<string>();
  let isEncrypted = false;
  const decoder = new TextDecoder('utf-8');

  for (let i = 0; i + 30 <= bytes.length; i++) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x03 && bytes[i + 3] === 0x04) {
      const flags = bytes[i + 6] | (bytes[i + 7] << 8);
      if ((flags & 0x01) !== 0) isEncrypted = true;
      const nameLen = bytes[i + 26] | (bytes[i + 27] << 8);
      if (nameLen > 0 && nameLen <= 512 && i + 30 + nameLen <= bytes.length) {
        names.add(decoder.decode(bytes.subarray(i + 30, i + 30 + nameLen)));
      }
    } else if (
      i + 46 <= bytes.length &&
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x01 &&
      bytes[i + 3] === 0x02
    ) {
      const flags = bytes[i + 8] | (bytes[i + 9] << 8);
      if ((flags & 0x01) !== 0) isEncrypted = true;
      const nameLen = bytes[i + 28] | (bytes[i + 29] << 8);
      if (nameLen > 0 && nameLen <= 512 && i + 46 + nameLen <= bytes.length) {
        names.add(decoder.decode(bytes.subarray(i + 46, i + 46 + nameLen)));
      }
    }
  }

  return { entryNames: Array.from(names), isEncrypted };
}

export function formatSuspiciousFileAlert(params: {
  senderUsername?: string;
  senderName?: string;
  fileName: string;
  reason: string;
  sourceChatLabel?: string;
}): string {
  const rawUser = params.senderUsername?.trim();
  const userHandle = rawUser
    ? rawUser.startsWith('@')
      ? rawUser
      : `@${rawUser}`
    : params.senderName?.trim()
    ? `@${params.senderName.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_')}`
    : '@username';

  const chatLine = params.sourceChatLabel ? `Chat: ${params.sourceChatLabel}\n` : '';

  return (
    `⚠️ Suspicious File Detected\n\n` +
    chatLine +
    `User: ${userHandle}\n` +
    `File: ${params.fileName}\n` +
    `Reason: ${params.reason}\n\n` +
    `Recommendation:\n` +
    `Do NOT open this file.\n` +
    `Scan with VirusTotal, MetaDefender, or abuse.ch MalwareBazaar.`
  );
}

function tokenize(text: string): string[] {
  const normalized = text
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, ' __url_token__ ')
    .replace(/\$?\d+(?:[.,]\d+)?%?/g, (m) => (m.includes('%') ? ' __percent_num__ ' : ' __num__ '))
    .replace(/[^a-z0-9_@\s]/g, ' ');
  const rawTokens = normalized.split(/\s+/).filter((t) => t.length >= 2);
  const bigrams: string[] = [];
  for (let i = 0; i < rawTokens.length - 1; i++) {
    bigrams.push(`${rawTokens[i]}_${rawTokens[i + 1]}`);
  }
  return [...rawTokens, ...bigrams];
}

function computeShannonEntropy(str: string): number {
  if (!str.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

export function computeByteEntropy(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    counts[bytes[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / bytes.length;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function normalizeLeetHomoglyphs(input: string): string {
  return input
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/rn/g, 'm');
}

export function extractUrlsFromText(text: string, explicitUrls: string[] = []): string[] {
  const deobfuscated = text.replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().replace('hxxp', 'http'));
  const regex = /\b(?:https?:\/\/|www\.)[^\s<>()"']+|\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:\/[^\s<>()"']*)?/gi;
  const matches = deobfuscated.match(regex) || [];
  const combined = new Set<string>();
  for (const candidate of [...explicitUrls, ...matches]) {
    const cleaned = candidate.replace(/[.,;!?)]+$/, '');
    if ((cleaned.includes('.') && !cleaned.includes('@')) || cleaned.startsWith('http')) {
      combined.add(cleaned);
    }
  }
  return Array.from(combined);
}

export function analyzeUrlLexicalFeatures(rawUrl: string, resolvedUrl?: string): UrlFeatureAnalysis {
  const effectiveTarget = resolvedUrl || rawUrl;
  const withProto = /^https?:\/\//i.test(effectiveTarget) ? effectiveTarget : `https://${effectiveTarget}`;

  let hostname = effectiveTarget.toLowerCase();
  let pathname = '/';
  let hasAtSymbol = rawUrl.includes('@');
  try {
    const parsed = new URL(withProto);
    hostname = parsed.hostname.toLowerCase();
    pathname = parsed.pathname + parsed.search;
    if (parsed.username || parsed.password) hasAtSymbol = true;
  } catch {
    hostname = effectiveTarget.split('/')[0].toLowerCase();
  }

  const rootParts = hostname.split('.').filter(Boolean);
  const tld = rootParts[rootParts.length - 1] || '';
  const registrableDomain = rootParts.slice(-2).join('.');
  const subdomainDepth = Math.max(0, rootParts.length - 2);
  const isOfficial = OFFICIAL_SAFE_DOMAINS.has(registrableDomain) || OFFICIAL_SAFE_DOMAINS.has(hostname);

  const shannonEntropy = computeShannonEntropy(hostname + pathname);
  const isPunycodeHomograph = hostname.includes('xn--') || /[^\x00-\x7F]/.test(rawUrl);
  const isIpLiteral = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const isShortener = URL_SHORTENERS.has(registrableDomain) || URL_SHORTENERS.has(hostname);

  let impersonatedBrand: string | null = null;
  if (!isOfficial) {
    const domainTokens = hostname.replace(/\.[a-z]+$/, '').split(/[.-]/);
    const fullCollapsed = normalizeLeetHomoglyphs(domainTokens.join(''));
    for (const brand of PROTECTED_BRANDS) {
      if (fullCollapsed.includes(brand)) {
        impersonatedBrand = brand;
        break;
      }
      for (const tok of domainTokens) {
        const deLeet = normalizeLeetHomoglyphs(tok);
        if (tok.length >= 5 && levenshteinDistance(deLeet, brand) === 1) {
          impersonatedBrand = brand;
          break;
        }
      }
      if (impersonatedBrand) break;
    }
  }

  let riskScore = 6;
  const signals: string[] = [];

  if (isOfficial && !hasAtSymbol) {
    return {
      url: rawUrl,
      resolvedUrl,
      hostname,
      riskScore: 4,
      shannonEntropy,
      impersonatedBrand: null,
      isPunycodeHomograph: false,
      isIpLiteral: false,
      hasSuspiciousTld: false,
      isShortener: false,
      subdomainDepth,
      signals: ['Verified official domain'],
    };
  }

  if (impersonatedBrand) {
    riskScore += 46;
    signals.push(`Brand lookalike / typosquatting targeting "${impersonatedBrand}"`);
  }
  if (isPunycodeHomograph) {
    riskScore += 42;
    signals.push('IDN Punycode / Unicode homograph script detected');
  }
  if (isIpLiteral) {
    riskScore += 38;
    signals.push('Raw IP literal host bypassing domain reputation');
  }
  if (hasSuspiciousTld) {
    riskScore += 24;
    signals.push(`High-abuse top-level domain (.${tld})`);
  }
  if (hasAtSymbol) {
    riskScore += 32;
    signals.push('Credential-stuffing "@" authority obfuscation in URL');
  }
  if (isShortener) {
    riskScore += resolvedUrl && resolvedUrl !== rawUrl ? 12 : 26;
    signals.push('Link shortener masking destination host');
  }
  if (subdomainDepth >= 2) {
    riskScore += 14;
    signals.push(`Deep subdomain nesting (${subdomainDepth} levels)`);
  }
  if (/(login|verify|auth|claim|airdrop|seed|restore|wallet|unlock|gift|bonus|kyc|invoice|payment|keygen|activator|crack)/i.test(hostname + pathname)) {
    riskScore += 22;
    signals.push('Credential, wallet, or lure keywords detected in URL');
  }
  const lowerPath = pathname.split('?')[0].toLowerCase();
  const pathExt = lowerPath.includes('.') ? lowerPath.split('.').pop() || '' : '';
  if (pathExt && (DANGEROUS_EXTENSIONS.has(pathExt) || HTML_PHISH_EXTENSIONS.has(pathExt))) {
    riskScore += 52;
    signals.push(`Direct download link to executable/script payload (.${pathExt})`);
  }
  if (shannonEntropy > 4.25) {
    riskScore += 14;
    signals.push(`Elevated URL character entropy (${shannonEntropy} bits)`);
  }
  if ((hostname.match(/-/g) || []).length >= 2) {
    riskScore += 12;
    signals.push('Multi-hyphenated deceptive domain structure');
  }

  riskScore = Math.min(99, Math.max(4, riskScore));
  if (signals.length === 0) {
    signals.push('Standard external web link');
  }

  return {
    url: rawUrl,
    resolvedUrl,
    hostname,
    riskScore,
    shannonEntropy,
    impersonatedBrand,
    isPunycodeHomograph,
    isIpLiteral,
    hasSuspiciousTld,
    isShortener,
    subdomainDepth,
    signals,
  };
}

export async function analyzeAttachmentFeatures(input: {
  fileName: string;
  mimeType: string;
  fileSize: number;
  bytes?: Uint8Array;
  headerHexOverride?: string;
  sha256Override?: string;
  deepInspectionSignals?: string[];
  deepInspectionRiskBoost?: number;
}): Promise<FileFeatureAnalysis> {
  const { fileName, mimeType, fileSize, bytes } = input;
  const hasRtloSpoofing = /[\u202A-\u202E\u2066-\u2069]/.test(fileName);
  const cleanName = fileName.replace(/[\u202A-\u202E\u2066-\u2069]/g, '');
  const parts = cleanName.toLowerCase().split('.').filter(Boolean);
  const ext = parts.length > 1 ? parts[parts.length - 1] : '';
  const prevExt = parts.length > 2 ? parts[parts.length - 2] : '';

  const lowerCleanName = cleanName.toLowerCase();
  const matchedProtectedExtension =
    ext && PROTECTED_EXT_NO_DOT.has(ext) ? `.${ext}` : null;

  const matchedLureKeywords = SUSPICIOUS_LURE_KEYWORDS.filter((kw) =>
    lowerCleanName.includes(kw)
  );

  const highCertaintyScamWarezKeywords = matchedLureKeywords.filter((kw) =>
    HIGH_CERTAINTY_WAREZ_SCAM_KEYWORDS.has(kw)
  );
  const cryptoPromoLureKeywords = matchedLureKeywords.filter((kw) =>
    ['crypto', 'wallet', 'premium', 'free', 'bonus', 'usdt', 'binance', 'metamask', 'tonkeeper', 'giveaway'].includes(kw)
  );

  const isArchiveExt = ARCHIVE_EXTENSIONS.has(ext);
  const isHtmlOrPhishAttachment = HTML_PHISH_EXTENSIONS.has(ext);

  const hasDoubleExtension =
    parts.length >= 3 &&
    ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mp3', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'csv', 'html'].includes(prevExt) &&
    (DANGEROUS_EXTENSIONS.has(ext) || HTML_PHISH_EXTENSIONS.has(ext));

  let magicHeaderHex = input.headerHexOverride || '';
  let sha256 = input.sha256Override || '';
  let byteEntropy = 0;

  if (bytes && bytes.length > 0) {
    magicHeaderHex = Array.from(bytes.subarray(0, 16))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    sha256 = await sha256HexFromBuffer(bytes.buffer as ArrayBuffer);
    byteEntropy = computeByteEntropy(bytes);
  } else {
    sha256 = sha256 || (await sha256HexFromString(`${fileName}:${mimeType}:${fileSize}`));
    byteEntropy = DANGEROUS_EXTENSIONS.has(ext) ? 6.84 : 4.92;
  }

  const isPeExecutable = magicHeaderHex.startsWith('4D5A'); // MZ
  const isElfBinary = magicHeaderHex.startsWith('7F454C46'); // .ELF
  const isDexBytecode = magicHeaderHex.startsWith('6465780A'); // dex\n
  const isLnkShortcut = magicHeaderHex.startsWith('4C00000001140200'); // .lnk
  const isChmHelp = magicHeaderHex.startsWith('49545346'); // ITSF
  const isOneNote = magicHeaderHex.startsWith('E4525C7B8CD8A74D'); // .one
  const isOle2Compound = magicHeaderHex.startsWith('D0CF11E0A1B11AE1');
  const isZipContainer = magicHeaderHex.startsWith('504B0304') || magicHeaderHex.startsWith('504B0506');
  const isRarArchive = magicHeaderHex.startsWith('526172211A07');
  const is7zArchive = magicHeaderHex.startsWith('377ABCAF271C');

  let containsAndroidDexOrManifest = false;
  let containsEmbeddedZipExeOrMacro = false;
  let embeddedPayloadName = '';
  let isEncryptedArchive = false;
  let containsPdfExploitAction = false;
  let containsInnerScamHoneypot = false;
  let innerScamReason = '';
  let containsEicarTestSignature = lowerCleanName.includes('eicar');

  if (bytes && bytes.length > 0) {
    const headBytes = bytes.subarray(0, Math.min(bytes.length, 262144));
    const asciiSlice = new TextDecoder('latin1').decode(headBytes);
    const utf16Slice = new TextDecoder('utf-16le').decode(
      headBytes.subarray(0, headBytes.length - (headBytes.length % 2))
    );

    if (asciiSlice.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')) {
      containsEicarTestSignature = true;
    }

    if (isZipContainer) {
      const zipParsed = parseBrowserZipEntries(bytes);
      const isOfficeOpenXml = ['docx', 'xlsx', 'pptx', 'ppsx', 'odt', 'ods'].includes(ext);
      if (
        zipParsed.entryNames.some(
          (n) => n === 'AndroidManifest.xml' || n.endsWith('/AndroidManifest.xml') || n === 'classes.dex'
        )
      ) {
        containsAndroidDexOrManifest = true;
      } else if (isOfficeOpenXml) {
        if (zipParsed.entryNames.some((n) => /(vbaProject\.bin|macrosheets\/|activeX\/|oleObject)/i.test(n))) {
          containsEmbeddedZipExeOrMacro = true;
          embeddedPayloadName = 'VBA Macro / OLE Payload';
        }
      } else {
        const badEntry = zipParsed.entryNames.find((n) => {
          if (n.endsWith('/')) return false;
          const b = n.split(/[\\/]/).pop() || n;
          const ep = b.toLowerCase().split('.').filter(Boolean);
          const ie = ep.length > 1 ? ep[ep.length - 1] : '';
          return DANGEROUS_EXTENSIONS.has(ie) || HTML_PHISH_EXTENSIONS.has(ie);
        });
        if (badEntry) {
          containsEmbeddedZipExeOrMacro = true;
          embeddedPayloadName = badEntry.split(/[\\/]/).pop() || badEntry;
        } else if (zipParsed.isEncrypted) {
          isEncryptedArchive = true;
        }
      }
    }

    if (isRarArchive || is7zArchive || ['rar', '7z', 'tar', 'gz'].includes(ext)) {
      const combinedArchiveText = `${asciiSlice}\n${utf16Slice}`;
      const m = combinedArchiveText.match(
        /([\w\-. ()]{1,70}\.(?:exe|scr|pif|com|msi|dll|apk|xapk|dex|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|url|reg|chm|one|docm|xlsm|pptm|xlsb|iso|img|vhd|dmg|pkg|sh|py|jar|html|htm|svg))(?![a-z0-9])/i
      );
      if (m && m[1]) {
        containsEmbeddedZipExeOrMacro = true;
        embeddedPayloadName = m[1].trim();
      } else if (is7zArchive) {
        const hexHead = Array.from(headBytes.subarray(0, Math.min(headBytes.length, 4096)))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
          .toUpperCase();
        if (hexHead.includes('06F10701')) {
          isEncryptedArchive = true;
        }
      }
    }

    if (isOle2Compound && !['msi', 'msp'].includes(ext)) {
      if (/(_VBA_PROJECT_CUR|VBAProject|AutoOpen|Document_Open|Workbook_Open|powershell|cmd\.exe|mshta|Equation\.3)/i.test(`${asciiSlice}\n${utf16Slice}`)) {
        containsEmbeddedZipExeOrMacro = true;
        embeddedPayloadName = 'Legacy Office AutoOpen VBA Macro';
      }
    }

    if (
      magicHeaderHex.startsWith('25504446') &&
      /\/(?:JavaScript|JS\b|Launch\b|EmbeddedFiles\b|RichMedia\b|SubmitForm\b)/i.test(asciiSlice)
    ) {
      containsPdfExploitAction = true;
    }

    // Check plaintext / HTML / PDF / JSON scam honeypots
    const lowerSample = asciiSlice.toLowerCase();
    if (
      /(seed phrase|recovery phrase|mnemonic|private key|12[\s-]word)/i.test(lowerSample) &&
      /(usdt|tron|trx|btc|eth|wallet|binance|okx|bybit|metamask|withdraw)/i.test(lowerSample)
    ) {
      containsInnerScamHoneypot = true;
      innerScamReason = 'Crypto wallet seed-phrase / multisig gas-trap honeypot detected inside file';
    } else if (
      isHtmlOrPhishAttachment &&
      /(<form|<input|password|window\.location|http-equiv|eval\s*\(|atob\s*\(|api\.telegram\.org\/bot|wallet|login|verify)/i.test(
        lowerSample
      )
    ) {
      containsInnerScamHoneypot = true;
      innerScamReason = 'HTML/SVG credential-phishing form or malicious redirect script detected';
    }
  }

  const hasExecutableHeader =
    isPeExecutable ||
    isElfBinary ||
    isDexBytecode ||
    isLnkShortcut ||
    isChmHelp ||
    isOneNote ||
    containsAndroidDexOrManifest;

  const claimsSafeDocumentOrImage =
    ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'csv', 'mp4', 'docx', 'xlsx', 'pptx'].includes(ext) ||
    mimeType.startsWith('image/') ||
    mimeType === 'application/pdf';

  const mimeMismatch =
    (claimsSafeDocumentOrImage &&
      (isPeExecutable ||
        isElfBinary ||
        isDexBytecode ||
        isLnkShortcut ||
        isRarArchive ||
        is7zArchive ||
        (containsAndroidDexOrManifest && !['apk', 'xapk', 'apks', 'apkm'].includes(ext)))) ||
    (ext === 'pdf' &&
      magicHeaderHex.length >= 8 &&
      magicHeaderHex !== 'N/A (metadata scan)' &&
      !magicHeaderHex.startsWith('25504446'));

  let riskScore = 5;
  const signals: string[] = [];

  if (containsEicarTestSignature) {
    riskScore = Math.max(riskScore, 97);
    signals.push('EICAR Standard Antivirus Test Signature detected');
  }
  if (hasRtloSpoofing) {
    riskScore = Math.max(riskScore, 92);
    signals.push('Unicode Right-to-Left Override (RTLO) filename spoofing detected');
  }
  if (hasDoubleExtension) {
    riskScore = Math.max(riskScore, 91);
    signals.push(`Disguised executable/script file with double extension (.${prevExt}.${ext})`);
  }
  if (matchedProtectedExtension) {
    riskScore = Math.max(riskScore, 84);
    signals.push(`Protected high-risk virus/executable extension blocked (${matchedProtectedExtension})`);
  } else if (
    ['apk', 'xapk', 'apks', 'apkm', 'aab', 'dex'].includes(ext) ||
    containsAndroidDexOrManifest ||
    mimeType === 'application/vnd.android.package-archive'
  ) {
    riskScore = Math.max(riskScore, 86);
    signals.push('Sideloaded Android package (APK/XAPK/DEX) capable of spyware or SMS/OTP theft');
  } else if (DANGEROUS_EXTENSIONS.has(ext) || isLnkShortcut || isChmHelp || isOneNote) {
    riskScore = Math.max(riskScore, 80);
    signals.push(`High-risk executable, shortcut, macro, or disk container (.${ext || 'bin'})`);
  }

  if (containsEmbeddedZipExeOrMacro) {
    riskScore = Math.max(riskScore, 92);
    signals.push(
      embeddedPayloadName
        ? `Archive/document contains hidden malicious payload ("${embeddedPayloadName}")`
        : 'Archive contains hidden executable payload or Office VBA macro binary'
    );
  } else if (isEncryptedArchive) {
    riskScore = Math.max(riskScore, 82);
    signals.push('Password-protected/encrypted archive concealing payload from antivirus scanners');
  }

  if (containsPdfExploitAction) {
    riskScore = Math.max(riskScore, 88);
    signals.push('PDF contains active /JavaScript, /Launch, or embedded file execution trigger');
  }
  if (containsInnerScamHoneypot) {
    riskScore = Math.max(riskScore, 88);
    signals.push(innerScamReason);
  }

  if (matchedLureKeywords.length > 0) {
    if (DANGEROUS_EXTENSIONS.has(ext) || hasExecutableHeader) {
      riskScore = Math.max(riskScore, 92);
      signals.push(
        `Dangerous file combined with lure keyword: ${matchedLureKeywords.slice(0, 3).map((k) => `"${k}"`).join(', ')}`
      );
    } else if (highCertaintyScamWarezKeywords.length > 0 || isArchiveExt || isHtmlOrPhishAttachment) {
      riskScore = Math.max(riskScore, 80);
      signals.push(
        `Suspicious scam/dropper lure matched: ${matchedLureKeywords.slice(0, 3).map((k) => `"${k}"`).join(', ')}`
      );
    } else if (cryptoPromoLureKeywords.length >= 2 || matchedLureKeywords.length >= 3) {
      riskScore = Math.max(riskScore, 74);
      signals.push(
        `Scam social-engineering keywords matched: ${matchedLureKeywords.slice(0, 3).map((k) => `"${k}"`).join(', ')}`
      );
    }
  } else if (isHtmlOrPhishAttachment) {
    riskScore = Math.max(riskScore, 76);
    signals.push(`HTML/script attachment (.${ext}) commonly used for Telegram credential phishing`);
  }

  if (isPeExecutable || isElfBinary || isDexBytecode) {
    riskScore = Math.max(riskScore, 86);
    signals.push(`Binary executable magic header signature (${magicHeaderHex.slice(0, 8)})`);
  }
  if (mimeMismatch) {
    riskScore = Math.max(riskScore, 92);
    signals.push('File magic header bytes contradict declared safe extension / MIME type');
  }
  if (byteEntropy >= 7.25 && (DANGEROUS_EXTENSIONS.has(ext) || isArchiveExt || hasExecutableHeader)) {
    riskScore = Math.min(99, riskScore + 8);
    signals.push(`High byte entropy (${byteEntropy} bits/B) indicative of packed/encrypted payload`);
  }
  if (input.deepInspectionRiskBoost && input.deepInspectionRiskBoost > 0) {
    riskScore = Math.max(riskScore, input.deepInspectionRiskBoost);
  }
  if (Array.isArray(input.deepInspectionSignals)) {
    for (const sig of input.deepInspectionSignals) {
      if (sig && !signals.includes(sig)) signals.push(sig);
    }
  }

  riskScore = Math.min(99, Math.max(3, riskScore));
  if (signals.length === 0) {
    signals.push('Benign attachment signature & consistent MIME metadata');
  }

  let primaryReason = 'Benign file signature';
  if (Array.isArray(input.deepInspectionSignals) && input.deepInspectionSignals[0] && riskScore >= 50) {
    primaryReason = input.deepInspectionSignals[0];
  } else if (hasDoubleExtension) {
    primaryReason = `Disguised executable/script with double extension (.${prevExt}.${ext})`;
  } else if (hasRtloSpoofing) {
    primaryReason = 'Spoofed filename using Unicode RTLO extension override';
  } else if (mimeMismatch) {
    primaryReason = `Disguised binary/archive hiding inside .${ext || 'file'} attachment`;
  } else if (containsEmbeddedZipExeOrMacro) {
    primaryReason = embeddedPayloadName
      ? `Archive/document containing hidden malicious payload ("${embeddedPayloadName}")`
      : 'Archive containing hidden executable or macro virus';
  } else if (isEncryptedArchive) {
    primaryReason = 'Password-encrypted archive hiding payload from malware scanners';
  } else if (containsPdfExploitAction) {
    primaryReason = 'Weaponized PDF with embedded script/launch trigger';
  } else if (containsInnerScamHoneypot) {
    primaryReason = innerScamReason;
  } else if (matchedProtectedExtension && matchedLureKeywords.length > 0) {
    primaryReason = `Protected ${matchedProtectedExtension} file with suspicious keyword (${matchedLureKeywords.slice(0, 3).join(', ')})`;
  } else if (matchedProtectedExtension) {
    primaryReason = `Blocked dangerous virus/executable file (${matchedProtectedExtension})`;
  } else if (hasExecutableHeader) {
    primaryReason = 'Executable binary or shortcut payload signature';
  } else if ((isArchiveExt || isHtmlOrPhishAttachment) && matchedLureKeywords.length > 0) {
    primaryReason = `Scam/dropper .${ext} attachment with lure keyword (${matchedLureKeywords.slice(0, 3).join(', ')})`;
  } else if (isHtmlOrPhishAttachment) {
    primaryReason = `Suspicious .${ext} credential-phishing attachment`;
  } else if (DANGEROUS_EXTENSIONS.has(ext)) {
    primaryReason = `Blocked high-risk executable, macro, or disk container (.${ext})`;
  } else if (matchedLureKeywords.length > 0 && riskScore >= 50) {
    primaryReason = `Suspicious scam lure file (${matchedLureKeywords.slice(0, 3).join(', ')})`;
  }

  const virusTotalUrl = `https://www.virustotal.com/gui/file/${sha256}`;

  return {
    fileName,
    mimeType,
    fileSize,
    sha256,
    magicHeaderHex: magicHeaderHex || 'N/A (metadata scan)',
    byteEntropy,
    riskScore,
    hasDoubleExtension,
    hasRtloSpoofing,
    hasExecutableHeader,
    mimeMismatch,
    matchedProtectedExtension,
    matchedLureKeywords,
    primaryReason,
    virusTotalUrl,
    signals,
  };
}

class OnDeviceNaiveBayesClassifier {
  private classDocCounts: Record<nbLabel, number> = { clean: 0, phishing: 0, scam: 0, spam: 0 };
  private classTokenTotals: Record<nbLabel, number> = { clean: 0, phishing: 0, scam: 0, spam: 0 };
  private tokenCounts: Record<nbLabel, Map<string, number>> = {
    clean: new Map(),
    phishing: new Map(),
    scam: new Map(),
    spam: new Map(),
  };
  private vocabulary = new Set<string>();
  private samples: TrainingSample[] = [];

  constructor() {
    this.resetAndTrainBase();
  }

  resetAndTrainBase(customSamples: TrainingSample[] = []): void {
    this.classDocCounts = { clean: 0, phishing: 0, scam: 0, spam: 0 };
    this.classTokenTotals = { clean: 0, phishing: 0, scam: 0, spam: 0 };
    this.tokenCounts = {
      clean: new Map(),
      phishing: new Map(),
      scam: new Map(),
      spam: new Map(),
    };
    this.vocabulary.clear();
    this.samples = [];

    INITIAL_TRAINING_CORPUS.forEach((item, idx) => {
      this.ingestSample({
        id: `base-${idx}`,
        text: item.text,
        label: item.label,
        addedByUser: false,
        createdAt: 1730000000000 + idx * 1000,
      });
    });

    for (const custom of customSamples) {
      this.ingestSample(custom);
    }
  }

  ingestSample(sample: TrainingSample): void {
    this.samples.push(sample);
    const label = sample.label;
    this.classDocCounts[label] += 1;
    const tokens = tokenize(sample.text);
    for (const tok of tokens) {
      this.vocabulary.add(tok);
      const prev = this.tokenCounts[label].get(tok) || 0;
      this.tokenCounts[label].set(tok, prev + 1);
      this.classTokenTotals[label] += 1;
    }
  }

  getModelStats() {
    return {
      totalSamples: this.samples.length,
      customSamplesCount: this.samples.filter((s) => s.addedByUser).length,
      vocabularySize: this.vocabulary.size,
      classCounts: { ...this.classDocCounts },
      samples: [...this.samples].reverse(),
    };
  }

  predictText(text: string): {
    probabilities: MlClassProbabilities;
    topTokens: Array<{ token: string; weight: number; targetClass: string }>;
  } {
    const tokens = tokenize(text);
    const labels: nbLabel[] = ['clean', 'phishing', 'scam', 'spam'];
    const totalDocs = Object.values(this.classDocCounts).reduce((a, b) => a + b, 0) || 1;
    const vocabSize = Math.max(1, this.vocabulary.size);

    if (tokens.length === 0) {
      return {
        probabilities: { clean: 0.91, phishing: 0.03, scam: 0.03, spam: 0.03 },
        topTokens: [],
      };
    }

    const logScores: Record<nbLabel, number> = {
      clean: Math.log((this.classDocCounts.clean + 1) / (totalDocs + 4)),
      phishing: Math.log((this.classDocCounts.phishing + 1) / (totalDocs + 4)),
      scam: Math.log((this.classDocCounts.scam + 1) / (totalDocs + 4)),
      spam: Math.log((this.classDocCounts.spam + 1) / (totalDocs + 4)),
    };

    const tokenImpacts: Array<{ token: string; weight: number; targetClass: string }> = [];
    const seenTokens = new Set<string>();

    for (const tok of tokens) {
      let bestThreatLabel: nbLabel = 'scam';
      let maxRatio = -Infinity;

      const cleanProb =
        ((this.tokenCounts.clean.get(tok) || 0) + 1) / (this.classTokenTotals.clean + vocabSize);

      for (const lbl of labels) {
        const count = this.tokenCounts[lbl].get(tok) || 0;
        const prob = (count + 1) / (this.classTokenTotals[lbl] + vocabSize);
        logScores[lbl] += Math.log(prob);

        if (lbl !== 'clean') {
          const logOdds = Math.log(prob / cleanProb);
          if (logOdds > maxRatio) {
            maxRatio = logOdds;
            bestThreatLabel = lbl;
          }
        }
      }

      if (!seenTokens.has(tok) && maxRatio > 0.35 && !tok.startsWith('__')) {
        seenTokens.add(tok);
        tokenImpacts.push({
          token: tok.replace(/_/g, ' '),
          weight: Number(maxRatio.toFixed(2)),
          targetClass: bestThreatLabel,
        });
      }
    }

    const maxLog = Math.max(...Object.values(logScores));
    const expScores: Record<nbLabel, number> = {
      clean: Math.exp(logScores.clean - maxLog),
      phishing: Math.exp(logScores.phishing - maxLog),
      scam: Math.exp(logScores.scam - maxLog),
      spam: Math.exp(logScores.spam - maxLog),
    };
    const sumExp = Object.values(expScores).reduce((a, b) => a + b, 0) || 1;

    const probabilities: MlClassProbabilities = {
      clean: Number((expScores.clean / sumExp).toFixed(4)),
      phishing: Number((expScores.phishing / sumExp).toFixed(4)),
      scam: Number((expScores.scam / sumExp).toFixed(4)),
      spam: Number((expScores.spam / sumExp).toFixed(4)),
    };

    tokenImpacts.sort((a, b) => b.weight - a.weight);

    return {
      probabilities,
      topTokens: tokenImpacts.slice(0, 6),
    };
  }

  async evaluateEvent(params: {
    text: string;
    explicitUrls?: string[];
    resolvedUrlsMap?: Record<string, string>;
    attachment?: {
      fileName: string;
      mimeType: string;
      fileSize: number;
      bytes?: Uint8Array;
      headerHexOverride?: string;
      sha256Override?: string;
      deepInspectionSignals?: string[];
      deepInspectionRiskBoost?: number;
    } | null;
  }): Promise<MlAnalysisResult> {
    const t0 = performance.now();
    const { text, explicitUrls = [], resolvedUrlsMap = {}, attachment } = params;

    const { probabilities, topTokens } = this.predictText(text);
    const extractedUrls = extractUrlsFromText(text, explicitUrls);
    // Filter out bare filenames (no http/www/slash) that match protected executable extensions so they are analyzed as files rather than domains
    const protectedExtPattern = /\.(exe|scr|bat|cmd|com|msi|ps1|vbs|js|jar|apk|iso)$/i;
    const realUrls = extractedUrls.filter((u) => {
      if (/^(https?:\/\/|www\.)/i.test(u) || u.includes('/')) return true;
      // Bare token like Invoice.pdf.exe -> treat as file mention unless it's a known domain like google.com
      if (protectedExtPattern.test(u)) {
        const lower = u.toLowerCase();
        if (lower.endsWith('.com') && !/\.(pdf|doc|docx|jpg|png|txt|zip|xls|xlsx)\.com$/i.test(lower)) {
          return true;
        }
        return false;
      }
      return true;
    });

    let effectiveAttachment = attachment || null;
    if (!effectiveAttachment && text) {
      const bareFileMatch = text.match(
        /(?:^|\s|["'(`])([\w.\-\u202A-\u202E\u2066-\u2069]{1,80}\.(?:exe|scr|bat|cmd|com|msi|ps1|vbs|js|jar|apk|iso))(?=$|\s|[.,;!?"')\]])/i
      );
      if (bareFileMatch && bareFileMatch[1]) {
        const candidateFile = bareFileMatch[1];
        const lowerCandidate = candidateFile.toLowerCase();
        // Exclude ordinary .com domains like example.com unless double extension or lure keyword
        const isOrdinaryDotCom =
          lowerCandidate.endsWith('.com') &&
          candidateFile.split('.').length === 2 &&
          !SUSPICIOUS_LURE_KEYWORDS.some((kw) => lowerCandidate.includes(kw));
        if (!isOrdinaryDotCom) {
          effectiveAttachment = {
            fileName: candidateFile,
            mimeType: 'application/octet-stream',
            fileSize: 0,
          };
        }
      }
    }

    const urlAnalyses = realUrls.map((u) => analyzeUrlLexicalFeatures(u, resolvedUrlsMap[u]));
    const fileAnalysis = effectiveAttachment ? await analyzeAttachmentFeatures(effectiveAttachment) : null;

    const maxUrlRisk = urlAnalyses.reduce((max, u) => Math.max(max, u.riskScore), 0);
    const fileRisk = fileAnalysis ? fileAnalysis.riskScore : 0;

    const lowerText = text.toLowerCase();
    const matchedTextLures = SUSPICIOUS_LURE_KEYWORDS.filter((kw) => lowerText.includes(kw));
    const lureBoostScore =
      matchedTextLures.length >= 3
        ? 78
        : matchedTextLures.length === 2
        ? 64
        : /(seed phrase|recovery phrase|5-digit|login code|2fa password|scam|malware|virus|trojan|ransomware)/i.test(lowerText)
        ? 74
        : 0;

    const nbThreatProb = 1 - probabilities.clean;
    const textRiskScore = Math.max(Math.round(nbThreatProb * 92), lureBoostScore);

    // Combine ensemble signals: Naive Bayes text classifier + Lexical URL analyzer + Attachment Malware inspector
    let category = ThreatCategory.Clean;
    let overallRiskScore = Math.max(textRiskScore, maxUrlRisk, fileRisk);

    // Boost combined multi-signal attacks (e.g. urgent scam text + phishing link)
    if (textRiskScore >= 55 && maxUrlRisk >= 55) {
      overallRiskScore = Math.min(99, Math.round(overallRiskScore * 1.12));
    }
    if (fileRisk >= 50) {
      category = ThreatCategory.Malware;
    } else if (maxUrlRisk >= 50 || (probabilities.phishing >= probabilities.scam && probabilities.phishing >= 0.42)) {
      category = ThreatCategory.Phishing;
    } else if (probabilities.scam >= 0.42 && probabilities.scam >= probabilities.spam) {
      category = ThreatCategory.Scam;
    } else if (probabilities.spam >= 0.45) {
      category = ThreatCategory.Spam;
    } else if (overallRiskScore >= 48) {
      category = maxUrlRisk >= textRiskScore ? ThreatCategory.Phishing : ThreatCategory.Scam;
    } else {
      category = ThreatCategory.Clean;
      overallRiskScore = Math.min(34, Math.max(4, Math.round(nbThreatProb * 38)));
    }

    let severity = ThreatSeverity.Safe;
    if (overallRiskScore >= 85) severity = ThreatSeverity.Critical;
    else if (overallRiskScore >= 68) severity = ThreatSeverity.High;
    else if (overallRiskScore >= 45) severity = ThreatSeverity.Medium;
    else if (overallRiskScore >= 25) severity = ThreatSeverity.Low;

    const explanation: string[] = [];
    if (fileAnalysis && fileAnalysis.riskScore >= 45) {
      explanation.push(...fileAnalysis.signals);
    }
    for (const urlInfo of urlAnalyses) {
      if (urlInfo.riskScore >= 45) {
        explanation.push(...urlInfo.signals.map((s) => `${urlInfo.hostname}: ${s}`));
      }
    }
    if (matchedTextLures.length >= 2 && category !== ThreatCategory.Clean) {
      explanation.push(
        `Matched protected scam/lure keywords in message (${matchedTextLures.map((k) => `"${k}"`).join(', ')})`
      );
    }
    if (topTokens.length > 0 && category !== ThreatCategory.Clean) {
      explanation.push(
        `Naive Bayes N-gram classifier matched ${category} indicators (${topTokens
          .slice(0, 3)
          .map((t) => `"${t.token}"`)
          .join(', ')})`
      );
    }
    if (explanation.length === 0) {
      explanation.push('Message passed on-device Naive Bayes, lexical URL, and file signature checks.');
    }

    const winningProb =
      category === ThreatCategory.Clean
        ? probabilities.clean
        : Math.max(
            probabilities.phishing,
            probabilities.scam,
            probabilities.spam,
            overallRiskScore / 100
          );

    const inferenceLatencyMs = Math.max(0.4, Number((performance.now() - t0).toFixed(2)));

    return {
      category,
      severity,
      confidence: Math.min(99.4, Math.max(54, Number((winningProb * 100).toFixed(1)))),
      overallRiskScore,
      inferenceLatencyMs,
      classProbabilities: probabilities,
      topContributingTokens: topTokens,
      urlAnalyses,
      fileAnalysis,
      explanation,
    };
  }
}

export const localMlEngine = new OnDeviceNaiveBayesClassifier();
