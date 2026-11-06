import React, { useRef, useState } from 'react';
import {
  CheckCircle2,
  Copy,
  Cpu,
  ExternalLink,
  FileSearch,
  Globe,
  PlusCircle,
  ShieldAlert,
  Upload,
} from 'lucide-react';
import {
  ThreatCategory,
  type FileFeatureAnalysis,
  type MlAnalysisResult,
  type TrainingSample,
} from '../types/security';
import {
  PROTECTED_FILE_EXTENSIONS,
  SUSPICIOUS_LURE_KEYWORDS,
  analyzeAttachmentFeatures,
  extractUrlsFromText,
  formatSuspiciousFileAlert,
  localMlEngine,
} from '../services/localMlEngine';
import {
  checkFileMultiEngineIntel,
  checkUrlMultiEngineIntel,
  getFileScannerLinks,
  getUrlScannerLinks,
  type FileThreatIntelReport,
  type UrlThreatIntelReport,
} from '../services/threatIntelLinks';
import { useOnlineStatus } from '../hooks/usePWAInstall';

interface ScannerMlViewProps {
  onRecordScanAsEvent: (text: string, analysis: MlAnalysisResult) => Promise<void>;
  onAddTrainingSample: (
    text: string,
    label: 'clean' | 'phishing' | 'scam' | 'spam'
  ) => Promise<void>;
  modelVersionTick: number;
  incomingSharedPayload?: { text: string; analysis: MlAnalysisResult } | null;
}

export const ScannerMlView: React.FC<ScannerMlViewProps> = ({
  onRecordScanAsEvent,
  onAddTrainingSample,
  modelVersionTick,
  incomingSharedPayload,
}) => {
  const isOnline = useOnlineStatus();
  const [subTab, setSubTab] = useState<'message' | 'file' | 'trainer'>('message');

  // Message & Link Scanner State
  const [inputText, setInputText] = useState(
    'Telegram Security Alert: Unusual login attempt detected. Verify your 5-digit login code immediately at https://telegram-security-verify.xyz/auth'
  );
  const [resolveRedirects, setResolveRedirects] = useState(false);
  const [scanningText, setScanningText] = useState(false);
  const [textResult, setTextResult] = useState<MlAnalysisResult | null>(null);
  const [redirectChainInfo, setRedirectChainInfo] = useState<string[] | null>(null);
  const [checkingUrlIntel, setCheckingUrlIntel] = useState(false);
  const [urlIntelReport, setUrlIntelReport] = useState<UrlThreatIntelReport | null>(null);

  // Local Virus & Attachment File Scanner State
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [scanningFile, setScanningFile] = useState(false);
  const [fileResult, setFileResult] = useState<FileFeatureAnalysis | null>(null);
  const [customFileName, setCustomFileName] = useState('Invoice.pdf.exe');
  const [customSenderHandle, setCustomSenderHandle] = useState('@username');
  const [copiedAlert, setCopiedAlert] = useState(false);
  const [checkingFileIntel, setCheckingFileIntel] = useState(false);
  const [fileIntelReport, setFileIntelReport] = useState<FileThreatIntelReport | null>(null);

  // On-Device Naive Bayes Trainer State
  const [trainText, setTrainText] = useState('');
  const [trainLabel, setTrainLabel] = useState<'scam' | 'phishing' | 'spam' | 'clean'>('scam');
  const [trainSavedMsg, setTrainSavedMsg] = useState<string | null>(null);

  // Read live model stats (re-evaluated whenever modelVersionTick increments)
  const modelStats = React.useMemo(() => {
    void modelVersionTick;
    return localMlEngine.getModelStats();
  }, [modelVersionTick]);

  React.useEffect(() => {
    if (incomingSharedPayload) {
      setSubTab('message');
      setInputText(incomingSharedPayload.text);
      setTextResult(incomingSharedPayload.analysis);
    }
  }, [incomingSharedPayload]);

  const handleScanMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    setScanningText(true);
    setRedirectChainInfo(null);
    setUrlIntelReport(null);

    try {
      const resolvedUrlsMap: Record<string, string> = {};
      const extracted = extractUrlsFromText(inputText);
      if (resolveRedirects && extracted.length > 0 && isOnline) {
        try {
          const resp = await fetch('/api/telegram/inspect-url', {
            method: 'POST',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: extracted[0] }),
          });
          const data = await resp.json();
          if (data.ok && data.finalUrl) {
            resolvedUrlsMap[extracted[0]] = data.finalUrl;
            if (Array.isArray(data.hops)) {
              setRedirectChainInfo(data.hops);
            }
          }
        } catch {
          // Fallback gracefully to offline lexical URL analysis
        }
      }

      const evaluation = await localMlEngine.evaluateEvent({
        text: inputText,
        resolvedUrlsMap,
      });
      setTextResult(evaluation);
      await onRecordScanAsEvent(inputText, evaluation);

      // Automatically run live multi-engine threat intelligence if a URL is present and online
      if (evaluation.urlAnalyses.length > 0 && isOnline) {
        const primaryTarget =
          evaluation.urlAnalyses[0].resolvedUrl || evaluation.urlAnalyses[0].url;
        setCheckingUrlIntel(true);
        try {
          const intel = await checkUrlMultiEngineIntel(primaryTarget);
          if (intel?.ok) {
            setUrlIntelReport(intel);
          }
        } catch {
          // Non-fatal offline fallback
        } finally {
          setCheckingUrlIntel(false);
        }
      }
    } finally {
      setScanningText(false);
    }
  };

  const handleRunFileIntelLookup = async (sha256: string, fileName: string) => {
    if (!isOnline) return;
    setCheckingFileIntel(true);
    try {
      const report = await checkFileMultiEngineIntel({ sha256, fileName });
      if (report?.ok) {
        setFileIntelReport(report);
      }
    } catch {
      // Non-fatal fallback
    } finally {
      setCheckingFileIntel(false);
    }
  };

  const handleInspectSelectedFile = async (file: File) => {
    setScanningFile(true);
    setFileIntelReport(null);
    try {
      const sliceBuffer = await file.slice(0, 262144).arrayBuffer();
      const bytes = new Uint8Array(sliceBuffer);
      const analysis = await analyzeAttachmentFeatures({
        fileName: file.name,
        mimeType: file.type || 'application/octet-stream',
        fileSize: file.size,
        bytes,
      });
      setFileResult(analysis);

      const fullEval = await localMlEngine.evaluateEvent({
        text: `Local file attachment inspection: ${file.name}`,
        attachment: {
          fileName: file.name,
          mimeType: file.type || 'application/octet-stream',
          fileSize: file.size,
          bytes,
        },
      });
      await onRecordScanAsEvent(`Inspected local file: ${file.name}`, fullEval);
      void handleRunFileIntelLookup(analysis.sha256, analysis.fileName);
    } finally {
      setScanningFile(false);
    }
  };

  const handleTestFilenameRule = async (
    targetFileName: string,
    headerHexOverride?: string,
    mimeOverride?: string
  ) => {
    const trimmed = targetFileName.trim();
    if (!trimmed) return;
    setScanningFile(true);
    setCopiedAlert(false);
    setFileIntelReport(null);
    try {
      const lower = trimmed.toLowerCase();
      const inferredHeader =
        headerHexOverride ??
        (lower.endsWith('.pdf')
          ? '255044462D312E370A25'
          : lower.endsWith('.apk') || lower.endsWith('.jar')
          ? '504B0304140008080800'
          : lower.endsWith('.exe') || lower.endsWith('.scr') || lower.endsWith('.com')
          ? '4D5A9000030000000400'
          : '');

      const sampleConfig = {
        fileName: trimmed,
        mimeType: mimeOverride || (lower.endsWith('.pdf') ? 'application/pdf' : 'application/octet-stream'),
        fileSize: 1843200,
        headerHexOverride: inferredHeader,
      };

      const analysis = await analyzeAttachmentFeatures(sampleConfig);
      setFileResult(analysis);

      const fullEval = await localMlEngine.evaluateEvent({
        text: `Attachment rule scan (${customSenderHandle || '@username'}): ${trimmed}`,
        attachment: sampleConfig,
      });
      await onRecordScanAsEvent(`Attachment scan: ${trimmed}`, fullEval);
      void handleRunFileIntelLookup(analysis.sha256, analysis.fileName);
    } finally {
      setScanningFile(false);
    }
  };

  const handleTrainSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (trainText.trim().length < 6) return;
    await onAddTrainingSample(trainText.trim(), trainLabel);
    setTrainText('');
    setTrainSavedMsg(
      `Trained local Naive Bayes model on new "${trainLabel}" pattern and encrypted sample in E2EE vault.`
    );
  };

  return (
    <div className="space-y-8">
      <section className="space-y-2 max-w-3xl">
        <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-400">
          <Cpu className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
          <span>On-Device Multinomial Naive Bayes</span>
          <span aria-hidden="true">·</span>
          <span className="font-mono tabular-nums">{modelStats.vocabularySize} N-Gram Features</span>
          <span aria-hidden="true">·</span>
          <span>14-Feature Lexical URL Homograph Inspector</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-50 [text-wrap:balance]">
          Local ML Phishing &amp; Malware Workbench
        </h1>
        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
          Evaluate suspicious Telegram messages, unmask shortened redirect links, compute SHA-256
          and Shannon byte entropy on attachments, or train the on-device classifier with new scam
          patterns.
        </p>
      </section>

      {/* Interactive Mode Switcher */}
      <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800/80 rounded-xl w-fit max-w-full overflow-x-auto">
        <button
          type="button"
          onClick={() => setSubTab('message')}
          className={`min-h-[40px] px-4 py-2 text-xs sm:text-sm font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 ${
            subTab === 'message'
              ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-50 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Message &amp; Link Phishing</span>
        </button>
        <button
          type="button"
          onClick={() => setSubTab('file')}
          className={`min-h-[40px] px-4 py-2 text-xs sm:text-sm font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 ${
            subTab === 'file'
              ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-50 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <FileSearch className="w-4 h-4" />
          <span>Virus &amp; File Shield</span>
        </button>
        <button
          type="button"
          onClick={() => setSubTab('trainer')}
          className={`min-h-[40px] px-4 py-2 text-xs sm:text-sm font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 ${
            subTab === 'trainer'
              ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-50 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <PlusCircle className="w-4 h-4" />
          <span>Train Local Model ({modelStats.totalSamples})</span>
        </button>
      </div>

      {/* SUBTAB 1: Message & URL Phishing Analyzer */}
      {subTab === 'message' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          <form
            onSubmit={handleScanMessage}
            className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4"
          >
            <div className="space-y-1">
              <label
                htmlFor="ml-message-input"
                className="block text-sm font-semibold text-slate-900 dark:text-slate-100"
              >
                Inspect Telegram Message or Suspicious Link
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Classification executes locally in browser memory and logs encrypted telemetry to
                your vault.
              </p>
            </div>

            <textarea
              id="ml-message-input"
              rows={5}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste a suspicious Telegram DM, group offer, or URL..."
              className="w-full p-3.5 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500 leading-relaxed"
            />

            <label className="flex items-center gap-3 min-h-[44px] cursor-pointer text-xs text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={resolveRedirects}
                onChange={(e) => setResolveRedirects(e.target.checked)}
                className="w-4 h-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500"
              />
              <span>
                Unmask shortened URL redirect hops via safe non-executing HEAD probe
              </span>
            </label>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                type="submit"
                disabled={scanningText || !inputText.trim()}
                className="min-h-[44px] px-5 py-2.5 rounded-xl text-sm font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
              >
                {scanningText ? 'Running ML Inference...' : 'Evaluate Threat Locally'}
              </button>
              <button
                type="button"
                onClick={() =>
                  setInputText(
                    'Hey everyone, official Telegram Bot API docs are at https://core.telegram.org/bots/api — see you at standup!'
                  )
                }
                className="min-h-[44px] px-4 py-2 text-xs font-medium border border-slate-200 dark:border-slate-800 rounded-xl text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                Load Benign Example
              </button>
            </div>
          </form>

          <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
            {!textResult ? (
              <div className="py-8 text-center space-y-2">
                <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  Ready for On-Device Inference
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
                  Click &ldquo;Evaluate Threat Locally&rdquo; to inspect Naive Bayes posterior
                  probabilities, N-gram log-odds weights, and domain homograph scores.
                </p>
              </div>
            ) : (
              <>
                <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-center gap-3">
                    {textResult.category === ThreatCategory.Clean ? (
                      <CheckCircle2 className="w-6 h-6 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    ) : (
                      <ShieldAlert className="w-6 h-6 text-red-600 dark:text-red-400 shrink-0" />
                    )}
                    <div>
                      <h3 className="text-base font-bold text-slate-900 dark:text-slate-50 capitalize">
                        {textResult.category} Verdict ({textResult.severity} severity)
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                        Confidence {textResult.confidence}% · Latency{' '}
                        {textResult.inferenceLatencyMs} ms
                      </p>
                    </div>
                  </div>
                  <div className="text-right font-mono tabular-nums">
                    <span className="text-2xl font-bold text-slate-900 dark:text-slate-50">
                      {textResult.overallRiskScore}
                    </span>
                    <span className="text-xs text-slate-500">/100</span>
                  </div>
                </div>

                {/* Posterior Class Probabilities */}
                <div className="space-y-2.5">
                  <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    Naive Bayes Posterior Distribution
                  </h4>
                  {(
                    [
                      { key: 'phishing', label: 'Phishing' },
                      { key: 'scam', label: 'Financial / Impersonation Scam' },
                      { key: 'spam', label: 'Bulk Spam' },
                      { key: 'clean', label: 'Clean Communication' },
                    ] as const
                  ).map((row) => {
                    const pct = Math.round(textResult.classProbabilities[row.key] * 1000) / 10;
                    return (
                      <div key={row.key} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-700 dark:text-slate-300">{row.label}</span>
                          <span className="font-mono tabular-nums text-slate-900 dark:text-slate-100">
                            {pct.toFixed(1)}%
                          </span>
                        </div>
                        <div className="h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-transform duration-150 origin-left ${
                              row.key === 'clean' ? 'bg-emerald-600' : 'bg-sky-600'
                            }`}
                            style={{ width: `${Math.max(2, pct)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Top Contributing N-Grams */}
                {textResult.topContributingTokens.length > 0 && (
                  <div className="space-y-1.5 pt-3 border-t border-slate-100 dark:border-slate-800">
                    <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      Top Discriminative N-Gram Tokens
                    </h4>
                    <p className="text-xs text-slate-600 dark:text-slate-400 font-mono">
                      {textResult.topContributingTokens
                        .map((t) => `${t.token} (+${t.weight} ${t.targetClass})`)
                        .join(' · ')}
                    </p>
                  </div>
                )}

                {/* Lexical URL Signals + Multi-Engine Free Scam/Phishing Scanners */}
                {textResult.urlAnalyses.length > 0 && (
                  <div className="space-y-3 pt-3 border-t border-slate-100 dark:border-slate-800">
                    <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      URL Lexical &amp; Homograph Telemetry
                    </h4>
                    {textResult.urlAnalyses.map((u, idx) => (
                      <div key={idx} className="text-xs space-y-2">
                        <p className="font-mono break-all text-slate-900 dark:text-slate-100">
                          {u.resolvedUrl && u.resolvedUrl !== u.url
                            ? `${u.url} → ${u.resolvedUrl}`
                            : u.url}
                        </p>
                        <p className="text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                          Risk {u.riskScore}/100 · Entropy {u.shannonEntropy} bits · Subdomains{' '}
                          {u.subdomainDepth}
                        </p>
                        <p className="text-slate-700 dark:text-slate-300">
                          {u.signals.join(' · ')}
                        </p>

                        {/* 1-Click Free External Scam & Phishing Portals */}
                        <div className="pt-1.5 space-y-1.5">
                          <p className="text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                            Verify Domain Across Free Threat Intelligence Engines:
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {getUrlScannerLinks(u.resolvedUrl || u.url).map((portal) => (
                              <a
                                key={portal.id}
                                href={portal.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                title={portal.description}
                                className="min-h-[34px] px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs font-medium text-slate-800 dark:text-slate-200 hover:border-sky-500 hover:text-sky-600 dark:hover:text-sky-400 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
                              >
                                <span>{portal.name}</span>
                                <ExternalLink className="w-3 h-3 opacity-70" />
                              </a>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}

                    {/* Live Server-Side Multi-Engine Reputation Results */}
                    <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                          Live Multi-Engine Feed Lookup (abuse.ch · Cloudflare 1.1.1.2 · Quad9 ·
                          RDAP · MetaDefender)
                        </span>
                        {checkingUrlIntel && (
                          <span className="text-xs text-sky-600 dark:text-sky-400 font-mono">
                            Querying feeds...
                          </span>
                        )}
                      </div>

                      {!isOnline && (
                        <p className="text-xs text-amber-800 dark:text-amber-300 bg-amber-50/80 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-xl px-3.5 py-2.5">
                          Wi-Fi / Mobile Data Disconnected — Enable Wi-Fi or 4G/5G to query live
                          Cloud Server multi-engine feeds (abuse.ch, OPSWAT MetaDefender, Cloudflare
                          1.1.1.2, Quad9, RDAP).
                        </p>
                      )}

                      {urlIntelReport && (
                        <div className="divide-y divide-slate-100 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl bg-slate-50/70 dark:bg-slate-950/60 px-3.5">
                          {urlIntelReport.engines.map((eng) => (
                            <div
                              key={eng.engineId}
                              className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 text-xs"
                            >
                              <div className="min-w-0 space-y-0.5">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                                    {eng.engineName}
                                  </span>
                                  <span
                                    className={`font-semibold uppercase text-[10px] ${
                                      eng.status === 'malicious'
                                        ? 'text-red-600 dark:text-red-400'
                                        : eng.status === 'suspicious'
                                        ? 'text-amber-700 dark:text-amber-400'
                                        : eng.status === 'clean' || eng.status === 'known_good'
                                        ? 'text-emerald-700 dark:text-emerald-400'
                                        : 'text-slate-500 dark:text-slate-400'
                                    }`}
                                  >
                                    {eng.status.replace('_', ' ')}
                                  </span>
                                </div>
                                <p className="text-slate-600 dark:text-slate-400">{eng.summary}</p>
                              </div>
                              <a
                                href={eng.lookupUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sky-600 dark:text-sky-400 hover:underline inline-flex items-center gap-1 shrink-0 font-medium"
                              >
                                <span>Open</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {redirectChainInfo && redirectChainInfo.length > 1 && (
                  <div className="pt-2 text-xs text-slate-600 dark:text-slate-400 font-mono break-all">
                    Redirect Hops: {redirectChainInfo.join(' -> ')}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 2: Virus & Malicious Attachment Inspector */}
      {subTab === 'file' && (
        <div className="space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
              <div className="space-y-1">
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                  Zero-Upload File &amp; Extension Protection Scanner
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                  Blocks dangerous attachment extensions, double-extension disguises, and
                  social-engineering lure filenames locally before execution.
                </p>
              </div>

              {/* Custom Filename + Sender Handle Rule Tester */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleTestFilenameRule(customFileName);
                }}
                className="space-y-3"
              >
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  <div>
                    <label
                      htmlFor="sender-handle-test"
                      className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                    >
                      Sender Handle
                    </label>
                    <input
                      id="sender-handle-test"
                      type="text"
                      value={customSenderHandle}
                      onChange={(e) => setCustomSenderHandle(e.target.value)}
                      placeholder="@username"
                      className="w-full min-h-[42px] px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label
                      htmlFor="filename-rule-test"
                      className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                    >
                      Attachment Filename to Test
                    </label>
                    <input
                      id="filename-rule-test"
                      type="text"
                      value={customFileName}
                      onChange={(e) => setCustomFileName(e.target.value)}
                      placeholder="Invoice.pdf.exe"
                      className="w-full min-h-[42px] px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={scanningFile || !customFileName.trim()}
                  className="min-h-[44px] px-5 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors whitespace-nowrap disabled:opacity-50"
                >
                  {scanningFile ? 'Evaluating File Rules...' : 'Test File Protection Alert'}
                </button>
              </form>

              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) {
                    setCopiedAlert(false);
                    void handleInspectSelectedFile(f);
                  }
                }}
              />

              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={scanningFile}
                className="w-full min-h-[108px] border border-dashed border-slate-300 dark:border-slate-700 rounded-2xl p-5 flex flex-col items-center justify-center gap-1.5 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors text-center"
              >
                <Upload className="w-5 h-5 text-sky-600 dark:text-sky-400" />
                <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  Or Select a Real Local File to Compute SHA-256 &amp; Entropy
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  100% local Web Crypto inspection — zero file upload
                </span>
              </button>

              <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                <p className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  Quick preset malware vectors:
                </p>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setCustomFileName('Invoice.pdf.exe');
                      void handleTestFilenameRule('Invoice.pdf.exe');
                    }}
                    className="min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                  >
                    Invoice.pdf.exe
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setCustomFileName('Crypto_Wallet_Seed_Keygen.bat');
                      void handleTestFilenameRule('Crypto_Wallet_Seed_Keygen.bat');
                    }}
                    className="min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                  >
                    Crypto_Wallet_Seed_Keygen.bat
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setCustomFileName('Free_Premium_Crack_Activator.iso');
                      void handleTestFilenameRule('Free_Premium_Crack_Activator.iso');
                    }}
                    className="min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                  >
                    Free_Premium_Crack_Activator.iso
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setCustomFileName('Quarterly_Report_2026.pdf');
                      void handleTestFilenameRule(
                        'Quarterly_Report_2026.pdf',
                        '255044462D312E370A25',
                        'application/pdf'
                      );
                    }}
                    className="min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                  >
                    Valid PDF
                  </button>
                </div>
              </div>
            </div>

            <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
              {!fileResult ? (
                <div className="py-12 text-center space-y-2">
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                    Ready to Inspect Attachment Rules
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
                    Click &ldquo;Test File Protection Alert&rdquo; or select any local file to
                    generate the Telegram security alert and VirusTotal SHA-256 verification link.
                  </p>
                </div>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
                    <div className="min-w-0">
                      <h3 className="text-base font-bold text-slate-900 dark:text-slate-50 break-all">
                        {fileResult.fileName}
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                        {(fileResult.fileSize / 1024).toFixed(1)} KB · {fileResult.primaryReason}
                      </p>
                    </div>
                    <div className="text-right font-mono tabular-nums shrink-0">
                      <span
                        className={`text-2xl font-bold ${
                          fileResult.riskScore >= 45
                            ? 'text-red-600 dark:text-red-400'
                            : 'text-emerald-600 dark:text-emerald-400'
                        }`}
                      >
                        {fileResult.riskScore}
                      </span>
                      <span className="text-xs text-slate-500">/100</span>
                    </div>
                  </div>

                  {/* Formatted Telegram Security Alert Output */}
                  {fileResult.riskScore >= 45 && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                          Generated Telegram Warning Alert
                        </h4>
                        <div className="flex items-center gap-3">
                          <button
                            type="button"
                            onClick={async () => {
                              const formatted = formatSuspiciousFileAlert({
                                senderUsername: customSenderHandle,
                                fileName: fileResult.fileName,
                                reason: fileResult.primaryReason,
                              });
                              await navigator.clipboard.writeText(formatted);
                              setCopiedAlert(true);
                            }}
                            className="text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1 whitespace-nowrap"
                          >
                            <Copy className="w-3.5 h-3.5" />
                            <span>{copiedAlert ? 'Copied Alert' : 'Copy Alert'}</span>
                          </button>
                          <a
                            href={fileResult.virusTotalUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1 whitespace-nowrap"
                          >
                            <span>Scan with VirusTotal</span>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      </div>
                      <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono whitespace-pre-wrap leading-relaxed">
                        {formatSuspiciousFileAlert({
                          senderUsername: customSenderHandle,
                          fileName: fileResult.fileName,
                          reason: fileResult.primaryReason,
                        })}
                      </pre>
                    </div>
                  )}

                  <div className="space-y-1.5 text-xs font-mono tabular-nums text-slate-700 dark:text-slate-300 pt-2 border-t border-slate-100 dark:border-slate-800">
                    <div>Magic Header Bytes: {fileResult.magicHeaderHex}</div>
                    <div>Shannon Byte Entropy: {fileResult.byteEntropy} / 8.000 bits/byte</div>
                    <div className="break-all">SHA-256: {fileResult.sha256}</div>
                  </div>

                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-1.5">
                    <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      Rule &amp; Signature Attribution
                    </h4>
                    <ul className="space-y-1 text-xs text-slate-700 dark:text-slate-300">
                      {fileResult.signals.map((sig, i) => (
                        <li key={i}>· {sig}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Multi-Engine Free Malware & Hash Scanners (MetaDefender, abuse.ch MalwareBazaar, ThreatFox, Hybrid Analysis, Kaspersky, Jotti, VirusTotal) */}
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                        Free Multi-Engine File &amp; Malware Verification Portals
                      </h4>
                      {checkingFileIntel && (
                        <span className="text-xs font-mono text-sky-600 dark:text-sky-400">
                          Querying SHA-256 feeds...
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap gap-2">
                      {getFileScannerLinks(fileResult.sha256).map((scanner) => (
                        <a
                          key={scanner.id}
                          href={scanner.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={scanner.description}
                          className="min-h-[36px] px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs font-medium text-slate-800 dark:text-slate-200 hover:border-sky-500 hover:text-sky-600 dark:hover:text-sky-400 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
                        >
                          <span>{scanner.name}</span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            ({scanner.badge})
                          </span>
                          <ExternalLink className="w-3 h-3 opacity-75" />
                        </a>
                      ))}
                    </div>

                    {!isOnline && (
                      <p className="text-xs text-amber-800 dark:text-amber-300 bg-amber-50/80 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-xl px-3.5 py-2.5">
                        Wi-Fi / Mobile Data Disconnected — Enable Wi-Fi or 4G/5G to query live Cloud
                        Server SHA-256 feeds (MalwareBazaar, ThreatFox, OPSWAT MetaDefender, Hybrid
                        Analysis).
                      </p>
                    )}

                    {fileIntelReport && (
                      <div className="divide-y divide-slate-100 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl bg-slate-50/70 dark:bg-slate-950/60 px-3.5">
                        {fileIntelReport.engines.map((eng) => (
                          <div
                            key={eng.engineId}
                            className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 text-xs"
                          >
                            <div className="min-w-0 space-y-0.5">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-slate-900 dark:text-slate-100">
                                  {eng.engineName}
                                </span>
                                <span
                                  className={`font-semibold uppercase text-[10px] ${
                                    eng.status === 'malicious'
                                      ? 'text-red-600 dark:text-red-400'
                                      : eng.status === 'suspicious'
                                      ? 'text-amber-700 dark:text-amber-400'
                                      : eng.status === 'clean' || eng.status === 'known_good'
                                      ? 'text-emerald-700 dark:text-emerald-400'
                                      : 'text-slate-500 dark:text-slate-400'
                                  }`}
                                >
                                  {eng.status.replace('_', ' ')}
                                </span>
                              </div>
                              <p className="text-slate-600 dark:text-slate-400">{eng.summary}</p>
                            </div>
                            <a
                              href={eng.lookupUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sky-600 dark:text-sky-400 hover:underline inline-flex items-center gap-1 shrink-0 font-medium"
                            >
                              <span>Verify</span>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Active File Protection Signatures Overview */}
          <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Protected Dangerous File Extensions ({PROTECTED_FILE_EXTENSIONS.length})
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Blocked automatically across direct extensions, URL downloads, and double-extension
                disguises:
              </p>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs font-mono pt-1">
                {PROTECTED_FILE_EXTENSIONS.map((ext, idx) => {
                  const matched = fileResult?.matchedProtectedExtension === ext;
                  return (
                    <React.Fragment key={ext}>
                      {idx > 0 && (
                        <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
                          ·
                        </span>
                      )}
                      <span
                        className={
                          matched
                            ? 'font-bold text-red-600 dark:text-red-400 underline'
                            : 'text-slate-700 dark:text-slate-300'
                        }
                      >
                        {ext}
                      </span>
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Suspicious Lure Filename Keywords ({SUSPICIOUS_LURE_KEYWORDS.length})
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Social-engineering keywords monitored across incoming Telegram attachment filenames:
              </p>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs font-mono pt-1">
                {SUSPICIOUS_LURE_KEYWORDS.map((kw, idx) => {
                  const matched = fileResult?.matchedLureKeywords.includes(kw);
                  return (
                    <React.Fragment key={kw}>
                      {idx > 0 && (
                        <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
                          ·
                        </span>
                      )}
                      <span
                        className={
                          matched
                            ? 'font-bold text-red-600 dark:text-red-400 underline'
                            : 'text-slate-700 dark:text-slate-300'
                        }
                      >
                        {kw}
                      </span>
                    </React.Fragment>
                  );
                })}
              </div>
            </div>
          </section>
        </div>
      )}

      {/* SUBTAB 3: On-Device Naive Bayes Trainer */}
      {subTab === 'trainer' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          <form
            onSubmit={handleTrainSubmit}
            className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4"
          >
            <div className="space-y-1">
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                Teach New Scam or Safe Pattern
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Add domain-specific messages to immediately recalculate Laplace-smoothed Naive Bayes
                token weights on your device. Custom samples are encrypted inside your E2EE vault.
              </p>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="train-category"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300"
              >
                Classification Label
              </label>
              <select
                id="train-category"
                value={trainLabel}
                onChange={(e) => setTrainLabel(e.target.value as typeof trainLabel)}
                className="w-full min-h-[44px] px-3.5 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
              >
                <option value="scam">Scam / Impersonation / Fake Profit</option>
                <option value="phishing">Phishing / OTP &amp; Seed Theft</option>
                <option value="spam">Unsolicited Bulk Spam</option>
                <option value="clean">Legitimate / False-Positive Correction</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="train-sample-text"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300"
              >
                Example Message Text
              </label>
              <textarea
                id="train-sample-text"
                rows={4}
                value={trainText}
                onChange={(e) => setTrainText(e.target.value)}
                placeholder="Paste a real scam message or safe internal message..."
                className="w-full p-3.5 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
              />
            </div>

            <button
              type="submit"
              disabled={trainText.trim().length < 6}
              className="w-full min-h-[44px] px-5 py-2.5 rounded-xl text-sm font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors disabled:opacity-50"
            >
              Train On-Device Model
            </button>

            {trainSavedMsg && (
              <p className="text-xs text-emerald-700 dark:text-emerald-400 font-medium">
                {trainSavedMsg}
              </p>
            )}
          </form>

          <div className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
              <div>
                <h3 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                  Active On-Device Corpus Summary
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                  Clean: {modelStats.classCounts.clean} · Phishing:{' '}
                  {modelStats.classCounts.phishing} · Scam: {modelStats.classCounts.scam} · Spam:{' '}
                  {modelStats.classCounts.spam}
                </p>
              </div>
              <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
                Custom Samples: {modelStats.customSamplesCount}
              </span>
            </div>

            <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[340px] overflow-y-auto">
              {modelStats.samples.slice(0, 14).map((s: TrainingSample) => (
                <div key={s.id} className="py-2.5 space-y-1">
                  <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                    <span className="font-semibold capitalize text-slate-800 dark:text-slate-200">
                      {s.label}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>{s.addedByUser ? 'Custom Encrypted Sample' : 'Built-in Corpus'}</span>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 line-clamp-2">
                    {s.text}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
