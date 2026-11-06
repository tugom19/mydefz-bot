import React, { useMemo, useState } from 'react';
import { BarChart3, Download, FileSpreadsheet, Lock } from 'lucide-react';
import {
  ChatSourceType,
  EnforcementStatus,
  ThreatCategory,
  type ThreatEvent,
} from '../types/security';

interface AnalyticsReportViewProps {
  events: ThreatEvent[];
  onExportEncryptedVault: () => void;
}

export const AnalyticsReportView: React.FC<AnalyticsReportViewProps> = ({
  events,
  onExportEncryptedVault,
}) => {
  const [rangeDays, setRangeDays] = useState<1 | 7 | 30>(7);

  const scopedEvents = useMemo(() => {
    const cutoff = Date.now() - rangeDays * 24 * 3600 * 1000;
    return events.filter((e) => e.timestamp >= cutoff);
  }, [events, rangeDays]);

  const summary = useMemo(() => {
    const total = scopedEvents.length;
    const threats = scopedEvents.filter((e) => e.analysis.category !== ThreatCategory.Clean);
    const phishing = threats.filter((e) => e.analysis.category === ThreatCategory.Phishing).length;
    const malware = threats.filter((e) => e.analysis.category === ThreatCategory.Malware).length;
    const scam = threats.filter((e) => e.analysis.category === ThreatCategory.Scam).length;
    const spam = threats.filter((e) => e.analysis.category === ThreatCategory.Spam).length;
    const personalDms = scopedEvents.filter((e) => e.personalWarningSent).length;
    const blockRate = total > 0 ? ((threats.length / total) * 100).toFixed(1) : '0.0';

    return {
      total,
      threatCount: threats.length,
      phishing,
      malware,
      scam,
      spam,
      personalDms,
      blockRate,
    };
  }, [scopedEvents]);

  // Bucketed chart series (6 time buckets across the chosen timeframe)
  const chartBuckets = useMemo(() => {
    const bucketCount = 6;
    const now = Date.now();
    const totalSpanMs = rangeDays * 24 * 3600 * 1000;
    const stepMs = totalSpanMs / bucketCount;

    return Array.from({ length: bucketCount }, (_, idx) => {
      const start = now - totalSpanMs + idx * stepMs;
      const end = start + stepMs;
      const slice = scopedEvents.filter((e) => e.timestamp >= start && e.timestamp < end);
      const phishingAndMalware = slice.filter(
        (e) =>
          e.analysis.category === ThreatCategory.Phishing ||
          e.analysis.category === ThreatCategory.Malware
      ).length;
      const scamAndSpam = slice.filter(
        (e) =>
          e.analysis.category === ThreatCategory.Scam ||
          e.analysis.category === ThreatCategory.Spam
      ).length;
      const clean = slice.filter((e) => e.analysis.category === ThreatCategory.Clean).length;

      const labelDate = new Date(end);
      const label =
        rangeDays === 1
          ? labelDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : labelDate.toLocaleDateString([], { month: 'short', day: 'numeric' });

      return {
        label,
        phishingAndMalware,
        scamAndSpam,
        clean,
        total: phishingAndMalware + scamAndSpam + clean,
      };
    });
  }, [scopedEvents, rangeDays]);

  const maxBucketTotal = useMemo(
    () => Math.max(4, ...chartBuckets.map((b) => b.total)),
    [chartBuckets]
  );

  // Breakdown by Chat Source Type
  const channelMatrix = useMemo(() => {
    const sources: Array<{ type: ChatSourceType; label: string }> = [
      { type: ChatSourceType.Private, label: 'Private Direct Chats' },
      { type: ChatSourceType.Supergroup, label: 'Supergroups' },
      { type: ChatSourceType.Group, label: 'Standard Groups' },
      { type: ChatSourceType.Channel, label: 'Broadcast Channels' },
      { type: ChatSourceType.LocalScan, label: 'Manual Local Scans' },
    ];

    return sources.map((src) => {
      const matching = scopedEvents.filter((e) => e.chatType === src.type);
      const blocked = matching.filter((e) => e.analysis.category !== ThreatCategory.Clean);
      const quarantined = matching.filter(
        (e) => e.enforcement === EnforcementStatus.Quarantined
      ).length;
      const meanRisk =
        matching.length > 0
          ? Math.round(
              matching.reduce((sum, item) => sum + item.analysis.overallRiskScore, 0) /
                matching.length
            )
          : 0;
      return {
        ...src,
        inspected: matching.length,
        blocked: blocked.length,
        quarantined,
        meanRisk,
      };
    });
  }, [scopedEvents]);

  // Top Flagged Malicious Indicators (Domains & File Payloads)
  const topIndicators = useMemo(() => {
    const list: Array<{
      indicator: string;
      kind: string;
      risk: number;
      chatTitle: string;
    }> = [];

    for (const evt of scopedEvents) {
      if (evt.analysis.fileAnalysis && evt.analysis.fileAnalysis.riskScore >= 45) {
        list.push({
          indicator: evt.analysis.fileAnalysis.fileName,
          kind: 'Malicious File Signature',
          risk: evt.analysis.fileAnalysis.riskScore,
          chatTitle: evt.chatTitle,
        });
      }
      for (const u of evt.analysis.urlAnalyses) {
        if (u.riskScore >= 45) {
          list.push({
            indicator: u.hostname,
            kind: u.impersonatedBrand
              ? `Brand Phishing (${u.impersonatedBrand})`
              : 'Suspicious URL Host',
            risk: u.riskScore,
            chatTitle: evt.chatTitle,
          });
        }
      }
    }

    return list.sort((a, b) => b.risk - a.risk).slice(0, 8);
  }, [scopedEvents]);

  const handleDownloadCsv = () => {
    const headers = [
      'Timestamp_ISO',
      'Category',
      'Severity',
      'Risk_Score',
      'Confidence_Pct',
      'Chat_Type',
      'Chat_Title',
      'Sender',
      'Enforcement',
      'Personal_Warning_Sent',
      'Latency_ms',
    ];
    const rows = scopedEvents.map((e) => [
      new Date(e.timestamp).toISOString(),
      e.analysis.category,
      e.analysis.severity,
      String(e.analysis.overallRiskScore),
      String(e.analysis.confidence),
      e.chatType,
      `"${e.chatTitle.replace(/"/g, '""')}"`,
      `"${e.senderName.replace(/"/g, '""')}"`,
      e.enforcement,
      String(e.personalWarningSent),
      String(e.analysis.inferenceLatencyMs),
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentinelgram-threat-report-${rangeDays}d.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJsonAudit = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      windowDays: rangeDays,
      summary,
      channelMatrix,
      topIndicators,
      eventsCount: scopedEvents.length,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentinelgram-admin-audit-${rangeDays}d.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8">
      <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-400">
            <BarChart3 className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
            <span>Administrative Oversight</span>
            <span aria-hidden="true">·</span>
            <span>Threat Attribution &amp; Audit Exports</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-50 [text-wrap:balance]">
            Blocked Threat Analytics &amp; Oversight Reports
          </h1>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
            Audit blocked phishing campaigns, malware attachments, and spam rates across monitored
            private and group chats without exposing decrypted history to external servers.
          </p>
        </div>

        {/* Timeframe Selector & Export Actions */}
        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800/80 rounded-xl">
            {(
              [
                { days: 1, label: '24 Hours' },
                { days: 7, label: '7 Days' },
                { days: 30, label: '30 Days' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.days}
                type="button"
                onClick={() => setRangeDays(opt.days)}
                className={`min-h-[38px] px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 ${
                  rangeDays === opt.days
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-50 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={handleDownloadCsv}
            className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <FileSpreadsheet className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <span>Download CSV</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadJsonAudit}
            className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON</span>
          </button>

          <button
            type="button"
            onClick={onExportEncryptedVault}
            className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:opacity-90 transition-opacity flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>E2EE Bundle</span>
          </button>
        </div>
      </section>

      {/* Executive Vector Breakdown Strip */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl grid grid-cols-2 lg:grid-cols-5 divide-y lg:divide-y-0 sm:divide-x divide-slate-200 dark:divide-slate-800">
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Threat Rate</p>
          <p className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {summary.blockRate}%
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
            {summary.threatCount} of {summary.total} events
          </p>
        </div>
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Phishing Links</p>
          <p className="text-2xl font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
            {summary.phishing}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">Lookalike &amp; OTP lures</p>
        </div>
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Virus &amp; Malware Files
          </p>
          <p className="text-2xl font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
            {summary.malware}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">APK, PE &amp; RTLO payloads</p>
        </div>
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Scam &amp; Spam Filtered
          </p>
          <p className="text-2xl font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
            {summary.scam + summary.spam}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
            {summary.scam} scam · {summary.spam} spam
          </p>
        </div>
        <div className="p-5 space-y-1 col-span-2 lg:col-span-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Personal DM Alerts
          </p>
          <p className="text-2xl font-bold font-mono tabular-nums text-sky-600 dark:text-sky-400">
            {summary.personalDms}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">Delivered via Bot API</p>
        </div>
      </section>

      {/* Chart + Indicator Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Stacked SVG Timeline Chart */}
        <div className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                Intercepted Volume by Time Interval
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Distribution of high-risk phishing/malware, scam/spam, and clean traffic
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs text-slate-600 dark:text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs bg-red-600 inline-block" />
                <span>Phishing/Malware</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs bg-amber-500 inline-block" />
                <span>Scam/Spam</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs bg-slate-300 dark:bg-slate-700 inline-block" />
                <span>Clean</span>
              </span>
            </div>
          </div>

          <div className="pt-2">
            <svg
              viewBox="0 0 600 220"
              role="img"
              aria-label="Stacked bar chart of inspected Telegram messages and blocked threats"
              className="w-full h-52 overflow-visible"
            >
              {[0, 0.5, 1].map((ratio, i) => {
                const y = 180 - ratio * 150;
                const val = Math.round(ratio * maxBucketTotal);
                return (
                  <g key={i}>
                    <line
                      x1={36}
                      x2={585}
                      y1={y}
                      y2={y}
                      stroke="currentColor"
                      className="text-slate-100 dark:text-slate-800"
                      strokeWidth={1}
                    />
                    <text
                      x={28}
                      y={y + 4}
                      textAnchor="end"
                      className="fill-slate-400 text-[10px] font-mono"
                    >
                      {val}
                    </text>
                  </g>
                );
              })}

              {chartBuckets.map((b, idx) => {
                const slotWidth = (585 - 48) / chartBuckets.length;
                const barWidth = 34;
                const x = 52 + idx * slotWidth + (slotWidth - barWidth) / 2;

                const hClean = (b.clean / maxBucketTotal) * 150;
                const hScam = (b.scamAndSpam / maxBucketTotal) * 150;
                const hCrit = (b.phishingAndMalware / maxBucketTotal) * 150;

                const yClean = 180 - hClean;
                const yScam = yClean - hScam;
                const yCrit = yScam - hCrit;

                return (
                  <g key={b.label}>
                    {hClean > 0 && (
                      <rect
                        x={x}
                        y={yClean}
                        width={barWidth}
                        height={hClean}
                        rx={3}
                        className="fill-slate-300 dark:fill-slate-700"
                      />
                    )}
                    {hScam > 0 && (
                      <rect
                        x={x}
                        y={yScam}
                        width={barWidth}
                        height={hScam}
                        rx={3}
                        className="fill-amber-500"
                      />
                    )}
                    {hCrit > 0 && (
                      <rect
                        x={x}
                        y={yCrit}
                        width={barWidth}
                        height={hCrit}
                        rx={3}
                        className="fill-red-600"
                      />
                    )}
                    <text
                      x={x + barWidth / 2}
                      y={202}
                      textAnchor="middle"
                      className="fill-slate-500 dark:fill-slate-400 text-[10px] font-mono"
                    >
                      {b.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Top Flagged Indicators */}
        <div className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
              High-Risk Blocked Indicators
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Phishing hostnames &amp; malicious attachment signatures intercepted
            </p>
          </div>

          {topIndicators.length === 0 ? (
            <p className="text-xs text-slate-500 dark:text-slate-400 py-8 text-center">
              No high-risk domain or file indicators recorded in this window.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {topIndicators.map((ind, idx) => (
                <div key={`${ind.indicator}-${idx}`} className="py-2.5 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-xs font-mono font-medium text-slate-900 dark:text-slate-100 truncate">
                      {ind.indicator}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                      {ind.kind} · {ind.chatTitle}
                    </p>
                  </div>
                  <span className="text-xs font-mono tabular-nums font-semibold text-red-600 dark:text-red-400 shrink-0">
                    {ind.risk}/100
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* High-Density Administrative Source Breakdown Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
            Protection Coverage by Chat Channel Type
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs sm:text-sm">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                <th className="py-3 px-6 font-medium">Channel Scope</th>
                <th className="py-3 px-4 font-medium text-right">Inspected</th>
                <th className="py-3 px-4 font-medium text-right">Blocked Threats</th>
                <th className="py-3 px-4 font-medium text-right">Quarantined</th>
                <th className="py-3 px-6 font-medium text-right">Mean Risk Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono tabular-nums">
              {channelMatrix.map((row) => (
                <tr
                  key={row.type}
                  className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors"
                >
                  <td className="py-3 px-6 font-sans font-medium text-slate-900 dark:text-slate-100">
                    {row.label}
                  </td>
                  <td className="py-3 px-4 text-right text-slate-700 dark:text-slate-300">
                    {row.inspected}
                  </td>
                  <td className="py-3 px-4 text-right text-red-600 dark:text-red-400 font-semibold">
                    {row.blocked}
                  </td>
                  <td className="py-3 px-4 text-right text-slate-700 dark:text-slate-300">
                    {row.quarantined}
                  </td>
                  <td className="py-3 px-6 text-right text-slate-900 dark:text-slate-100">
                    {row.meanRisk}/100
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
