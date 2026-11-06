import React, { useState, useEffect } from 'react';
import {
  FileText,
  Send,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Activity,
  HelpCircle,
  Zap,
  ShieldAlert,
} from 'lucide-react';

interface TelegramWeeklyReportCardProps {
  botUsername: string;
  personalChatId: string;
}

export const TelegramWeeklyReportCard: React.FC<TelegramWeeklyReportCardProps> = ({
  botUsername,
  personalChatId,
}) => {
  const [reportText, setReportText] = useState<string>('');
  const [stats, setStats] = useState<{ totalInspected: number; threatsBlocked: number; cleanVerified: number } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [sendingToTg, setSendingToTg] = useState<boolean>(false);
  const [feedbackMsg, setFeedbackMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/telegram/weekly-report');
      const data = await res.json();
      if (data.ok) {
        setReportText(data.reportText || '');
        setStats(data.stats || null);
      }
    } catch (err) {
      console.error('Failed to load weekly report:', err);
    } finally {
      setLoading(false);
    }
  };

  const sendReportToTelegram = async () => {
    setSendingToTg(true);
    setFeedbackMsg(null);
    try {
      const res = await fetch('/api/telegram/send-weekly-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chatId: personalChatId }),
      });
      const data = await res.json();
      if (data.ok) {
        setFeedbackMsg({
          type: 'success',
          text: `Weekly detection report dispatched to your Telegram chat (${personalChatId || 'personal bot chat'})!`,
        });
      } else {
        setFeedbackMsg({
          type: 'error',
          text: data.message || 'Failed to dispatch report to Telegram.',
        });
      }
    } catch (err) {
      setFeedbackMsg({
        type: 'error',
        text: err instanceof Error ? err.message : 'Network error dispatching report',
      });
    } finally {
      setSendingToTg(false);
    }
  };

  useEffect(() => {
    void fetchReport();
  }, []);

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-6 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-sky-50 dark:bg-sky-950 border border-sky-200 dark:border-sky-800 flex items-center justify-center text-sky-600 dark:text-sky-400 shrink-0">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50 flex items-center gap-2">
              <span>Weekly Threat Detection Report &amp; Command Center</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                24/7 Active
              </span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Native Telegram bot commands and 7-day aggregated threat intelligence reports for @{botUsername || 'mydefz_bot'}.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => void fetchReport()}
            disabled={loading}
            className="min-h-[38px] px-3.5 py-1.5 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Audit</span>
          </button>
          <button
            type="button"
            onClick={() => void sendReportToTelegram()}
            disabled={sendingToTg}
            className="min-h-[38px] px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-500 flex items-center gap-1.5 shadow-sm disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{sendingToTg ? 'Sending...' : 'Send to Telegram'}</span>
          </button>
        </div>
      </div>

      {feedbackMsg && (
        <div
          className={`p-3 rounded-xl text-xs flex items-center gap-2 ${
            feedbackMsg.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300'
              : 'bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-300'
          }`}
        >
          {feedbackMsg.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0" />
          )}
          <span>{feedbackMsg.text}</span>
        </div>
      )}

      {/* 4 Telegram Bot Commands Matrix */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-sky-600 dark:text-sky-400 font-mono text-xs font-semibold">
            <FileText className="w-4 h-4" />
            <span>/report</span>
          </div>
          <p className="text-xs font-medium text-slate-800 dark:text-slate-200">Weekly Detection Audit</p>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
            7-day rolling report of blocked malware, rogue APKs, macro droppers, and audit history.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-mono text-xs font-semibold">
            <Activity className="w-4 h-4" />
            <span>/status</span>
          </div>
          <p className="text-xs font-medium text-slate-800 dark:text-slate-200">Live Health &amp; Counters</p>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
            Daemon uptime, memory, engine health matrix, and live scan counters.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400 font-mono text-xs font-semibold">
            <Zap className="w-4 h-4" />
            <span>/test</span>
          </div>
          <p className="text-xs font-medium text-slate-800 dark:text-slate-200">Interactive Diagnostic Ping</p>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
            Round-trip latency test (ms) and real-time sandbox verification simulation.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-purple-600 dark:text-purple-400 font-mono text-xs font-semibold">
            <HelpCircle className="w-4 h-4" />
            <span>/help</span>
          </div>
          <p className="text-xs font-medium text-slate-800 dark:text-slate-200">Supported Formats &amp; Engines</p>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
            Complete guide of protected file types (.exe, .apk, .zip, .docm) &amp; threat tiers.
          </p>
        </div>
      </div>

      {/* Formatted Report Preview Box */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400 font-medium">
          <span>Telegram Bot Live Report Preview</span>
          {stats && (
            <span className="font-mono text-[11px]">
              Inspected: {stats.totalInspected} | Blocked: {stats.threatsBlocked} | Clean: {stats.cleanVerified}
            </span>
          )}
        </div>
        <div className="relative rounded-xl bg-slate-950 text-slate-200 p-4 border border-slate-800 font-mono text-xs leading-relaxed max-h-72 overflow-y-auto whitespace-pre-wrap select-text">
          {loading ? (
            <div className="flex items-center justify-center py-8 text-slate-500 gap-2">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Generating weekly detection report...</span>
            </div>
          ) : (
            reportText || 'No detection events logged yet. Send a file or message to @mydefz_bot to begin recording.'
          )}
        </div>
      </div>
    </div>
  );
};
