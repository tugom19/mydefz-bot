import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock,
  Crown,
  FileWarning,
  Plus,
  RefreshCw,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  UserCheck,
  UserMinus,
  Users,
  X,
} from 'lucide-react';

import type {
  BotInspectionDiagnostic,
  ManagedTelegramAccount,
  UserBotPolicyConfig,
} from '../types/security';

export type { ManagedTelegramAccount };

export interface AdminAccountsResponse {
  ok: boolean;
  adminChatId: string;
  accounts: ManagedTelegramAccount[];
  logsByAccount?: Record<string, BotInspectionDiagnostic[]>;
  globalStats?: {
    totalAccounts: number;
    activeAccounts: number;
    removedAccounts: number;
    totalInspections: number;
    totalThreatsBlocked: number;
  };
};

interface AdminAccountsControlCardProps {
  selectedContextChatId?: string;
  onSelectContextChatId?: (chatId: string) => void;
  onAdminDataSynced?: (data: AdminAccountsResponse) => void;
}

export const AdminAccountsControlCard: React.FC<AdminAccountsControlCardProps> = ({
  selectedContextChatId = 'ALL',
  onSelectContextChatId,
  onAdminDataSynced,
}) => {
  const [data, setData] = useState<AdminAccountsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionBusyId, setActionBusyId] = useState<string | null>(null);
  const [sendingPanel, setSendingPanel] = useState(false);
  const [newChatId, setNewChatId] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [addingUser, setAddingUser] = useState(false);
  const [selectedUserReport, setSelectedUserReport] = useState<{
    chatId: string;
    displayName: string;
    reportText: string;
  } | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const fetchAccounts = useCallback(async (showSpinner = false) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await fetch('/api/telegram/admin/accounts');
      if (res.ok) {
        const json = (await res.json()) as AdminAccountsResponse;
        if (json.ok) {
          setData(json);
          onAdminDataSynced?.(json);
        }
      }
    } catch {
      // Non-fatal
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [onAdminDataSynced]);

  useEffect(() => {
    void fetchAccounts(true);
    const timer = setInterval(() => void fetchAccounts(false), 4000);
    return () => clearInterval(timer);
  }, [fetchAccounts]);

  const handleUserStatusAction = async (
    targetChatId: string,
    action: 'remove' | 'restore' | 'delete' | 'approve_30d' | 'renew_30d' | 'reject'
  ) => {
    setActionBusyId(`${targetChatId}:${action}`);
    setFeedback(null);

    // Instant 0ms optimistic UI update
    const previousData = data;
    if (data) {
      const now = Date.now();
      const thirtyDays = 30 * 24 * 60 * 60 * 1000;
      const nextAccounts =
        action === 'delete'
          ? data.accounts.filter((a) => a.chatId !== targetChatId)
          : data.accounts.map((a) => {
              if (a.chatId !== targetChatId) return a;
              if (action === 'approve_30d') {
                return {
                  ...a,
                  status: 'active' as const,
                  approvalStatus: 'approved' as const,
                  approvedAt: now,
                  expiresAt: now + thirtyDays,
                };
              }
              if (action === 'renew_30d') {
                const base = Math.max(now, a.expiresAt && a.expiresAt > now ? a.expiresAt : now);
                return {
                  ...a,
                  status: 'active' as const,
                  approvalStatus: 'approved' as const,
                  expiresAt: base + thirtyDays,
                };
              }
              if (action === 'reject') {
                return {
                  ...a,
                  status: 'removed' as const,
                  approvalStatus: 'rejected' as const,
                };
              }
              if (action === 'remove') {
                return {
                  ...a,
                  status: 'removed' as const,
                };
              }
              if (action === 'restore') {
                return {
                  ...a,
                  status: 'active' as const,
                };
              }
              return a;
            });
      setData({ ...data, accounts: nextAccounts });
    }

    try {
      const res = await fetch('/api/telegram/admin/user-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetChatId, action, notifyTelegram: true }),
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        setFeedback({ ok: true, text: json.message || 'Account updated.' });
        if (json.accounts && data) {
          setData((prev) => (prev ? { ...prev, accounts: json.accounts } : prev));
        } else {
          await fetchAccounts(false);
        }
      } else {
        if (previousData) setData(previousData);
        setFeedback({ ok: false, text: json.message || 'Failed to update user status.' });
      }
    } catch {
      if (previousData) setData(previousData);
      setFeedback({ ok: false, text: 'Network error while updating user.' });
    } finally {
      setActionBusyId(null);
    }
  };

  const handleViewUserReport = async (acc: ManagedTelegramAccount) => {
    setActionBusyId(`${acc.chatId}:report`);
    try {
      const res = await fetch(
        `/api/telegram/admin/user-report?chatId=${encodeURIComponent(acc.chatId)}`
      );
      const json = await res.json();
      if (res.ok && json.ok) {
        setSelectedUserReport({
          chatId: acc.chatId,
          displayName: acc.displayName,
          reportText: json.reportText,
        });
      }
    } catch {
      setFeedback({ ok: false, text: 'Could not load user report.' });
    } finally {
      setActionBusyId(null);
    }
  };

  const handleAddAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanId = newChatId.trim();
    if (!cleanId) return;
    setAddingUser(true);
    setFeedback(null);
    try {
      const res = await fetch('/api/telegram/admin/add-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chatId: cleanId,
          displayName: newDisplayName.trim() || `User ${cleanId}`,
        }),
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        setNewChatId('');
        setNewDisplayName('');
        setFeedback({ ok: true, text: json.message || `Added account ${cleanId}.` });
        await fetchAccounts();
      } else {
        setFeedback({ ok: false, text: json.message || 'Could not add user.' });
      }
    } catch {
      setFeedback({ ok: false, text: 'Network error while adding user.' });
    } finally {
      setAddingUser(false);
    }
  };

  const handleSendAdminPanelToTelegram = async () => {
    setSendingPanel(true);
    setFeedback(null);
    try {
      const res = await fetch('/api/telegram/admin/send-panel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        setFeedback({
          ok: true,
          text: json.message || 'Admin Control Panel dispatched to your Telegram!',
        });
      } else {
        setFeedback({ ok: false, text: json.message || 'Could not dispatch Admin Panel.' });
      }
    } catch {
      setFeedback({ ok: false, text: 'Network error dispatching Admin Panel.' });
    } finally {
      setSendingPanel(false);
    }
  };

  const accounts = data?.accounts || [];
  const adminChatId = data?.adminChatId || '334856454';

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-5">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-amber-600 dark:text-amber-400">
            <Crown className="w-4 h-4" />
            <span>Master Admin Control Center (Chat ID: {adminChatId})</span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
            Connected Accounts, User Removal &amp; Multi-Account Reports
          </h2>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 max-w-3xl">
            Monitor every Telegram account that connects <span className="font-mono">@mydefz_bot</span>{' '}
            (Direct Chat, Business Chat Automation, or Group Admin). You can inspect each user&apos;s
            detection report, remove/block unauthorized users, or control everything directly in
            Telegram with <span className="font-mono">/admin</span>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => void fetchAccounts(true)}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Users</span>
          </button>

          <button
            type="button"
            onClick={handleSendAdminPanelToTelegram}
            disabled={sendingPanel}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-amber-600 hover:bg-amber-500 disabled:opacity-60 text-white shadow-sm transition-colors"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{sendingPanel ? 'Sending to Telegram...' : 'Open Admin Panel in Telegram'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div
          className={`p-3.5 rounded-xl border text-xs sm:text-sm flex items-center justify-between ${
            feedback.ok
              ? 'bg-emerald-50/80 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800/60 text-emerald-800 dark:text-emerald-200'
              : 'bg-rose-50/80 dark:bg-rose-950/30 border-rose-200 dark:border-rose-800/60 text-rose-800 dark:text-rose-200'
          }`}
        >
          <span>{feedback.text}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-xs underline ml-4 opacity-75 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Summary KPI Bar */}
      {(() => {
        const pendingCount = accounts.filter(
          (a) => a.status === 'pending_approval' || a.approvalStatus === 'pending'
        ).length;
        const activeCount = accounts.filter((a) => a.status === 'active').length;
        const expiredCount = accounts.filter((a) => a.status === 'expired').length;
        const removedCount = accounts.filter((a) => a.status === 'removed').length;

        return (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200/70 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Total Added Accounts</div>
              <div className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                {accounts.length}
              </div>
            </div>
            <div className="p-4 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200/70 dark:border-emerald-900/50">
              <div className="text-xs text-emerald-700 dark:text-emerald-300">Active (30-Day Shield)</div>
              <div className="text-2xl font-bold text-emerald-700 dark:text-emerald-300 mt-1">
                {activeCount}
              </div>
            </div>
            <div
              className={`p-4 rounded-xl border ${
                pendingCount > 0
                  ? 'bg-amber-100/70 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 animate-pulse'
                  : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200/70 dark:border-slate-800'
              }`}
            >
              <div className="text-xs font-semibold text-amber-800 dark:text-amber-300 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                <span>Pending Approvals</span>
              </div>
              <div className="text-2xl font-bold text-amber-800 dark:text-amber-300 mt-1">
                {pendingCount}
              </div>
            </div>
            <div className="p-4 rounded-xl bg-rose-50/60 dark:bg-rose-950/20 border border-rose-200/70 dark:border-rose-900/50">
              <div className="text-xs text-rose-700 dark:text-rose-300">Expired / Removed</div>
              <div className="text-2xl font-bold text-rose-700 dark:text-rose-300 mt-1">
                {expiredCount + removedCount}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Dedicated Pending Approval Queue */}
      {(() => {
        const pendingAccounts = accounts.filter(
          (a) => a.status === 'pending_approval' || a.approvalStatus === 'pending'
        );
        if (pendingAccounts.length === 0) return null;

        return (
          <div className="p-4 sm:p-5 rounded-2xl bg-amber-50 dark:bg-amber-950/30 border-2 border-amber-300 dark:border-amber-800/80 space-y-3.5">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div className="flex items-center gap-2 text-amber-900 dark:text-amber-200 font-bold text-sm sm:text-base">
                <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0" />
                <span>Pending Account Approval Queue ({pendingAccounts.length} Awaiting Review)</span>
              </div>
              <span className="text-xs font-medium text-amber-800 dark:text-amber-300 bg-amber-100 dark:bg-amber-900/50 px-2.5 py-1 rounded-full">
                1 Approval = 30 Days Protection
              </span>
            </div>
            <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed">
              These users connected <span className="font-mono">@mydefz_bot</span> to Telegram Chat Automation.
              Confirm payment with the user before granting their 30-day 14-layer virus &amp; scam protection license.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              {pendingAccounts.map((p) => {
                const isBusy = actionBusyId?.startsWith(p.chatId);
                return (
                  <div
                    key={p.chatId}
                    className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-amber-200 dark:border-amber-800/60 flex flex-col justify-between gap-3 shadow-xs"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                          {p.displayName}
                        </span>
                        <span className="text-[11px] font-mono text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/50 px-2 py-0.5 rounded border border-amber-200 dark:border-amber-900">
                          ID: {p.chatId}
                        </span>
                      </div>
                      {p.username && (
                        <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                          {p.username.startsWith('@') ? p.username : `@${p.username}`}
                        </div>
                      )}
                      <div className="text-xs text-slate-600 dark:text-slate-300 mt-1.5 flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        <span>Requested: {new Date(p.requestedAt || p.addedAt).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 pt-1 border-t border-slate-100 dark:border-slate-800">
                      <button
                        type="button"
                        onClick={() => handleUserStatusAction(p.chatId, 'approve_30d')}
                        disabled={isBusy}
                        className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white shadow-xs transition-colors"
                      >
                        <Check className="w-3.5 h-3.5" />
                        <span>Approve 30 Days</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => handleUserStatusAction(p.chatId, 'reject')}
                        disabled={isBusy}
                        className="inline-flex items-center justify-center gap-1 px-3 py-2 rounded-xl text-xs font-semibold bg-rose-50 hover:bg-rose-100 dark:bg-rose-950/50 dark:hover:bg-rose-900/50 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 transition-colors"
                      >
                        <X className="w-3.5 h-3.5" />
                        <span>Reject</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Accounts Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Users className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <span>Added &amp; Connected Telegram Accounts</span>
          </h3>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            1 Approval = 30 Days · Alert sent 5 days before expiration
          </span>
        </div>

        <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-xl">
          <table className="w-full text-left border-collapse text-xs sm:text-sm">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300 border-b border-slate-200 dark:border-slate-800">
                <th className="py-3 px-4 font-semibold">Account &amp; Role</th>
                <th className="py-3 px-4 font-semibold">Chat ID (Alert Target)</th>
                <th className="py-3 px-4 font-semibold">Subscription &amp; Term</th>
                <th className="py-3 px-4 font-semibold">Activity &amp; Threats</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold text-right">Admin Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {accounts.map((acc) => {
                const isMasterAdmin = acc.role === 'admin' || acc.chatId === adminChatId;
                const isPending = acc.status === 'pending_approval' || acc.approvalStatus === 'pending';
                const isExpired = acc.status === 'expired' || (acc.expiresAt ? Date.now() > acc.expiresAt : false);
                const isRemoved = acc.status === 'removed' || acc.approvalStatus === 'rejected';

                const daysRemaining = acc.expiresAt
                  ? Math.max(0, Math.ceil((acc.expiresAt - Date.now()) / (24 * 3600 * 1000)))
                  : null;
                const expiryFormatted = acc.expiresAt
                  ? new Date(acc.expiresAt).toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                      year: 'numeric',
                    })
                  : null;

                return (
                  <tr
                    key={acc.chatId}
                    className={`${
                      isPending
                        ? 'bg-amber-50/40 dark:bg-amber-950/20'
                        : isRemoved
                        ? 'bg-rose-50/30 dark:bg-rose-950/10 opacity-75'
                        : isExpired
                        ? 'bg-orange-50/30 dark:bg-orange-950/10'
                        : 'hover:bg-slate-50/70 dark:hover:bg-slate-800/30'
                    }`}
                  >
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          {acc.displayName}
                        </span>
                        {isMasterAdmin ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300/60 dark:border-amber-800">
                            <Crown className="w-3 h-3" />
                            ADMIN
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                            USER
                          </span>
                        )}
                      </div>
                      {acc.username && (
                        <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                          {acc.username.startsWith('@') ? acc.username : `@${acc.username}`}
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-4 font-mono font-semibold text-slate-800 dark:text-slate-200">
                      {acc.chatId}
                      {acc.businessConnectionId && (
                        <div className="text-[11px] font-normal text-slate-500 dark:text-slate-400">
                          Biz ID: {acc.businessConnectionId.slice(0, 12)}...
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      {isMasterAdmin ? (
                        <span className="text-xs font-medium text-slate-600 dark:text-slate-400">
                          Permanent Access
                        </span>
                      ) : isPending ? (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-amber-700 dark:text-amber-300">
                          <Clock className="w-3.5 h-3.5" />
                          Requested 30-Day Plan
                        </span>
                      ) : isExpired ? (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-rose-600 dark:text-rose-400">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Term Ended ({expiryFormatted})
                        </span>
                      ) : daysRemaining !== null ? (
                        <div>
                          <div className="flex items-center gap-1 text-xs font-semibold text-slate-800 dark:text-slate-200">
                            <Sparkles className="w-3.5 h-3.5 text-amber-500" />
                            <span>{daysRemaining} Days Left</span>
                            {daysRemaining <= 5 && (
                              <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                                5d Alert
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400">
                            Expires: {expiryFormatted}
                          </div>
                        </div>
                      ) : (
                        <span className="text-xs text-slate-500">Standard</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="text-xs text-slate-700 dark:text-slate-300">
                        Scans: <span className="font-semibold">{acc.totalScans || 0}</span> ·
                        Blocked:{' '}
                        <span className="font-semibold text-rose-600 dark:text-rose-400">
                          {acc.threatsBlocked || 0}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400">
                        Last active:{' '}
                        {acc.lastActiveAt
                          ? new Date(acc.lastActiveAt).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })
                          : 'Recently'}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      {isPending ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300/60 dark:border-amber-800">
                          <Clock className="w-3.5 h-3.5" />
                          Pending Approval
                        </span>
                      ) : isRemoved ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          Removed / Blocked
                        </span>
                      ) : isExpired ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-orange-100 dark:bg-orange-950/60 text-orange-800 dark:text-orange-300">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Expired (Unprotected)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Active
                        </span>
                      )}
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <div className="inline-flex items-center justify-end gap-1.5 flex-wrap">
                        {onSelectContextChatId && (
                          <button
                            type="button"
                            onClick={() => onSelectContextChatId(acc.chatId)}
                            className={`inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                              selectedContextChatId === acc.chatId
                                ? 'bg-sky-600 text-white shadow-xs'
                                : 'bg-sky-50 hover:bg-sky-100 dark:bg-sky-950/60 dark:hover:bg-sky-900/60 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800'
                            }`}
                          >
                            <span>
                              {selectedContextChatId === acc.chatId ? '✓ Context' : 'Context'}
                            </span>
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() => handleViewUserReport(acc)}
                          disabled={actionBusyId === `${acc.chatId}:report`}
                          className="inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 transition-colors"
                        >
                          <FileWarning className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
                          <span>Report</span>
                        </button>

                        {!isMasterAdmin && (
                          <>
                            {isPending ? (
                              <>
                                <button
                                  type="button"
                                  onClick={() => handleUserStatusAction(acc.chatId, 'approve_30d')}
                                  disabled={actionBusyId?.startsWith(acc.chatId)}
                                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
                                >
                                  <Check className="w-3.5 h-3.5" />
                                  <span>Approve 30d</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleUserStatusAction(acc.chatId, 'reject')}
                                  disabled={actionBusyId?.startsWith(acc.chatId)}
                                  className="inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-semibold bg-rose-50 hover:bg-rose-100 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-800 transition-colors"
                                >
                                  <X className="w-3.5 h-3.5" />
                                  <span>Reject</span>
                                </button>
                              </>
                            ) : isRemoved ? (
                              <button
                                type="button"
                                onClick={() => handleUserStatusAction(acc.chatId, 'restore')}
                                disabled={actionBusyId === `${acc.chatId}:restore`}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
                              >
                                <UserCheck className="w-3.5 h-3.5" />
                                <span>Restore</span>
                              </button>
                            ) : isExpired ? (
                              <>
                                <button
                                  type="button"
                                  onClick={() => handleUserStatusAction(acc.chatId, 'renew_30d')}
                                  disabled={actionBusyId?.startsWith(acc.chatId)}
                                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
                                >
                                  <Sparkles className="w-3.5 h-3.5" />
                                  <span>Renew 30d</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleUserStatusAction(acc.chatId, 'remove')}
                                  disabled={actionBusyId === `${acc.chatId}:remove`}
                                  className="inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors"
                                >
                                  <UserMinus className="w-3.5 h-3.5" />
                                  <span>Remove</span>
                                </button>
                              </>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  onClick={() => handleUserStatusAction(acc.chatId, 'renew_30d')}
                                  disabled={actionBusyId?.startsWith(acc.chatId)}
                                  title="Extend protection by 30 days"
                                  className="inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-semibold bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-950/60 dark:hover:bg-emerald-900/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 transition-colors"
                                >
                                  <Plus className="w-3.5 h-3.5" />
                                  <span>+30d</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleUserStatusAction(acc.chatId, 'remove')}
                                  disabled={actionBusyId === `${acc.chatId}:remove`}
                                  className="inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors"
                                >
                                  <UserMinus className="w-3.5 h-3.5" />
                                  <span>Remove</span>
                                </button>
                              </>
                            )}

                            <button
                              type="button"
                              onClick={() => handleUserStatusAction(acc.chatId, 'delete')}
                              disabled={actionBusyId === `${acc.chatId}:delete`}
                              title="Delete account record"
                              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected User Inspection Report Modal / Drawer */}
      {selectedUserReport && (
        <div className="p-4 sm:p-5 rounded-xl bg-slate-900 text-slate-100 border border-slate-700 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2 text-xs sm:text-sm font-semibold text-amber-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>
                Admin Security Report for {selectedUserReport.displayName} (Chat ID:{' '}
                {selectedUserReport.chatId})
              </span>
            </div>
            <button
              type="button"
              onClick={() => setSelectedUserReport(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Close Report ✕
            </button>
          </div>
          <pre className="text-xs font-mono whitespace-pre-wrap leading-relaxed text-slate-200 max-h-72 overflow-y-auto">
            {selectedUserReport.reportText}
          </pre>
        </div>
      )}

      {/* Pre-Authorize / Add Account Form */}
      <form
        onSubmit={handleAddAccount}
        className="pt-3 border-t border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-end gap-3"
      >
        <div className="flex-1">
          <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
            Add / Authorize Telegram Account by Chat ID
          </label>
          <input
            type="text"
            value={newChatId}
            onChange={(e) => setNewChatId(e.target.value)}
            placeholder="e.g. 6364419031"
            className="w-full px-3.5 py-2 rounded-xl text-xs sm:text-sm bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 font-mono"
          />
        </div>
        <div className="flex-1">
          <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
            Account Name / Label
          </label>
          <input
            type="text"
            value={newDisplayName}
            onChange={(e) => setNewDisplayName(e.target.value)}
            placeholder="e.g. Second Phone / Staff Account"
            className="w-full px-3.5 py-2 rounded-xl text-xs sm:text-sm bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100"
          />
        </div>
        <button
          type="submit"
          disabled={addingUser || !newChatId.trim()}
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>{addingUser ? 'Adding...' : 'Add Account'}</span>
        </button>
      </form>
    </section>
  );
};
