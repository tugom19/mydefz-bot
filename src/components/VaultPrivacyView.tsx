import React, { useState } from 'react';
import { KeyRound, Lock, RefreshCw, ShieldCheck, Trash2, Upload } from 'lucide-react';
import type { EncryptedEnvelope } from '../types/security';
import type { VaultStateSummary } from '../services/cryptoVault';

interface VaultPrivacyViewProps {
  vaultSummary: VaultStateSummary;
  rawEnvelopes: EncryptedEnvelope[];
  onSetPassphrase: (passphrase: string) => Promise<void>;
  onRemovePassphrase: () => Promise<void>;
  onLockVault: () => void;
  onRotateKey: () => Promise<void>;
  onExportBundleWithPassphrase: (passphrase: string) => Promise<void>;
  onImportBundleWithPassphrase: (jsonText: string, passphrase: string) => Promise<number>;
  onWipeResetVault: () => Promise<void>;
}

export const VaultPrivacyView: React.FC<VaultPrivacyViewProps> = ({
  vaultSummary,
  rawEnvelopes,
  onSetPassphrase,
  onRemovePassphrase,
  onLockVault,
  onRotateKey,
  onExportBundleWithPassphrase,
  onImportBundleWithPassphrase,
  onWipeResetVault,
}) => {
  const [passphraseInput, setPassphraseInput] = useState('');
  const [bundlePassphrase, setBundlePassphrase] = useState('');
  const [importJsonText, setImportJsonText] = useState('');
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmWipe, setConfirmWipe] = useState(false);

  const handleEnablePassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFeedback(null);
    try {
      await onSetPassphrase(passphraseInput);
      setPassphraseInput('');
      setFeedback({
        ok: true,
        text: 'Master AES-256-GCM key wrapped with PBKDF2-HMAC-SHA256 (120,000 iterations). You can now lock the vault at any time.',
      });
    } catch (err) {
      setFeedback({
        ok: false,
        text: err instanceof Error ? err.message : 'Could not set passphrase.',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleKeyRotation = async () => {
    setBusy(true);
    setFeedback(null);
    try {
      await onRotateKey();
      setFeedback({
        ok: true,
        text: 'Generated fresh 256-bit AES-GCM key and re-encrypted all threat records, Bot credentials, and custom ML samples.',
      });
    } catch (err) {
      setFeedback({
        ok: false,
        text: err instanceof Error ? err.message : 'Key rotation failed.',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleExportBundle = async () => {
    setBusy(true);
    setFeedback(null);
    try {
      await onExportBundleWithPassphrase(bundlePassphrase);
      setFeedback({
        ok: true,
        text: 'Downloaded PBKDF2 + AES-256-GCM encrypted portable backup (.tgs-vault.json).',
      });
    } catch (err) {
      setFeedback({
        ok: false,
        text: err instanceof Error ? err.message : 'Encrypted export failed.',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleImportBundle = async () => {
    setBusy(true);
    setFeedback(null);
    try {
      const count = await onImportBundleWithPassphrase(importJsonText, bundlePassphrase);
      setImportJsonText('');
      setFeedback({
        ok: true,
        text: `Authenticated and decrypted ${count} threat event records into your local vault.`,
      });
    } catch (err) {
      setFeedback({
        ok: false,
        text: err instanceof Error ? err.message : 'Bundle decryption failed.',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <section className="space-y-2 max-w-3xl">
        <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-400">
          <Lock className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
          <span>Web Crypto API SubtleCrypto</span>
          <span aria-hidden="true">·</span>
          <span>AES-256-GCM + ECDH P-256</span>
          <span aria-hidden="true">·</span>
          <span>PBKDF2 120k Key Wrapping</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-50 [text-wrap:balance]">
          End-to-End Encryption &amp; Data Privacy Vault
        </h1>
        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
          All intercepted Telegram message previews, Bot API credentials, and custom ML training
          samples are encrypted locally with authenticated AES-256-GCM before storage. Keys never
          leave your device.
        </p>
      </section>

      {feedback && (
        <div
          role="status"
          className={`p-4 rounded-2xl border text-sm font-medium ${
            feedback.ok
              ? 'bg-emerald-50/80 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/70 text-emerald-900 dark:text-emerald-200'
              : 'bg-red-50/80 dark:bg-red-950/40 border-red-200 dark:border-red-800/70 text-red-900 dark:text-red-200'
          }`}
        >
          {feedback.text}
        </div>
      )}

      {/* Cryptographic Identity Strip */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-200 dark:divide-slate-800">
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            AES-256-GCM Master Key Fingerprint
          </p>
          <p className="text-xs sm:text-sm font-mono font-semibold text-slate-900 dark:text-slate-100 break-all">
            {vaultSummary.aesKeyFingerprint}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            96-bit CSPRNG IV per encrypted record
          </p>
        </div>
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            ECDH P-256 Public Identity Fingerprint
          </p>
          <p className="text-xs sm:text-sm font-mono font-semibold text-slate-900 dark:text-slate-100 break-all">
            {vaultSummary.ecdhPublicKeyFingerprint}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Elliptic-curve audit key identity
          </p>
        </div>
        <div className="p-5 space-y-1">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Sealed Vault Envelopes
          </p>
          <p className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {vaultSummary.encryptedRecordCount}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {vaultSummary.passphraseProtected
              ? 'Protected by PBKDF2 passphrase'
              : 'Auto-unlocked device key'}
          </p>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Passphrase Wrapping & Key Rotation */}
        <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-6">
          <form onSubmit={handleEnablePassphrase} className="space-y-4">
            <div className="space-y-1">
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                Passphrase Key Wrapping &amp; Vault Lock
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Wrap your 256-bit vault key with a PBKDF2-SHA256 passphrase so zero unencrypted key
                material persists when you lock the session.
              </p>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="vault-passphrase"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300"
              >
                {vaultSummary.passphraseProtected
                  ? 'Update Master Vault Passphrase'
                  : 'Set Master Vault Passphrase (min 6 chars)'}
              </label>
              <input
                id="vault-passphrase"
                type="password"
                value={passphraseInput}
                onChange={(e) => setPassphraseInput(e.target.value)}
                placeholder="Enter strong vault passphrase..."
                className="w-full min-h-[44px] px-3.5 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
              />
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="submit"
                disabled={busy || passphraseInput.trim().length < 6}
                className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 disabled:opacity-50"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Wrap Key with Passphrase</span>
              </button>

              {vaultSummary.passphraseProtected && (
                <>
                  <button
                    type="button"
                    onClick={onLockVault}
                    className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:opacity-90 transition-opacity whitespace-nowrap shrink-0"
                  >
                    Lock Vault Now
                  </button>
                  <button
                    type="button"
                    onClick={onRemovePassphrase}
                    className="min-h-[44px] px-3.5 py-2 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Remove Passphrase
                  </button>
                </>
              )}
            </div>
          </form>

          <div className="pt-5 border-t border-slate-100 dark:border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Cryptographic Hygiene &amp; Emergency Wipe
            </h3>
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                disabled={busy}
                onClick={handleKeyRotation}
                className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Rotate AES-256 Master Key</span>
              </button>

              {!confirmWipe ? (
                <button
                  type="button"
                  onClick={() => setConfirmWipe(true)}
                  className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Reset &amp; Wipe Local Vault</span>
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      await onWipeResetVault();
                      setConfirmWipe(false);
                      setFeedback({
                        ok: true,
                        text: 'Wiped previous keys and provisioned a clean encrypted vault.',
                      });
                    }}
                    className="min-h-[40px] px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-red-600 text-white hover:bg-red-700 transition-colors whitespace-nowrap"
                  >
                    Confirm Wipe
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmWipe(false)}
                    className="min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400"
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Portable Encrypted Bundle Exchange & Raw Ciphertext Verification */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="space-y-1">
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
                Portable E2EE Threat Bundle Export &amp; Restore
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Share or back up encrypted threat logs across Android and desktop devices using a
                dedicated bundle passphrase.
              </p>
            </div>

            <input
              type="password"
              value={bundlePassphrase}
              onChange={(e) => setBundlePassphrase(e.target.value)}
              placeholder="Bundle encryption passphrase (min 6 chars)..."
              aria-label="Portable bundle passphrase"
              className="w-full min-h-[44px] px-3.5 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-slate-100"
            />

            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                disabled={busy || bundlePassphrase.trim().length < 6}
                onClick={handleExportBundle}
                className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:opacity-90 transition-opacity flex items-center gap-2 whitespace-nowrap shrink-0 disabled:opacity-50"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Download Encrypted Bundle</span>
              </button>

              <label className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-2 cursor-pointer whitespace-nowrap shrink-0">
                <Upload className="w-3.5 h-3.5" />
                <span>Load .json Bundle File</span>
                <input
                  type="file"
                  accept=".json,application/json"
                  className="hidden"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      const text = await file.text();
                      setImportJsonText(text);
                    }
                  }}
                />
              </label>
            </div>

            {importJsonText && (
              <div className="space-y-2 pt-2">
                <p className="text-xs text-slate-600 dark:text-slate-400 font-mono">
                  Loaded encrypted bundle ({importJsonText.length} bytes). Enter passphrase above
                  and click Decrypt &amp; Restore.
                </p>
                <button
                  type="button"
                  disabled={busy || bundlePassphrase.trim().length < 6}
                  onClick={handleImportBundle}
                  className="min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-sky-600 text-white hover:bg-sky-700 transition-colors disabled:opacity-50"
                >
                  Decrypt &amp; Restore Bundle
                </button>
              </div>
            )}
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              At-Rest Storage Verification (Latest Encrypted Record)
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Raw JSON persisted inside browser storage proving zero plaintext chat exposure:
            </p>
            <pre className="p-3.5 rounded-xl bg-slate-950 text-slate-200 text-[11px] font-mono overflow-x-auto leading-relaxed">
              {rawEnvelopes[0]
                ? JSON.stringify(
                    {
                      version: rawEnvelopes[0].version,
                      algorithm: rawEnvelopes[0].algorithm,
                      keyFingerprint: rawEnvelopes[0].keyFingerprint,
                      ivBase64: rawEnvelopes[0].ivBase64,
                      ciphertextSample: `${rawEnvelopes[0].ciphertextBase64.slice(0, 84)}...`,
                    },
                    null,
                    2
                  )
                : '{\n  "status": "empty_vault"\n}'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
