import type { EncryptedEnvelope } from '../types/security';

const VAULT_RAW_KEY_STORAGE = 'sentinelgram_e2ee_raw_key_v1';
const VAULT_WRAPPED_KEY_STORAGE = 'sentinelgram_e2ee_wrapped_key_v1';
const VAULT_ECDH_PUB_STORAGE = 'sentinelgram_ecdh_pub_v1';
const VAULT_RECORDS_STORAGE = 'sentinelgram_encrypted_records_v1';
const VAULT_CONFIG_STORAGE = 'sentinelgram_encrypted_config_v1';
const VAULT_CUSTOM_SAMPLES_STORAGE = 'sentinelgram_encrypted_samples_v1';

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function sha256HexFromBuffer(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256HexFromString(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  return sha256HexFromBuffer(encoded.buffer as ArrayBuffer);
}

export interface VaultStateSummary {
  initialized: boolean;
  locked: boolean;
  passphraseProtected: boolean;
  aesKeyFingerprint: string;
  ecdhPublicKeyFingerprint: string;
  encryptedRecordCount: number;
}

class E2eeCryptoVault {
  private activeKey: CryptoKey | null = null;
  private keyFingerprint = '';
  private ecdhFingerprint = '';

  async initialize(): Promise<VaultStateSummary> {
    await this.ensureEcdhIdentity();

    const wrappedMeta = localStorage.getItem(VAULT_WRAPPED_KEY_STORAGE);
    if (wrappedMeta) {
      // Vault is protected by user passphrase; remains locked until unlocked
      const parsed = JSON.parse(wrappedMeta) as { fingerprint: string };
      this.keyFingerprint = parsed.fingerprint || 'LOCKED-KEY';
      return this.getSummary();
    }

    const storedRawBase64 = localStorage.getItem(VAULT_RAW_KEY_STORAGE);
    if (storedRawBase64) {
      const rawBytes = base64ToBytes(storedRawBase64);
      this.activeKey = await crypto.subtle.importKey(
        'raw',
        rawBytes.buffer as ArrayBuffer,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      this.keyFingerprint = (await sha256HexFromBuffer(rawBytes.buffer as ArrayBuffer))
        .slice(0, 32)
        .toUpperCase();
    } else {
      await this.provisionFreshMasterKey();
    }

    return this.getSummary();
  }

  private async ensureEcdhIdentity(): Promise<void> {
    const existingPub = localStorage.getItem(VAULT_ECDH_PUB_STORAGE);
    if (existingPub) {
      this.ecdhFingerprint = (await sha256HexFromString(existingPub)).slice(0, 32).toUpperCase();
      return;
    }
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const exportedSpki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const pubBase64 = bytesToBase64(new Uint8Array(exportedSpki));
    localStorage.setItem(VAULT_ECDH_PUB_STORAGE, pubBase64);
    this.ecdhFingerprint = (await sha256HexFromString(pubBase64)).slice(0, 32).toUpperCase();
  }

  private async provisionFreshMasterKey(): Promise<void> {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const exported = await crypto.subtle.exportKey('raw', key);
    const rawBytes = new Uint8Array(exported);
    localStorage.setItem(VAULT_RAW_KEY_STORAGE, bytesToBase64(rawBytes));
    localStorage.removeItem(VAULT_WRAPPED_KEY_STORAGE);
    this.activeKey = key;
    this.keyFingerprint = (await sha256HexFromBuffer(exported)).slice(0, 32).toUpperCase();
  }

  isUnlocked(): boolean {
    return this.activeKey !== null;
  }

  isPassphraseProtected(): boolean {
    return Boolean(localStorage.getItem(VAULT_WRAPPED_KEY_STORAGE));
  }

  getSummary(): VaultStateSummary {
    const rawEnvelopes = this.readRawEnvelopes(VAULT_RECORDS_STORAGE);
    return {
      initialized: true,
      locked: this.activeKey === null,
      passphraseProtected: this.isPassphraseProtected(),
      aesKeyFingerprint: this.keyFingerprint,
      ecdhPublicKeyFingerprint: this.ecdhFingerprint,
      encryptedRecordCount: rawEnvelopes.length,
    };
  }

  private async deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt.buffer as ArrayBuffer,
        iterations: 120000,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async enablePassphraseProtection(passphrase: string): Promise<VaultStateSummary> {
    if (!this.activeKey) {
      throw new Error('Unlock the vault before setting a passphrase.');
    }
    if (passphrase.trim().length < 6) {
      throw new Error('Passphrase must be at least 6 characters.');
    }
    const rawKeyBuf = await crypto.subtle.exportKey('raw', this.activeKey);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrappingKey = await this.deriveWrappingKey(passphrase, salt);
    const wrappedCipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      wrappingKey,
      rawKeyBuf
    );

    localStorage.setItem(
      VAULT_WRAPPED_KEY_STORAGE,
      JSON.stringify({
        saltBase64: bytesToBase64(salt),
        ivBase64: bytesToBase64(iv),
        wrappedKeyBase64: bytesToBase64(new Uint8Array(wrappedCipher)),
        fingerprint: this.keyFingerprint,
      })
    );
    localStorage.removeItem(VAULT_RAW_KEY_STORAGE);
    return this.getSummary();
  }

  async removePassphraseProtection(): Promise<VaultStateSummary> {
    if (!this.activeKey) {
      throw new Error('Vault must be unlocked first.');
    }
    const exported = await crypto.subtle.exportKey('raw', this.activeKey);
    localStorage.setItem(VAULT_RAW_KEY_STORAGE, bytesToBase64(new Uint8Array(exported)));
    localStorage.removeItem(VAULT_WRAPPED_KEY_STORAGE);
    return this.getSummary();
  }

  lockVault(): VaultStateSummary {
    if (!this.isPassphraseProtected()) {
      throw new Error('Set a vault passphrase first so you can unlock the vault again.');
    }
    this.activeKey = null;
    return this.getSummary();
  }

  async unlockWithPassphrase(passphrase: string): Promise<VaultStateSummary> {
    const wrappedMeta = localStorage.getItem(VAULT_WRAPPED_KEY_STORAGE);
    if (!wrappedMeta) {
      return this.getSummary();
    }
    const parsed = JSON.parse(wrappedMeta) as {
      saltBase64: string;
      ivBase64: string;
      wrappedKeyBase64: string;
      fingerprint: string;
    };
    const salt = base64ToBytes(parsed.saltBase64);
    const iv = base64ToBytes(parsed.ivBase64);
    const wrappedBytes = base64ToBytes(parsed.wrappedKeyBase64);
    const wrappingKey = await this.deriveWrappingKey(passphrase, salt);

    try {
      const unwrappedRaw = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
        wrappingKey,
        wrappedBytes.buffer as ArrayBuffer
      );
      this.activeKey = await crypto.subtle.importKey(
        'raw',
        unwrappedRaw,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      this.keyFingerprint = parsed.fingerprint;
      return this.getSummary();
    } catch {
      throw new Error('Incorrect passphrase. AES-256-GCM authentication tag verification failed.');
    }
  }

  async encryptPayload<T>(payload: T): Promise<EncryptedEnvelope> {
    if (!this.activeKey) {
      throw new Error('E2EE Vault is currently locked.');
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(payload));
    const cipherBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      this.activeKey,
      plaintextBytes
    );
    return {
      version: 1,
      algorithm: 'AES-256-GCM',
      ivBase64: bytesToBase64(iv),
      ciphertextBase64: bytesToBase64(new Uint8Array(cipherBuf)),
      keyFingerprint: this.keyFingerprint,
      encryptedAt: Date.now(),
    };
  }

  async decryptEnvelope<T>(envelope: EncryptedEnvelope): Promise<T> {
    if (!this.activeKey) {
      throw new Error('E2EE Vault is locked.');
    }
    const iv = base64ToBytes(envelope.ivBase64);
    const cipherBytes = base64ToBytes(envelope.ciphertextBase64);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      this.activeKey,
      cipherBytes.buffer as ArrayBuffer
    );
    const text = new TextDecoder().decode(plainBuf);
    return JSON.parse(text) as T;
  }

  readRawEnvelopes(storageKey = VAULT_RECORDS_STORAGE): EncryptedEnvelope[] {
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  async saveEncryptedList<T>(items: T[], storageKey = VAULT_RECORDS_STORAGE): Promise<EncryptedEnvelope[]> {
    const envelopes: EncryptedEnvelope[] = [];
    for (const item of items) {
      envelopes.push(await this.encryptPayload(item));
    }
    localStorage.setItem(storageKey, JSON.stringify(envelopes));
    return envelopes;
  }

  async loadEncryptedList<T>(storageKey = VAULT_RECORDS_STORAGE): Promise<T[]> {
    const envelopes = this.readRawEnvelopes(storageKey);
    const results: T[] = [];
    for (const env of envelopes) {
      try {
        results.push(await this.decryptEnvelope<T>(env));
      } catch {
        // Skip corrupted or mismatched key records gracefully
      }
    }
    return results;
  }

  async saveEncryptedConfig<T>(config: T): Promise<EncryptedEnvelope> {
    const env = await this.encryptPayload(config);
    localStorage.setItem(VAULT_CONFIG_STORAGE, JSON.stringify(env));
    return env;
  }

  async loadEncryptedConfig<T>(): Promise<T | null> {
    try {
      const raw = localStorage.getItem(VAULT_CONFIG_STORAGE);
      if (!raw) return null;
      const env = JSON.parse(raw) as EncryptedEnvelope;
      return await this.decryptEnvelope<T>(env);
    } catch {
      return null;
    }
  }

  async saveCustomSamples<T>(samples: T[]): Promise<void> {
    await this.saveEncryptedList(samples, VAULT_CUSTOM_SAMPLES_STORAGE);
  }

  async loadCustomSamples<T>(): Promise<T[]> {
    return this.loadEncryptedList<T>(VAULT_CUSTOM_SAMPLES_STORAGE);
  }

  async rotateMasterKey<TEvent, TConfig, TSample>(
    events: TEvent[],
    config: TConfig,
    samples: TSample[]
  ): Promise<VaultStateSummary> {
    if (!this.activeKey) {
      throw new Error('Unlock the vault before rotating encryption keys.');
    }
    await this.provisionFreshMasterKey();
    await this.saveEncryptedList(events, VAULT_RECORDS_STORAGE);
    await this.saveEncryptedConfig(config);
    await this.saveCustomSamples(samples);
    return this.getSummary();
  }

  async exportPortableEncryptedBundle<T>(payload: T, exportPassphrase: string): Promise<string> {
    if (exportPassphrase.trim().length < 6) {
      throw new Error('Bundle passphrase must be at least 6 characters.');
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveWrappingKey(exportPassphrase, salt);
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const cipherBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      key,
      plaintext
    );
    return JSON.stringify(
      {
        schema: 'sentinelgram-e2ee-bundle-v1',
        kdf: 'PBKDF2-HMAC-SHA256-120000',
        cipher: 'AES-256-GCM',
        saltBase64: bytesToBase64(salt),
        ivBase64: bytesToBase64(iv),
        ciphertextBase64: bytesToBase64(new Uint8Array(cipherBuf)),
        exportedAt: new Date().toISOString(),
      },
      null,
      2
    );
  }

  async importPortableEncryptedBundle<T>(bundleJson: string, exportPassphrase: string): Promise<T> {
    const parsed = JSON.parse(bundleJson) as {
      schema?: string;
      saltBase64?: string;
      ivBase64?: string;
      ciphertextBase64?: string;
    };
    if (
      parsed.schema !== 'sentinelgram-e2ee-bundle-v1' ||
      !parsed.saltBase64 ||
      !parsed.ivBase64 ||
      !parsed.ciphertextBase64
    ) {
      throw new Error('Invalid SentinelGram E2EE bundle format.');
    }
    const salt = base64ToBytes(parsed.saltBase64);
    const iv = base64ToBytes(parsed.ivBase64);
    const cipher = base64ToBytes(parsed.ciphertextBase64);
    const key = await this.deriveWrappingKey(exportPassphrase, salt);
    try {
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
        key,
        cipher.buffer as ArrayBuffer
      );
      return JSON.parse(new TextDecoder().decode(plainBuf)) as T;
    } catch {
      throw new Error('Decryption failed: incorrect bundle passphrase or tampered ciphertext.');
    }
  }

  wipeAllVaultStorage(): void {
    localStorage.removeItem(VAULT_RAW_KEY_STORAGE);
    localStorage.removeItem(VAULT_WRAPPED_KEY_STORAGE);
    localStorage.removeItem(VAULT_ECDH_PUB_STORAGE);
    localStorage.removeItem(VAULT_RECORDS_STORAGE);
    localStorage.removeItem(VAULT_CONFIG_STORAGE);
    localStorage.removeItem(VAULT_CUSTOM_SAMPLES_STORAGE);
    this.activeKey = null;
  }
}

export const cryptoVault = new E2eeCryptoVault();
