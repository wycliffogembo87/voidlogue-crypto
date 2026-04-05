/**
 * vault.ts — Voidlogue Conversation Vault
 *
 * PIN-based local encryption for saved conversations.
 * The PIN never leaves the device. Email + codename are
 * encrypted with AES-256-GCM keyed by PBKDF2(PIN, salt).
 *
 * Labels are ALWAYS encrypted — never stored in plaintext.
 * Labels are encrypted with the PIN-derived key.
 *
 * Storage keys in localStorage:
 *   voidlogue_conv_{roomHash}  — encrypted blob
 *   voidlogue_convlist         — plaintext index (hashes + encrypted labels)
 */

const ENC = new TextEncoder();
const DEC = new TextDecoder();
const PBKDF2_ITER = 2_000_000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

type LabelEntry = {
  encrypted: string;
  iv: string;
  salt?: string;
  hint?: string;
};
type ConvListEntry = { roomHash: string; hint: LabelEntry; savedAt: number };
type VaultBlob = {
  salt: string;
  iv: string;
  data: string;
  attempts: number;
  lockedUntil: number | null;
  codenameSalt?: string;
  codenameIv?: string;
  codenameData?: string;
};

function randomB64(bytes: number): string {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = '';
  for (let i = 0; i < array.length; i++) {
    binary += String.fromCharCode(array[i]!);
  }
  return btoa(binary);
}

async function deriveKey(pin: string, saltB64: string): Promise<CryptoKey> {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const km = await crypto.subtle.importKey(
    'raw',
    ENC.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveLabelKey(
  passphrase: string,
  saltB64: string
): Promise<CryptoKey> {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const km = await crypto.subtle.importKey(
    'raw',
    ENC.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptLabel(
  label: string,
  keyOrPassphrase: CryptoKey | string
): Promise<LabelEntry> {
  if (!label) return { encrypted: '', iv: '', hint: '(no label)' };
  let key: CryptoKey;
  let salt: string | undefined;
  if (typeof keyOrPassphrase === 'string') {
    salt = randomB64(16);
    key = await deriveLabelKey(keyOrPassphrase, salt);
  } else {
    key = keyOrPassphrase;
  }
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const iv = btoa(String.fromCharCode(...ivBytes));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes },
    key,
    ENC.encode(label)
  );
  const data = btoa(String.fromCharCode(...new Uint8Array(ct)));
  return salt ? { encrypted: data, iv, salt } : { encrypted: data, iv };
}

async function decryptLabel(
  entry: LabelEntry,
  keyOrPassphrase: CryptoKey | string
): Promise<string> {
  if (!entry || !entry.encrypted) return '';
  let key: CryptoKey;
  if (typeof keyOrPassphrase === 'string') {
    if (!entry.salt) throw new Error('missing_salt');
    key = await deriveLabelKey(keyOrPassphrase, entry.salt);
  } else {
    key = keyOrPassphrase;
  }
  const iv = Uint8Array.from(atob(entry.iv), (c) => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(entry.encrypted), (c) => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return DEC.decode(pt);
}

export const LabelCipher = {
  encrypt: encryptLabel,
  decrypt: decryptLabel,
  deriveKey: deriveLabelKey,
};

export const Vault = {
  async save(
    roomHash: string,
    email: string,
    codename: string,
    pin: string,
    hint: string = ''
  ): Promise<boolean> {
    const salt = randomB64(16);
    const ivBytes = crypto.getRandomValues(new Uint8Array(12));
    const iv = btoa(String.fromCharCode(...ivBytes));
    const key = await deriveKey(pin, salt);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ivBytes },
      key,
      ENC.encode(JSON.stringify({ email, codename }))
    );
    const blob: VaultBlob = {
      salt,
      iv,
      data: btoa(String.fromCharCode(...new Uint8Array(ct))),
      attempts: 0,
      lockedUntil: null,
    };

    const codenameSalt = randomB64(16);
    const codenameIvBytes = crypto.getRandomValues(new Uint8Array(12));
    const codenameIv = btoa(String.fromCharCode(...codenameIvBytes));
    const codenameKey = await deriveKey(codename, codenameSalt);
    const codenameCt = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: codenameIvBytes },
      codenameKey,
      ENC.encode(JSON.stringify({ email }))
    );
    blob.codenameSalt = codenameSalt;
    blob.codenameIv = codenameIv;
    blob.codenameData = btoa(
      String.fromCharCode(...new Uint8Array(codenameCt))
    );

    localStorage.setItem(`voidlogue_conv_${roomHash}`, JSON.stringify(blob));

    // Only add labelled conversations to the index.
    // Ghost (unlabelled) convos are stored in localStorage under their key
    // but must NOT appear in the convlist so they stay hidden from the UI.
    if (hint.trim()) {
      const labelEntry = await encryptLabel(hint, key);
      await this._updateIndex(roomHash, labelEntry);
    }
    return true;
  },

  async verifyCodename(
    roomHash: string,
    codename: string
  ): Promise<{ email: string }> {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) throw new Error('not_found');
    const blob = JSON.parse(raw) as VaultBlob;
    if (!blob.codenameSalt || !blob.codenameIv || !blob.codenameData) {
      throw new Error('no_codename_blob');
    }
    const iv = Uint8Array.from(atob(blob.codenameIv), (c) => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(blob.codenameData), (c) => c.charCodeAt(0));
    const key = await deriveKey(codename, blob.codenameSalt);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    const { email } = JSON.parse(DEC.decode(pt));
    return { email };
  },

  async load(
    roomHash: string,
    pin: string
  ): Promise<
    | { email: string; codename: string; hint: string }
    | { error: string; minutesRemaining?: number; attemptsLeft?: number }
  > {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) return { error: 'not_found' };
    const blob = JSON.parse(raw) as VaultBlob;

    if (blob.lockedUntil && Date.now() < blob.lockedUntil) {
      const mins = Math.ceil((blob.lockedUntil - Date.now()) / 60000);
      return { error: 'locked', minutesRemaining: mins };
    }

    try {
      const key = await deriveKey(pin, blob.salt);
      const iv = Uint8Array.from(atob(blob.iv), (c) => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(blob.data), (c) => c.charCodeAt(0));
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      const { email, codename } = JSON.parse(DEC.decode(pt));
      blob.attempts = 0;
      blob.lockedUntil = null;
      localStorage.setItem(`voidlogue_conv_${roomHash}`, JSON.stringify(blob));

      let hint = '';
      try {
        const entry = this._getEncryptedHint(roomHash);
        hint = entry ? await decryptLabel(entry, key) : '';
      } catch (_) {
        /* hint decrypt failed, continue without it */
      }

      return { email, codename, hint };
    } catch {
      blob.attempts = (blob.attempts || 0) + 1;
      if (blob.attempts >= MAX_ATTEMPTS) {
        blob.lockedUntil = Date.now() + LOCKOUT_MS;
        blob.attempts = 0;
        localStorage.setItem(
          `voidlogue_conv_${roomHash}`,
          JSON.stringify(blob)
        );
        return { error: 'locked', minutesRemaining: 15 };
      }
      const attemptsLeft = MAX_ATTEMPTS - blob.attempts;
      localStorage.setItem(`voidlogue_conv_${roomHash}`, JSON.stringify(blob));
      return { error: 'wrong_pin', attemptsLeft };
    }
  },

  async resetPin(
    roomHash: string,
    email: string,
    codename: string,
    newPin: string,
    existingHintEntry?: LabelEntry
  ): Promise<boolean> {
    // Save as ghost (no hint) — avoids re-encrypting the label under the new
    // PIN key, which would create a new index entry and make ghosts visible.
    const ok = await this.save(roomHash, email, codename, newPin, '');
    // If the caller supplies the original encrypted label entry, restore it
    // verbatim — no re-encryption needed since labels are keyed independently.
    if (ok && existingHintEntry?.encrypted) {
      await this._updateIndex(roomHash, existingHintEntry);
    }
    return ok;
  },

  async updateLabel(
    roomHash: string,
    newHint: string,
    keyOrPassphrase: CryptoKey | string
  ): Promise<void> {
    const entry = await encryptLabel(newHint, keyOrPassphrase);
    await this._updateIndex(roomHash, entry);
  },

  delete(roomHash: string): void {
    localStorage.removeItem(`voidlogue_conv_${roomHash}`);
    const list = this.list().filter((c) => c.roomHash !== roomHash);
    localStorage.setItem('voidlogue_convlist', JSON.stringify(list));
  },

  list(): ConvListEntry[] {
    try {
      return JSON.parse(localStorage.getItem('voidlogue_convlist') || '[]');
    } catch {
      return [];
    }
  },

  has(roomHash: string): boolean {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) return false;
    try {
      const blob = JSON.parse(raw) as VaultBlob;
      return !!blob.salt && !!blob.data;
    } catch {
      return false;
    }
  },

  hasAny(roomHash: string): boolean {
    if (this.has(roomHash)) return true;
    return this.list().some((c) => c.roomHash === roomHash);
  },

  lockoutStatus(roomHash: string): {
    locked: boolean;
    minutesRemaining?: number;
    attemptsUsed?: number;
  } | null {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) return null;
    const blob = JSON.parse(raw) as VaultBlob;
    if (blob.lockedUntil && Date.now() < blob.lockedUntil) {
      return {
        locked: true,
        minutesRemaining: Math.ceil((blob.lockedUntil - Date.now()) / 60000),
      };
    }
    return { locked: false, attemptsUsed: blob.attempts || 0 };
  },

  wipeAll(): void {
    const list = this.list();
    list.forEach((c) =>
      localStorage.removeItem(`voidlogue_conv_${c.roomHash}`)
    );
    localStorage.removeItem('voidlogue_convlist');
  },

  _getEncryptedHint(roomHash: string): LabelEntry | null {
    return this.list().find((c) => c.roomHash === roomHash)?.hint || null;
  },

  async _updateIndex(roomHash: string, labelEntry: LabelEntry): Promise<void> {
    const list = this.list().filter((c) => c.roomHash !== roomHash);
    list.unshift({ roomHash, hint: labelEntry, savedAt: Date.now() });
    localStorage.setItem('voidlogue_convlist', JSON.stringify(list));
  },

  async migratePlaintextLabels(): Promise<void> {
    if (localStorage.getItem('voidlogue_labels_migrated')) return;
    const list = this.list();
    let changed = false;
    for (const entry of list) {
      if (!entry.hint || typeof entry.hint === 'string') {
        entry.hint = { encrypted: '', iv: '', hint: '(no label)' };
        changed = true;
      }
    }
    if (changed) {
      localStorage.setItem('voidlogue_convlist', JSON.stringify(list));
    }
    localStorage.setItem('voidlogue_labels_migrated', '1');
  },
};
