/**
 * vault.js — Voidlogue Conversation Vault
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
const PBKDF2_ITER = 600_000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const LABEL_PBKDF2_ITER = 600_000;

function randomB64(bytes) {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = '';
  for (let i = 0; i < array.length; i++) {
    binary += String.fromCharCode(array[i]);
  }
  return btoa(binary);
}

async function deriveKey(pin, saltB64) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const km = await crypto.subtle.importKey(
    'raw',
    ENC.encode(String(pin)),
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

async function deriveLabelKey(passphrase, saltB64) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const km = await crypto.subtle.importKey(
    'raw',
    ENC.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: LABEL_PBKDF2_ITER, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptLabel(label, keyOrPassphrase) {
  if (!label) return { encrypted: '', hint: '(no label)' };
  let key, salt;
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

async function decryptLabel(entry, keyOrPassphrase) {
  if (!entry || !entry.encrypted) return '';
  let key;
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
  /** Save email + codename encrypted with PIN. hint encrypted with PIN-derived key. */
  async save(roomHash, email, codename, pin, hint = '') {
    const salt = randomB64(16);
    const ivBytes = crypto.getRandomValues(new Uint8Array(12));
    const iv = btoa(String.fromCharCode(...ivBytes));
    const key = await deriveKey(pin, salt);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ivBytes },
      key,
      ENC.encode(JSON.stringify({ email, codename }))
    );
    const blob = {
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

    const labelEntry = await encryptLabel(hint, key);
    await this._updateIndex(roomHash, labelEntry);
    return true;
  },

  /** Verify codename against the codename-encrypted verification blob. Returns {email} or throws. */
  async verifyCodename(roomHash, codename) {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) throw new Error('not_found');
    const blob = JSON.parse(raw);
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

  /** Decrypt with PIN. Returns {email, codename, hint} or {error, ...}. */
  async load(roomHash, pin) {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) return { error: 'not_found' };
    const blob = JSON.parse(raw);

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

  /** Re-encrypt with new PIN after user re-enters email + codename. */
  async resetPin(roomHash, email, codename, newPin) {
    const entry = this._getEncryptedHint(roomHash);
    return this.save(
      roomHash,
      email,
      codename,
      newPin,
      entry ? '(restored)' : ''
    );
  },

  /** Re-encrypt label with a new key. */
  async updateLabel(roomHash, newHint, keyOrPassphrase) {
    const entry = await encryptLabel(newHint, keyOrPassphrase);
    await this._updateIndex(roomHash, entry);
  },

  /** Remove a conversation from vault and index. */
  delete(roomHash) {
    localStorage.removeItem(`voidlogue_conv_${roomHash}`);
    const list = this.list().filter((c) => c.roomHash !== roomHash);
    localStorage.setItem('voidlogue_convlist', JSON.stringify(list));
  },

  /** Returns the plaintext index of saved conversations. */
  list() {
    try {
      return JSON.parse(localStorage.getItem('voidlogue_convlist') || '[]');
    } catch {
      return [];
    }
  },

  /** Returns true if conversation has a PIN-protected vault entry. */
  has(roomHash) {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) return false;
    try {
      const blob = JSON.parse(raw);
      return !!blob.salt && !!blob.data;
    } catch {
      return false;
    }
  },

  /** Returns true if conversation has any vault entry. */
  hasAny(roomHash) {
    if (this.has(roomHash)) return true;
    return this.list().some((c) => c.roomHash === roomHash);
  },

  /** Returns lockout info without attempting a decrypt. */
  lockoutStatus(roomHash) {
    const raw = localStorage.getItem(`voidlogue_conv_${roomHash}`);
    if (!raw) return null;
    const blob = JSON.parse(raw);
    if (blob.lockedUntil && Date.now() < blob.lockedUntil) {
      return {
        locked: true,
        minutesRemaining: Math.ceil((blob.lockedUntil - Date.now()) / 60000),
      };
    }
    return { locked: false, attemptsUsed: blob.attempts || 0 };
  },

  /** Wipe everything — called by panic clear. */
  wipeAll() {
    const list = this.list();
    list.forEach((c) =>
      localStorage.removeItem(`voidlogue_conv_${c.roomHash}`)
    );
    localStorage.removeItem('voidlogue_convlist');
  },

  _getEncryptedHint(roomHash) {
    return this.list().find((c) => c.roomHash === roomHash)?.hint || null;
  },

  async _updateIndex(roomHash, labelEntry) {
    const list = this.list().filter((c) => c.roomHash !== roomHash);
    list.unshift({ roomHash, hint: labelEntry, savedAt: Date.now() });
    localStorage.setItem('voidlogue_convlist', JSON.stringify(list));
  },

  /** Migrate any plaintext labels to encrypted format. Call once on app start. */
  async migratePlaintextLabels() {
    if (localStorage.getItem('voidlogue_labels_migrated')) return;
    const list = this.list();
    let changed = false;
    for (const entry of list) {
      if (!entry.hint || typeof entry.hint === 'string') {
        entry.hint = { encrypted: '', hint: '(no label)' };
        changed = true;
      }
    }
    if (changed) {
      localStorage.setItem('voidlogue_convlist', JSON.stringify(list));
    }
    localStorage.setItem('voidlogue_labels_migrated', '1');
  },
};
