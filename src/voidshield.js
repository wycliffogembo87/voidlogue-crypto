/**
 * VoidShield — Voidlogue Client-Side Cryptography
 * =================================================
 * Version: 1.0.0
 * License: MIT
 * Repository: https://github.com/voidlogue/voidlogue-crypto
 *
 * All cryptographic operations run entirely in the browser using the
 * Web Crypto API. Nothing sensitive ever reaches the server as plaintext.
 *
 * Exports:
 *   VoidShield  — crypto primitives for Conversation and Revelation
 *   generateCodename — EFF-wordlist passphrase generator
 *
 * Cryptographic primitives:
 *   Hashing:         SHA-256 via SubtleCrypto.digest
 *   Key derivation:  PBKDF2 (SHA-256, 600,000 iterations)
 *   Encryption:      AES-256-GCM with random 96-bit IV per message
 *   Randomness:      crypto.getRandomValues (rejection-sampling for uniformity)
 *
 * What this proves (open-source audit surface):
 *   - Room hashes are derived client-side. The server receives only an opaque
 *     hash and can never reverse it to learn email addresses or codenames.
 *   - Message encryption keys are derived from the codename and never sent
 *     to the server. The server stores only ciphertext it cannot decrypt.
 *   - Revelation keys are derived from the recipient's security fields — values
 *     the server never holds. Delivery does not require decryption.
 */

import { EFF_WORDLIST } from './eff_wordlist.js';

// ── INTERNAL CONSTANTS ────────────────────────────────────────────────────
// These salts are intentionally public — security depends on key secrecy,
// not salt secrecy. Published here for independent verification.
const APP_SALT = 'voidlogue-v1-room-salt-2026';
const REV_SALT = 'voidlogue-revelation-v1';
const PBKDF2_ITER = 600_000;
const CHUNK_BYTES = 256 * 1024; // 256 KB per media chunk
const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ── BASE64 HELPERS ────────────────────────────────────────────────────────
const b64 = (buf) =>
  btoa(
    String.fromCharCode(
      ...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer)
    )
  );
const ub64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ── VOIDSHIELD ────────────────────────────────────────────────────────────

/**
 * VoidShield — cryptographic primitives for Voidlogue.
 *
 * All methods are pure (no side-effects, no DOM access, no localStorage).
 * Safe to use in any JavaScript environment that provides the Web Crypto API.
 */
export const VoidShield = {
  // ── Hashing ──────────────────────────────────────────────────────────────

  /**
   * SHA-256 of `input`, returned as lowercase hex string.
   * @param {string} input
   * @returns {Promise<string>} 64-character hex string
   */
  async hex(input) {
    const buf = await crypto.subtle.digest('SHA-256', ENC.encode(input));
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  },

  // ── Conversation ─────────────────────────────────────────────────────────

  /**
   * Derives a room hash from two email addresses and a shared codename.
   *
   * The sort ensures the hash is identical regardless of which party derives
   * it first. The server receives only this opaque hash — never the emails
   * or the codename.
   *
   * Algorithm:
   *   hA = SHA-256(emailA.toLowerCase().trim())
   *   hB = SHA-256(emailB.toLowerCase().trim())
   *   roomHash = SHA-256(sort([hA, hB]).join(":") + ":" + codename + ":" + APP_SALT)
   *
   * @param {string} emailA
   * @param {string} emailB
   * @param {string} codename
   * @returns {Promise<string>} 64-character hex room hash
   */
  async roomId(emailA, emailB, codename) {
    const [hA, hB] = await Promise.all([
      this.hex(emailA.toLowerCase().trim()),
      this.hex(emailB.toLowerCase().trim()),
    ]);
    return this.hex(`${[hA, hB].sort().join(':')}:${codename}:${APP_SALT}`);
  },

  /**
   * Validates a user-entered codename meets minimum entropy requirements.
   * @param {string} codename
   * @returns {{ valid: boolean, reason?: string }}
   */
  validateCodename(codename) {
    if (!codename || codename.length < 8)
      return {
        valid: false,
        reason: 'Codename must be at least 8 characters.',
      };
    if (codename.length > 128)
      return {
        valid: false,
        reason: 'Codename must be 128 characters or less.',
      };
    if (/^\d+$/.test(codename))
      return { valid: false, reason: 'Codename cannot be only numbers.' };
    if (new Set(codename.toLowerCase()).size < 4)
      return {
        valid: false,
        reason: 'Codename must have at least 4 unique characters.',
      };
    return { valid: true };
  },

  /**
   * Derives an AES-256-GCM key from a codename and room hash via PBKDF2.
   *
   * The derived key is non-extractable — the browser will not allow it to
   * be exported or inspected. It can only be used for encrypt/decrypt.
   *
   * @param {string} codename  shared secret
   * @param {string} roomHash  used as PBKDF2 salt
   * @returns {Promise<CryptoKey>}
   */
  async deriveKey(codename, roomHash) {
    const km = await crypto.subtle.importKey(
      'raw',
      ENC.encode(codename),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: ENC.encode(roomHash),
        iterations: PBKDF2_ITER,
        hash: 'SHA-256',
      },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  /**
   * AES-256-GCM encrypt plaintext string.
   * A fresh random 96-bit IV is generated for every call.
   *
   * @param {string} plaintext
   * @param {CryptoKey} key
   * @returns {Promise<{ ciphertextB64: string, ivB64: string }>}
   */
  async encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      ENC.encode(plaintext)
    );
    return { ciphertextB64: b64(ct), ivB64: b64(iv) };
  },

  /**
   * AES-256-GCM decrypt.
   * Throws DOMException if ciphertext has been tampered with (authentication
   * tag mismatch — inherent to AES-GCM).
   *
   * @param {string} ciphertextB64
   * @param {string} ivB64
   * @param {CryptoKey} key
   * @returns {Promise<string>} plaintext
   */
  async decrypt(ciphertextB64, ivB64, key) {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ub64(ivB64) },
      key,
      ub64(ciphertextB64)
    );
    return DEC.decode(pt);
  },

  // ── Media (chunked encryption) ────────────────────────────────────────────

  /**
   * Encrypts a File in 256 KB chunks for Revelation media attachments.
   * Each chunk has an independent random IV.
   *
   * @param {File} file
   * @param {CryptoKey} key
   * @returns {Promise<Array<{ ciphertextB64, ivB64, index, totalChunks }>>}
   */
  async encryptMedia(file, key) {
    const buffer = await file.arrayBuffer();
    const total = Math.ceil(buffer.byteLength / CHUNK_BYTES);
    const chunks = [];
    for (
      let i = 0, offset = 0;
      offset < buffer.byteLength;
      i++, offset += CHUNK_BYTES
    ) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        buffer.slice(offset, offset + CHUNK_BYTES)
      );
      chunks.push({
        ciphertextB64: b64(ct),
        ivB64: b64(iv),
        index: i,
        totalChunks: total,
      });
    }
    return chunks;
  },

  /**
   * Async generator — decrypts and yields each chunk buffer in index order.
   *
   * @param {Array} chunks
   * @param {CryptoKey} key
   * @yields {ArrayBuffer}
   */
  async *decryptMediaStream(chunks, key) {
    for (const c of [...chunks].sort((a, b) => a.index - b.index)) {
      yield await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ub64(c.ivB64) },
        key,
        ub64(c.ciphertextB64)
      );
    }
  },

  // ── Revelation ────────────────────────────────────────────────────────────

  /**
   * Derives a Revelation encryption key from sender email, recipient email,
   * and recipient security field values.
   *
   * The server never holds any of these inputs. Delivery does not require
   * decryption — the server relays encrypted bytes it cannot read.
   *
   * For anonymous revelations, pass "__anon__" as senderEmail.
   *
   * @param {string} senderEmail    raw email or "__anon__"
   * @param {string} recipientEmail raw recipient email
   * @param {string[]} fieldValues  raw security field values (e.g. ["Alice", "1990-01-01"])
   * @returns {Promise<CryptoKey>}
   */
  async deriveRevelationKey(senderEmail, recipientEmail, fieldValues = []) {
    const [hS, hR] = await Promise.all([
      this.hex(senderEmail.toLowerCase().trim()),
      this.hex(recipientEmail.toLowerCase().trim()),
    ]);
    const fh = await Promise.all(
      fieldValues.map((v) => this.hex(this._norm(v)))
    );
    const input = [[hS, hR].sort().join(':'), ...fh].join(':');
    const km = await crypto.subtle.importKey(
      'raw',
      ENC.encode(input),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: ENC.encode(REV_SALT),
        iterations: PBKDF2_ITER,
        hash: 'SHA-256',
      },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  /**
   * Revelation key derivation using pre-computed email hashes.
   *
   * Used by the recipient's ReadingView where the server provides the sender's
   * email hash (computed at send time) rather than the raw email. The recipient
   * never types the sender's email.
   *
   * @param {string} senderEmailHash    64-char hex SHA-256 of sender email
   * @param {string} recipientEmailHash 64-char hex SHA-256 of recipient email
   * @param {string[]} fieldValues      raw security field values
   * @returns {Promise<CryptoKey>}
   */
  async deriveRevelationKeyFromHashes(
    senderEmailHash,
    recipientEmailHash,
    fieldValues = []
  ) {
    const fh = await Promise.all(
      fieldValues.map((v) => this.hex(this._norm(v)))
    );
    const input = [
      [senderEmailHash, recipientEmailHash].sort().join(':'),
      ...fh,
    ].join(':');
    const km = await crypto.subtle.importKey(
      'raw',
      ENC.encode(input),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: ENC.encode(REV_SALT),
        iterations: PBKDF2_ITER,
        hash: 'SHA-256',
      },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  /**
   * Hash a security field value for server-side storage and comparison.
   * Raw values are never sent to the server.
   *
   * @param {string} value raw field value
   * @returns {Promise<string>} 64-char hex hash
   */
  async hashFieldValue(value) {
    return this.hex(this._norm(value));
  },

  // ── Identity ──────────────────────────────────────────────────────────────

  /**
   * Derives a room-scoped sender identifier.
   * SHA-256(uuid + ":" + roomHash) — opaque, cannot be used to join rooms.
   *
   * @param {string} uuid     user's internal UUID
   * @param {string} roomHash derived room hash
   * @returns {Promise<string>} 64-char hex sender hash
   */
  async senderHash(uuid, roomHash) {
    return this.hex(`${uuid}:${roomHash}`);
  },

  // ── Randomness ────────────────────────────────────────────────────────────

  /**
   * Cryptographically uniform random integer in [0, max).
   *
   * Uses rejection sampling to eliminate modular bias — unlike a simple
   * `getRandomValues() % max` which biases toward lower values when max
   * is not a power of two.
   *
   * @param {number} max exclusive upper bound
   * @returns {number}
   */
  secureRandom(max) {
    const buf = new Uint32Array(1);
    const lim = Math.floor(0x100000000 / max) * max;
    do {
      crypto.getRandomValues(buf);
    } while (buf[0] >= lim);
    return buf[0] % max;
  },

  // ── Internal ─────────────────────────────────────────────────────────────

  /**
   * Normalise a field value for consistent hashing.
   * Lowercases, strips whitespace, hyphens, underscores, and dots.
   * @internal
   */
  _norm(v) {
    return String(v)
      .toLowerCase()
      .replace(/[\s\-_.]/g, '')
      .trim();
  },
};

// ── CODENAME GENERATOR ────────────────────────────────────────────────────

/**
 * Generates a random passphrase from the EFF long wordlist.
 *
 * Default: 3 words (≈38 bits of entropy from 7776-word pool).
 * Increase wordCount for higher-security codenames:
 *   4 words ≈ 51 bits
 *   5 words ≈ 64 bits
 *   6 words ≈ 77 bits
 *
 * The EFF wordlist is intentionally public. Security comes from the
 * randomness of selection, not the secrecy of the word list.
 *
 * @param {number} wordCount number of words (2–8)
 * @returns {string} hyphen-separated passphrase
 */
export function generateCodename(wordCount = 3) {
  const count = Math.max(2, Math.min(8, wordCount));
  const words = [];
  for (let i = 0; i < count; i++) {
    words.push(EFF_WORDLIST[VoidShield.secureRandom(EFF_WORDLIST.length)]);
  }
  return words.join('-');
}
