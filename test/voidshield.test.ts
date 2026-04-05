/**
 * voidlogue-crypto test suite
 *
 * Tests run in Node.js ≥18 using Vitest.
 * Web Crypto API is available natively in Node 18+.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import { expect } from 'expect';
import { VoidShield, generateCodename } from '../src/voidshield.js';
import { EFF_WORDLIST } from '../src/eff_wordlist.js';

// ── VoidShield.hex ─────────────────────────────────────────────────────────

describe('VoidShield.hex', () => {
  it('returns a 64-character lowercase hex string', async () => {
    const h = await VoidShield.hex('hello');
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]+$/);
  });

  it('is deterministic — same input always produces same output', async () => {
    const h1 = await VoidShield.hex('voidlogue');
    const h2 = await VoidShield.hex('voidlogue');
    expect(h1).toBe(h2);
  });

  it('different inputs produce different hashes', async () => {
    const h1 = await VoidShield.hex('alice@example.com');
    const h2 = await VoidShield.hex('bob@example.com');
    expect(h1).not.toBe(h2);
  });

  it('known SHA-256 vector: empty string', async () => {
    const h = await VoidShield.hex('');
    expect(h).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });
});

// ── VoidShield.relationshipHash ────────────────────────────────────────────

describe('VoidShield.relationshipHash', () => {
  it('returns a 64-character hex string', async () => {
    const hash = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });

  it('is commutative — order of emails does not matter', async () => {
    const h1 = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    const h2 = await VoidShield.relationshipHash(
      'bob@example.com',
      'alice@example.com'
    );
    expect(h1).toBe(h2);
  });

  it('is deterministic — same inputs always produce same hash', async () => {
    const h1 = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    const h2 = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    expect(h1).toBe(h2);
  });

  it('different email pairs produce different hashes', async () => {
    const h1 = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    const h2 = await VoidShield.relationshipHash(
      'charlie@example.com',
      'bob@example.com'
    );
    expect(h1).not.toBe(h2);
  });

  it('normalises email case — uppercase and lowercase produce same hash', async () => {
    const h1 = await VoidShield.relationshipHash(
      'Alice@Example.COM',
      'bob@example.com'
    );
    const h2 = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    expect(h1).toBe(h2);
  });

  it('does not reveal raw email identity', async () => {
    const hash = await VoidShield.relationshipHash(
      'alice@example.com',
      'bob@example.com'
    );
    expect(hash).not.toContain('alice');
    expect(hash).not.toContain('bob');
  });
});

// ── VoidShield.isInitiator ─────────────────────────────────────────────────

describe('VoidShield.isInitiator', () => {
  it('returns a boolean', async () => {
    const isInit = await VoidShield.isInitiator(
      'a@example.com',
      'b@example.com'
    );
    expect(typeof isInit).toBe('boolean');
  });

  it('is deterministic and mutually exclusive', async () => {
    const emailA = 'alice@example.com';
    const emailB = 'bob@example.com';
    const aInit = await VoidShield.isInitiator(emailA, emailB);
    const bInit = await VoidShield.isInitiator(emailB, emailA);
    expect(aInit).not.toBe(bInit);
  });

  it('normalises case and whitespace like relationshipHash', async () => {
    const lower = await VoidShield.isInitiator(
      'alice@example.com',
      'bob@example.com'
    );
    const upper = await VoidShield.isInitiator(
      ' ALICE@EXAMPLE.COM ',
      ' BoB@example.com '
    );
    expect(lower).toBe(upper);
  });
});

// ── VoidShield.roomId ──────────────────────────────────────────────────────

describe('VoidShield.roomId', () => {
  it('returns a 64-character hex string', async () => {
    const id = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    expect(id).toHaveLength(64);
    expect(id).toMatch(/^[0-9a-f]+$/);
  });

  it('is commutative — order of emails does not matter', async () => {
    const id1 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    const id2 = await VoidShield.roomId(
      'bob@example.com',
      'alice@example.com',
      'iron-falcon'
    );
    expect(id1).toBe(id2);
  });

  it('is deterministic — same inputs always produce same room hash', async () => {
    const id1 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    const id2 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    expect(id1).toBe(id2);
  });

  it('different codenames produce different room hashes', async () => {
    const id1 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    const id2 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'silver-moon'
    );
    expect(id1).not.toBe(id2);
  });

  it('different email pairs produce different room hashes', async () => {
    const id1 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    const id2 = await VoidShield.roomId(
      'charlie@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    expect(id1).not.toBe(id2);
  });

  it('normalises email case — uppercase and lowercase produce same room hash', async () => {
    const id1 = await VoidShield.roomId(
      'Alice@Example.COM',
      'bob@example.com',
      'iron-falcon'
    );
    const id2 = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    expect(id1).toBe(id2);
  });

  it('the room hash is not the raw email — server never sees identity', async () => {
    const id = await VoidShield.roomId(
      'alice@example.com',
      'bob@example.com',
      'iron-falcon'
    );
    expect(id).not.toContain('alice');
    expect(id).not.toContain('bob');
    expect(id).not.toContain('iron-falcon');
  });
});

// ── VoidShield.validateCodename ────────────────────────────────────────────

describe('VoidShield.validateCodename', () => {
  it('accepts valid codenames', () => {
    expect(VoidShield.validateCodename('iron-falcon-sky').valid).toBe(true);
    expect(
      VoidShield.validateCodename('correct-horse-battery-staple').valid
    ).toBe(true);
    expect(VoidShield.validateCodename('mysecret1234').valid).toBe(true);
  });

  it('rejects codenames shorter than 8 characters', () => {
    const r = VoidShield.validateCodename('short');
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/8 characters/);
  });

  it('rejects codenames longer than 128 characters', () => {
    const r = VoidShield.validateCodename('a'.repeat(129));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/128/);
  });

  it('rejects numeric-only codenames', () => {
    const r = VoidShield.validateCodename('12345678');
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/only numbers/);
  });

  it('rejects codenames with fewer than 4 unique characters', () => {
    const r = VoidShield.validateCodename('aaaabbbb');
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/unique/);
  });

  it('rejects empty / null input', () => {
    expect(VoidShield.validateCodename('').valid).toBe(false);
    expect(VoidShield.validateCodename(null as unknown as string).valid).toBe(
      false
    );
    expect(
      VoidShield.validateCodename(undefined as unknown as string).valid
    ).toBe(false);
  });
});

// ── VoidShield.deriveKey + encrypt + decrypt ───────────────────────────────

describe('VoidShield encrypt/decrypt round-trip', () => {
  it('encrypts and decrypts a message correctly', async () => {
    const roomHash = await VoidShield.roomId(
      'a@b.com',
      'c@d.com',
      'test-codename'
    );
    const key = await VoidShield.deriveKey('test-codename', roomHash);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt(
      'hello world',
      key
    );
    const plaintext = await VoidShield.decrypt(ciphertextB64, ivB64, key);
    expect(plaintext).toBe('hello world');
  });

  it('produces different ciphertext each time (fresh random IV)', async () => {
    const roomHash = await VoidShield.roomId(
      'a@b.com',
      'c@d.com',
      'test-codename'
    );
    const key = await VoidShield.deriveKey('test-codename', roomHash);
    const r1 = await VoidShield.encrypt('same message', key);
    const r2 = await VoidShield.encrypt('same message', key);
    expect(r1.ciphertextB64).not.toBe(r2.ciphertextB64);
    expect(r1.ivB64).not.toBe(r2.ivB64);
  });

  it('decryption fails with wrong key (authentication tag mismatch)', async () => {
    const rh1 = await VoidShield.roomId('a@b.com', 'c@d.com', 'codename-one');
    const rh2 = await VoidShield.roomId('a@b.com', 'c@d.com', 'codename-two');
    const key1 = await VoidShield.deriveKey('codename-one', rh1);
    const key2 = await VoidShield.deriveKey('codename-two', rh2);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('secret', key1);
    await expect(
      VoidShield.decrypt(ciphertextB64, ivB64, key2)
    ).rejects.toThrow();
  });

  it('decryption fails with tampered ciphertext', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'codename');
    const key = await VoidShield.deriveKey('codename', rh);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt(
      'secret message',
      key
    );
    // Tamper with a character in the ciphertext
    const tampered = ciphertextB64.slice(0, -4) + 'XXXX';
    await expect(VoidShield.decrypt(tampered, ivB64, key)).rejects.toThrow();
  });

  it('key derivation is deterministic — same codename and roomHash produce same key behaviour', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'stable-codename');
    const key1 = await VoidShield.deriveKey('stable-codename', rh);
    const key2 = await VoidShield.deriveKey('stable-codename', rh);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('test', key1);
    const result = await VoidShield.decrypt(ciphertextB64, ivB64, key2);
    expect(result).toBe('test');
  });
});

// ── VoidShield.deriveRevelationKey ─────────────────────────────────────────

describe('VoidShield.deriveRevelationKey', () => {
  it('returns a non-null CryptoKey', async () => {
    const key = await VoidShield.deriveRevelationKey(
      'sender@example.com',
      'recipient@example.com',
      ['Alice', '1990-01-01']
    );
    expect(key).toBeTruthy();
    expect(key.type).toBe('secret');
  });

  it('is commutative on email order', async () => {
    const k1 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'field',
    ]);
    const k2 = await VoidShield.deriveRevelationKey('r@b.com', 's@a.com', [
      'field',
    ]);
    // Verify by encrypting with k1 and decrypting with k2
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('test', k1);
    const result = await VoidShield.decrypt(ciphertextB64, ivB64, k2);
    expect(result).toBe('test');
  });

  it('different field values produce different keys', async () => {
    const k1 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'Alice',
    ]);
    const k2 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'Bob',
    ]);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('test', k1);
    await expect(
      VoidShield.decrypt(ciphertextB64, ivB64, k2)
    ).rejects.toThrow();
  });

  it('normalises field values (case + whitespace insensitive)', async () => {
    const k1 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'alice',
    ]);
    const k2 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      ' Alice ',
    ]);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('test', k1);
    const result = await VoidShield.decrypt(ciphertextB64, ivB64, k2);
    expect(result).toBe('test');
  });
});

// ── VoidShield.deriveRevelationKeyFromHashes ───────────────────────────────

describe('VoidShield.deriveRevelationKeyFromHashes', () => {
  it('produces same key as deriveRevelationKey given same inputs', async () => {
    const sEmail = 'sender@example.com';
    const rEmail = 'recipient@example.com';
    const fields = ['Alice', '1990-01-01'];

    const sHash = await VoidShield.hex(sEmail.toLowerCase().trim());
    const rHash = await VoidShield.hex(rEmail.toLowerCase().trim());

    const k1 = await VoidShield.deriveRevelationKey(sEmail, rEmail, fields);
    const k2 = await VoidShield.deriveRevelationKeyFromHashes(
      sHash,
      rHash,
      fields
    );

    const { ciphertextB64, ivB64 } = await VoidShield.encrypt(
      'revelation content',
      k1
    );
    const result = await VoidShield.decrypt(ciphertextB64, ivB64, k2);
    expect(result).toBe('revelation content');
  });
});

// ── VoidShield.hashFieldValue ──────────────────────────────────────────────

describe('VoidShield.hashFieldValue', () => {
  it('returns a 64-character hex hash', async () => {
    const h = await VoidShield.hashFieldValue('Alice');
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]+$/);
  });

  it('normalises before hashing — case insensitive', async () => {
    const h1 = await VoidShield.hashFieldValue('alice');
    const h2 = await VoidShield.hashFieldValue('ALICE');
    expect(h1).toBe(h2);
  });

  it('normalises before hashing — strips whitespace', async () => {
    const h1 = await VoidShield.hashFieldValue('alice');
    const h2 = await VoidShield.hashFieldValue(' alice ');
    expect(h1).toBe(h2);
  });

  it('the raw value is not derivable from the hash', async () => {
    const h = await VoidShield.hashFieldValue('alice');
    expect(h).not.toContain('alice');
  });
});

// ── VoidShield.senderHash ─────────────────────────────────────────────────

describe('VoidShield.senderHash', () => {
  it('returns a 64-character hex string', async () => {
    const h = await VoidShield.senderHash('user-uuid-1234', 'room-hash-abcd');
    expect(h).toHaveLength(64);
  });

  it('different UUIDs produce different sender hashes for the same room', async () => {
    const h1 = await VoidShield.senderHash('uuid-A', 'room-hash');
    const h2 = await VoidShield.senderHash('uuid-B', 'room-hash');
    expect(h1).not.toBe(h2);
  });

  it('same UUID in different rooms produces different sender hashes', async () => {
    const h1 = await VoidShield.senderHash('uuid-A', 'room-hash-1');
    const h2 = await VoidShield.senderHash('uuid-A', 'room-hash-2');
    expect(h1).not.toBe(h2);
  });

  it('sender hash does not contain the raw UUID', async () => {
    const uuid = 'my-very-specific-uuid';
    const h = await VoidShield.senderHash(uuid, 'room-hash');
    expect(h).not.toContain(uuid);
  });
});

// ── VoidShield.secureRandom ───────────────────────────────────────────────

describe('VoidShield.secureRandom', () => {
  it('returns values within [0, max)', () => {
    for (let i = 0; i < 200; i++) {
      const r = VoidShield.secureRandom(100);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThan(100);
    }
  });

  it('returns integer values only', () => {
    for (let i = 0; i < 50; i++) {
      const r = VoidShield.secureRandom(1000);
      expect(Number.isInteger(r)).toBe(true);
    }
  });

  it('distributes values across range (basic uniformity check)', () => {
    const counts = new Array(10).fill(0);
    for (let i = 0; i < 1000; i++) {
      counts[VoidShield.secureRandom(10)]++;
    }
    // Each bucket should have roughly 100 ± 50 (very loose check for CI)
    counts.forEach((c) => {
      expect(c).toBeGreaterThan(30);
      expect(c).toBeLessThan(200);
    });
  });

  it('works for max=1 (always returns 0)', () => {
    for (let i = 0; i < 20; i++) {
      expect(VoidShield.secureRandom(1)).toBe(0);
    }
  });
});

// ── Media encryption ──────────────────────────────────────────────────────

describe('VoidShield media encryption', () => {
  it('encryptMedia returns chunks with correct structure', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'media-test');
    const key = await VoidShield.deriveKey('media-test', rh);
    const data = new Uint8Array(1024).fill(42); // 1 KB of 0x2A
    const file = new File([data], 'test.bin', {
      type: 'application/octet-stream',
    });

    const chunks = await VoidShield.encryptMedia(file, key);
    expect(chunks.length).toBeGreaterThan(0);
    chunks.forEach((c) => {
      expect(c).toHaveProperty('ciphertextB64');
      expect(c).toHaveProperty('ivB64');
      expect(c).toHaveProperty('index');
      expect(c).toHaveProperty('totalChunks');
    });
  });

  it('decryptMediaStream recovers original file bytes', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'media-test');
    const key = await VoidShield.deriveKey('media-test', rh);
    const original = new Uint8Array(512).fill(99);
    const file = new File([original], 'test.bin', {
      type: 'application/octet-stream',
    });

    const chunks = await VoidShield.encryptMedia(file, key);
    const buffers = [];
    for await (const buf of VoidShield.decryptMediaStream(chunks, key)) {
      buffers.push(new Uint8Array(buf));
    }
    const recovered = new Uint8Array(
      buffers.reduce((acc, b) => acc + b.length, 0)
    );
    let offset = 0;
    for (const b of buffers) {
      recovered.set(b, offset);
      offset += b.length;
    }

    expect(recovered).toEqual(original);
  });
});

// ── generateCodename ──────────────────────────────────────────────────────

describe('generateCodename', () => {
  it('returns a hyphen-separated string', () => {
    const c = generateCodename();
    expect(c).toMatch(/^[a-z]+-[a-z]+-[a-z]+$/);
  });

  it('defaults to 3 words', () => {
    const c = generateCodename();
    expect(c.split('-').length).toBe(3);
  });

  it('respects wordCount parameter', () => {
    for (let n = 2; n <= 8; n++) {
      expect(generateCodename(n).split('-').length).toBe(n);
    }
  });

  it('clamps wordCount to [2, 8]', () => {
    expect(generateCodename(1).split('-').length).toBe(2);
    expect(generateCodename(99).split('-').length).toBe(8);
  });

  it('all words come from the EFF wordlist', () => {
    const set = new Set(EFF_WORDLIST);
    for (let i = 0; i < 20; i++) {
      generateCodename(4)
        .split('-')
        .forEach((w) => {
          expect(set.has(w)).toBe(true);
        });
    }
  });

  it('generates different codenames on successive calls (randomness)', () => {
    const results = new Set();
    for (let i = 0; i < 20; i++) results.add(generateCodename());
    // With 7776^3 combinations it would be astronomically unlikely to get any repeat
    expect(results.size).toBeGreaterThan(15);
  });
});

// ── EFF_WORDLIST ──────────────────────────────────────────────────────────

describe('EFF_WORDLIST', () => {
  it('contains exactly 7776 words', () => {
    expect(EFF_WORDLIST.length).toBe(7776);
  });

  it('all entries are non-empty lowercase strings', () => {
    EFF_WORDLIST.forEach((w) => {
      expect(typeof w).toBe('string');
      expect(w.length).toBeGreaterThan(0);
      expect(w).toBe(w.toLowerCase());
    });
  });

  it('contains no duplicates', () => {
    expect(new Set(EFF_WORDLIST).size).toBe(7776);
  });

  it('is frozen (immutable)', () => {
    expect(Object.isFrozen(EFF_WORDLIST)).toBe(true);
  });
});

// ── Security invariants ───────────────────────────────────────────────────

describe('Security invariants', () => {
  it('room hash does not reveal email A', async () => {
    const id = await VoidShield.roomId(
      'alice@secret.com',
      'bob@example.com',
      'codename'
    );
    expect(id).not.toContain('alice');
    expect(id).not.toContain('secret');
  });

  it('room hash does not reveal email B', async () => {
    const id = await VoidShield.roomId(
      'alice@example.com',
      'bob@secret.com',
      'codename'
    );
    expect(id).not.toContain('bob');
    expect(id).not.toContain('secret');
  });

  it('room hash does not reveal the codename', async () => {
    const codename = 'my-very-secret-codename';
    const id = await VoidShield.roomId('a@b.com', 'c@d.com', codename);
    expect(id).not.toContain(codename);
    expect(id).not.toContain('very-secret');
  });

  it('ciphertext does not contain the plaintext', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'codename');
    const key = await VoidShield.deriveKey('codename', rh);
    const msg = 'this is my secret message';
    const { ciphertextB64 } = await VoidShield.encrypt(msg, key);
    const decoded = atob(ciphertextB64);
    expect(decoded).not.toContain(msg);
  });

  it('two Revelation keys derived from same inputs are functionally identical', async () => {
    const k1 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'fieldvalue',
    ]);
    const k2 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'fieldvalue',
    ]);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('revelation', k1);
    expect(await VoidShield.decrypt(ciphertextB64, ivB64, k2)).toBe(
      'revelation'
    );
  });

  it('wrong field value cannot decrypt revelation', async () => {
    const k1 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'correct-value',
    ]);
    const k2 = await VoidShield.deriveRevelationKey('s@a.com', 'r@b.com', [
      'wrong-value',
    ]);
    const { ciphertextB64, ivB64 } = await VoidShield.encrypt('private', k1);
    await expect(
      VoidShield.decrypt(ciphertextB64, ivB64, k2)
    ).rejects.toThrow();
  });
});

// ── Media Chunks AAD testing ───────────────────────────────────────────────

describe('VoidShield media chunk AAD validation', () => {
  it('throws an error if a chunk originates from a different streamId', async () => {
    const rh = await VoidShield.roomId(
      'a@b.com',
      'c@d.com',
      'cross-stream-test'
    );
    const key = await VoidShield.deriveKey('cross-stream-test', rh);

    const file1 = new File([new Uint8Array(500 * 1024).fill(7)], 'test1.bin', {
      type: 'application/octet-stream',
    });
    const chunks1 = await VoidShield.encryptMedia(file1, key);

    const file2 = new File([new Uint8Array(500 * 1024).fill(8)], 'test2.bin', {
      type: 'application/octet-stream',
    });
    const chunks2 = await VoidShield.encryptMedia(file2, key);

    chunks1[1] = chunks2[1]!;

    let threw = false;
    try {
      for await (const _buf of VoidShield.decryptMediaStream(chunks1, key)) {
        // Drain stream to trigger auth check
      }
    } catch (_e) {
      threw = true;
    }
    expect(threw).toBe(true);
  });
  it('throws an error if a chunk index is tampered with', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'media-aad-test');
    const key = await VoidShield.deriveKey('media-aad-test', rh);
    const file = new File([new Uint8Array(512).fill(7)], 'test.bin', {
      type: 'application/octet-stream',
    });
    const chunks = await VoidShield.encryptMedia(file, key);

    chunks[0]!.index = 1; // Tamper index

    let threw = false;
    try {
      for await (const _buf of VoidShield.decryptMediaStream(chunks, key)) {
        // Drain stream to trigger auth check
      }
    } catch (_e) {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  it('throws an error if totalChunks is tampered with', async () => {
    const rh = await VoidShield.roomId('a@b.com', 'c@d.com', 'media-aad-test');
    const key = await VoidShield.deriveKey('media-aad-test', rh);
    const file = new File([new Uint8Array(512).fill(7)], 'test.bin', {
      type: 'application/octet-stream',
    });
    const chunks = await VoidShield.encryptMedia(file, key);

    chunks[0]!.totalChunks = 999; // Tamper count

    let threw = false;
    try {
      for await (const _buf of VoidShield.decryptMediaStream(chunks, key)) {
        // Drain stream to trigger auth check
      }
    } catch (_e) {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});

// ── Hybrid Kyber Encryption ───────────────────────────────────────────────

describe('VoidShield hybrid Kyber encryption', () => {
  it('encrypts and decrypts a hybrid payload correctly', async () => {
    const { publicKey, secretKey } = await VoidShield.generateKyberKeyPair();
    const plaintext = 'top secret quantum payload';

    const hybridCt = await VoidShield.encryptHybrid(plaintext, publicKey);

    expect(hybridCt).toHaveProperty('version');
    expect(hybridCt).toHaveProperty('aesCiphertextB64');
    expect(hybridCt).toHaveProperty('aesIvB64');
    expect(hybridCt).toHaveProperty('kyberCiphertextB64');
    expect(hybridCt).toHaveProperty('encapsulatedKeyB64');

    const decrypted = await VoidShield.decryptHybrid(hybridCt, secretKey);
    expect(decrypted).toBe(plaintext);
  });

  it('fails decryption with an invalid secret key', async () => {
    const { publicKey } = await VoidShield.generateKyberKeyPair();
    const { secretKey: wrongKey } = await VoidShield.generateKyberKeyPair();
    const plaintext = 'top secret quantum payload';

    const hybridCt = await VoidShield.encryptHybrid(plaintext, publicKey);

    await expect(
      VoidShield.decryptHybrid(hybridCt, wrongKey)
    ).rejects.toThrow();
  });

  it('fails decryption if wrapped key is tampered with', async () => {
    const { publicKey, secretKey } = await VoidShield.generateKyberKeyPair();
    const hybridCt = await VoidShield.encryptHybrid('test', publicKey);

    if (hybridCt.encapsulatedKeyB64) {
      hybridCt.encapsulatedKeyB64 =
        hybridCt.encapsulatedKeyB64.substring(
          0,
          hybridCt.encapsulatedKeyB64.length - 2
        ) + 'XX';
    }

    await expect(
      VoidShield.decryptHybrid(hybridCt, secretKey)
    ).rejects.toThrow();
  });
});
