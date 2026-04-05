# voidlogue-crypto

**Open-source cryptographic layer for Voidlogue — published for independent audit and verification.**

[![npm version](https://img.shields.io/npm/v/voidlogue-crypto.svg)](https://www.npmjs.com/package/voidlogue-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](./LICENSE)

This package contains exactly the code running in the browser at [voidlogue.com](https://voidlogue.com).
It is published so that Voidlogue's privacy claims can be independently verified.

---

## What this proves

| Claim | Code |
|---|---|
| "We cannot read your messages" | `VoidShield.roomId()`, `VoidShield.deriveKey()`, `VoidShield.encrypt()` |
| "We cannot read your Revelations" | `VoidShield.deriveRevelationKey()`, `VoidShield.encryptMedia()` |
| "Your saved shortcuts are encrypted locally" | `Vault.save()`, `Vault.load()` |

See [SECURITY.md](./SECURITY.md) for a full technical explanation of each claim.

---

## Installation

```bash
npm install voidlogue-crypto
```

---

## Usage

```javascript
import { VoidShield, generateCodename } from "voidlogue-crypto";

// Derive a room hash (server never sees emails or codename)
const roomHash = await VoidShield.roomId(
  "alice@example.com",
  "bob@example.com",
  "iron-falcon-sky"
);

// Derive encryption key
const key = await VoidShield.deriveKey("iron-falcon-sky", roomHash);

// Encrypt a message
const { ciphertextB64, ivB64 } = await VoidShield.encrypt("hello", key);

// Decrypt (throws if key is wrong — AES-GCM authentication)
const plaintext = await VoidShield.decrypt(ciphertextB64, ivB64, key);

// Generate a random codename from the EFF wordlist
const codename = generateCodename(4); // e.g. "correct-horse-battery-staple"
```

---

## API Reference

### `VoidShield`

#### Conversation

| Method | Description |
|---|---|
| `hex(input)` | SHA-256 of input string → 64-char hex |
| `relationshipHash(emailA, emailB)` | Pure relationship identifier. Commutative. |
| `isInitiator(myEmail, theirEmail)` | Deterministic tie-breaker for UI deadlocks |
| `roomId(emailA, emailB, codename)` | Derives opaque room hash. Commutative. |
| `validateCodename(codename)` | Returns `{ valid, reason? }` |
| `deriveKey(codename, roomHash)` | PBKDF2 → AES-256-GCM key (non-extractable) |
| `encrypt(plaintext, key)` | AES-256-GCM → `{ ciphertextB64, ivB64 }` |
| `decrypt(ciphertextB64, ivB64, key)` | AES-256-GCM → plaintext string |
| `senderHash(uuid, roomHash)` | Room-scoped sender identifier |

#### Revelation

| Method | Description |
|---|---|
| `deriveRevelationKey(senderEmail, recipientEmail, fieldValues[])` | Key from emails + security fields |
| `deriveRevelationKeyFromHashes(senderHash, recipientHash, fieldValues[])` | Key from pre-computed hashes |
| `hashFieldValue(value)` | Normalise + SHA-256 for server storage |
| `encryptMedia(file, key)` | Chunked file encryption → chunk array |
| `decryptMediaStream(chunks, key)` | Async generator → ArrayBuffer per chunk |

#### Utilities

| Method | Description |
|---|---|
| `secureRandom(max)` | Uniform random int in `[0, max)` — rejection sampling |

### `generateCodename(wordCount?)`

Generates a hyphen-separated passphrase from the EFF long wordlist.

- Default: 3 words (~38 bits of entropy)
- Range: 2–8 words, clamped
- 4 words ≈ 51 bits, 5 words ≈ 64 bits, 6 words ≈ 77 bits

```javascript
generateCodename()  // "iron-falcon-sky"
generateCodename(5) // "correct-horse-battery-staple-moon"
```

### `Vault`

PIN-based local encryption for saved conversation credentials.

```javascript
import { Vault } from "voidlogue-crypto";

// Save email + codename encrypted with PIN
await Vault.save(roomHash, email, codename, "123456", "Alice — work");

// Load (returns {email, codename} or {error: "wrong_pin"|"locked"|"not_found"})
const result = await Vault.load(roomHash, "123456");

// List saved conversations (no sensitive data)
const list = Vault.list(); // [{roomHash, hint (encrypted), savedAt}]

// Wipe all (panic clear)
Vault.wipeAll();
```

### `EFF_WORDLIST`

The complete EFF long wordlist — 7776 words, frozen array.

```javascript
import { EFF_WORDLIST } from "voidlogue-crypto";
console.log(EFF_WORDLIST.length); // 7776
```

---

## Cryptographic algorithm summary

```
Room hash:
  hA, hB   = SHA-256(email.toLowerCase().trim())
  relHash  = SHA-256(sort([hA,hB]).join(":") + ":" + APP_SALT + ":relationship")
  roomHash = SHA-256(relHash + ":" + codename + ":" + APP_SALT)

Conversation key:
  key = PBKDF2(codename, salt=roomHash, iters=600_000, hash=SHA-256) → AES-256-GCM

Revelation key:
  hS, hR = SHA-256(email.toLowerCase().trim())
  fh[]   = SHA-256(normalise(fieldValue))
  input  = sort([hS,hR]).join(":") + ":" + fh.join(":")
  key    = PBKDF2(input, salt="voidlogue-revelation-v2", iters=600_000, hash=SHA-256) → AES-256-GCM

Vault PIN key:
  key = PBKDF2(PIN, random_16B_salt, iters=2_000_000, hash=SHA-256) → AES-256-GCM

All encryption: AES-256-GCM with random 96-bit IV per operation
All randomness: crypto.getRandomValues() with rejection sampling
```

No third-party cryptographic libraries. All operations use the Web Crypto API.

---

## Running the tests

```bash
npm install
npm test
```

Tests cover:
- SHA-256 against known vectors
- `roomId` commutativity, determinism, isolation
- Encrypt/decrypt round-trip and tamper detection
- Revelation key derivation cross-compatibility
- `secureRandom` uniformity and bounds
- Media chunk encryption and decryption
- `generateCodename` wordlist coverage
- `EFF_WORDLIST` integrity (7776 entries, no duplicates, frozen)
- Security invariants (ciphertext contains no plaintext, hashes contain no inputs)

---

## Verifying the deployed code

The code at [voidlogue.com](https://voidlogue.com) uses this package directly.
To verify:

1. Open voidlogue.com in your browser
2. DevTools → Sources → search for `VoidShield` or `roomId`
3. Compare the implementation against this repository

---

## What is NOT in this package

- Server code (Phoenix/Elixir backend)
- Database schema or queries
- The Revelation product server logic
- Payment or subscription code
- Admin infrastructure
- Anything that runs outside the browser

---

## License

MIT — see [LICENSE](./LICENSE) for details and rationale.

## Security disclosure

See [SECURITY.md](./SECURITY.md) — email security@voidlogue.com for vulnerabilities.

---

*Part of [Voidlogue](https://voidlogue.com) — Said once. Gone forever.*
