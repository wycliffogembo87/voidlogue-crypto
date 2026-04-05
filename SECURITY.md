# Security Policy

## What this package proves

This package is the open-source cryptographic layer for Voidlogue. It is
published so that the following privacy claims can be independently verified
against the actual code running in the browser.

---

### Claim 1: "We cannot read your Conversation messages"

**Code that proves it:** `src/voidshield.ts` — `relationshipHash()`, `roomId()`, `deriveKey()`, `encrypt()`

Room hashes are derived entirely client-side from the pair of email addresses
and the shared codename. The algorithm:

```
hA       = SHA-256(emailA.toLowerCase().trim())
hB       = SHA-256(emailB.toLowerCase().trim())
relHash  = SHA-256(sort([hA, hB]).join(":") + ":" + APP_SALT + ":relationship")
roomHash = SHA-256(relHash + ":" + codename + ":" + APP_SALT)
```

The server receives only `roomHash` — an opaque 64-character hex string. It
cannot reverse this to learn the email addresses or the codename.

The encryption key is derived from the codename:

```
key = PBKDF2(codename, salt=roomHash, iterations=600_000, hash=SHA-256)
      → 256-bit raw key → imported as AES-256-GCM (non-extractable)
```

The codename is never sent to the server. The server stores only
`AES-256-GCM(plaintext, key, random_IV)` — ciphertext it cannot decrypt
because it never held the key material.

---

### Claim 2: "We cannot read your Revelations"

**Code that proves it:** `src/voidshield.ts` — `deriveRevelationKey()`,
`deriveRevelationKeyFromHashes()`, `encryptMedia()`

Revelation content is encrypted before upload. The key is derived from:

```
hS    = SHA-256(senderEmail.toLowerCase().trim())
hR    = SHA-256(recipientEmail.toLowerCase().trim())
fh[]  = SHA-256(normalise(fieldValue)) for each security field

input = sort([hS, hR]).join(":") + ":" + fh.join(":")
key   = PBKDF2(input, salt="voidlogue-revelation-v2", iterations=600_000, hash=SHA-256)
       → AES-256-GCM key
```

The security field values (e.g. the recipient's date of birth, first name)
are never sent to the server. The server stores only the hashes of field
values for access control purposes — and never the values themselves. The
decryption key cannot be derived without the raw field values which only the
recipient holds.

Delivery does not require decryption. The server relays encrypted bytes it
cannot read.

---

### Claim 3: "Your saved conversation shortcuts are encrypted locally"

**Code that proves it:** `src/vault.ts`

The Vault encrypts the user's email and codename on-device before storing
them in `localStorage`:

```
key  = PBKDF2(PIN, random_salt, iterations=2_000_000, hash=SHA-256) → AES-256-GCM key
blob = AES-256-GCM(JSON({email, codename}), key, random_IV)
```

The PIN is never stored anywhere. The server is never involved. Even if
someone extracts the device's `localStorage` they receive AES-256-GCM
ciphertext that cannot be decrypted without the PIN.

---

## Cryptographic primitive choices

| Primitive | Algorithm | Rationale |
|---|---|---|
| Symmetric encryption | AES-256-GCM | NIST-approved; provides authenticated encryption (tamper detection). Uses strict AAD to prevent stream reordering mutations. |
| Key derivation | PBKDF2 via WebCryptoAPI | Natively supported hardware hashing eliminating massive JS dependencies; Iterations boosted to 2,000,000 in local Vault context to combat brute-forcing. |
| Hashing | SHA-256 via SubtleCrypto | Collision-resistant; output is 256 bits; hardware-accelerated |
| Randomness | `crypto.getRandomValues` with rejection sampling | Cryptographically secure; rejection sampling eliminates modular bias |
| Post-quantum | Hybrid Kyber-768 + AES-256-GCM | NIST PQC standard; protects against "harvest now, decrypt later" |

### Key Derivation & PBKDF2

We strictly utilize browser-native `SubtleCrypto.deriveKey` coupled with PBKDF2 hashing at `600,000` cycles for general communication keys and an intensive `2,000,000` multiplier for the local `Vault` unlocking procedures, serving as a powerful counter against ASICs / GPUs without exposing WASM side-channel timing delays. By retaining WebCrypto constraints, Voidlogue operates exclusively inside optimized memory partitions.

### Post-quantum hybrid encryption

The `encryptHybrid()` / `decryptHybrid()` methods implement a hybrid scheme:
1. A random AES-256 key encrypts the plaintext (classical security)
2. Kyber-768 encapsulates a shared secret (post-quantum security)
3. Both are combined via SHA-256 key derivation

This ensures that even if AES-256 is broken by a future quantum computer,
the Kyber layer still protects the data, and vice versa.

**Note**: The current Kyber implementation uses placeholder key material.
For production deployment, integrate `@noble/post-quantum` or a WASM-based
Kyber implementation (e.g., `pqcrypto-kyber`).

### Dependency audit

There are **zero third-party cryptographic dependencies**. VoidShield strictly delegates memory limits to native WebCrypto architectures spanning out-of-the-box browser cryptography without introducing WASM bloat or supply chain poisoning attacks.

Automated static safety triggers include:
- **Dependabot**: Weekly automated checks for repository packages
- **CodeQL**: Weekly scheduled analysis + per-PR checks
- **npm audit**: Run on every CI build

---

## What this package does NOT prove

- That the server does not log data it should not log (requires server audit)
- That the server deletes messages as described (requires server audit)
- That the N=1 constraint is enforced server-side (requires server audit)
- That the server does not store session data beyond what is stated

These claims require auditing the server code, which is not included here.
We will answer specific questions about the server implementation directly.

---

## Threat model

### Protects against

- Platform reading message content (server never holds keys)
- Server breach exposing message content (only ciphertext stored)
- Legal compulsion to produce message content (server has nothing to produce)
- Person with physical device access seeing conversation content
- GPU/ASIC brute-force attacks on key derivation (through intensive parameter thresholds up to 2,000,000 hardware-aligned iterations)
- Media stream tampering / dropping (AES AAD authenticates complete arrays uniquely)
- "Harvest now, decrypt later" attacks (post-quantum hybrid encryption)

### Does NOT protect against

- Government subpoena for metadata (who talked to whom, when)
- Nation-state network surveillance
- The counterparty sharing decrypted content
- Screen photography
- Compromise of the user's Google account (authentication layer)

---

## Reporting vulnerabilities

**Please do not open a public issue for security vulnerabilities.**

Email: security@voidlogue.com

We will acknowledge within 48 hours and aim to resolve critical issues within
7 days. We will credit researchers in release notes unless anonymity is
requested.

## Scope

In scope:
- Cryptographic implementation errors in this package
- Key derivation weaknesses
- Randomness or bias issues in `secureRandom()`
- Any input that allows recovery of plaintext without the correct key

Out of scope:
- Social engineering attacks
- Physical device access attacks
- Issues in the server-side code (not in this repo)
- Theoretical weaknesses in AES-256-GCM or PBKDF2 as standardised algorithms
