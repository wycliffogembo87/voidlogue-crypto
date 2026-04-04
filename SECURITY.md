# Security Policy

## What this package proves

This package is the open-source cryptographic layer for Voidlogue. It is
published so that the following privacy claims can be independently verified
against the actual code running in the browser.

---

### Claim 1: "We cannot read your Conversation messages"

**Code that proves it:** `src/voidshield.js` — `roomId()`, `deriveKey()`, `encrypt()`

Room hashes are derived entirely client-side from the pair of email addresses
and the shared codename. The algorithm:

```
hA       = SHA-256(emailA.toLowerCase().trim())
hB       = SHA-256(emailB.toLowerCase().trim())
roomHash = SHA-256(sort([hA, hB]).join(":") + ":" + codename + ":" + APP_SALT)
```

The server receives only `roomHash` — an opaque 64-character hex string. It
cannot reverse this to learn the email addresses or the codename.

The encryption key is derived from the codename:

```
key = PBKDF2(codename, salt=roomHash, iterations=600_000, hash=SHA-256)
     → AES-256-GCM key (non-extractable)
```

The codename is never sent to the server. The server stores only
`AES-256-GCM(plaintext, key, random_IV)` — ciphertext it cannot decrypt
because it never held the key material.

---

### Claim 2: "We cannot read your Revelations"

**Code that proves it:** `src/voidshield.js` — `deriveRevelationKey()`,
`deriveRevelationKeyFromHashes()`, `encryptMedia()`

Revelation content is encrypted before upload. The key is derived from:

```
hS    = SHA-256(senderEmail.toLowerCase().trim())
hR    = SHA-256(recipientEmail.toLowerCase().trim())
fh[]  = SHA-256(normalise(fieldValue)) for each security field

input = sort([hS, hR]).join(":") + ":" + fh.join(":")
key   = PBKDF2(input, salt="voidlogue-revelation-v1", iterations=600_000)
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

**Code that proves it:** `src/vault.js`

The Vault encrypts the user's email and codename on-device before storing
them in `localStorage`:

```
key  = PBKDF2(PIN, random_salt, iterations=600_000) → AES-256-GCM key
blob = AES-256-GCM(JSON({email, codename}), key, random_IV)
```

The PIN is never stored anywhere. The server is never involved. Even if
someone extracts the device's `localStorage` they receive AES-256-GCM
ciphertext that cannot be decrypted without the PIN.

---

## Cryptographic primitive choices

| Primitive | Algorithm | Rationale |
|---|---|---|
| Symmetric encryption | AES-256-GCM | NIST-approved; provides authenticated encryption (tamper detection) |
| Key derivation | PBKDF2, SHA-256, 600k iterations | Standardised; makes brute-force computationally expensive |
| Hashing | SHA-256 | Collision-resistant; output is 256 bits |
| Randomness | `crypto.getRandomValues` with rejection sampling | Cryptographically secure; rejection sampling eliminates modular bias |

No third-party cryptographic libraries are used. All operations use the
Web Crypto API built into the browser.

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

### Does NOT protect against

- Government subpoena for metadata (who talked to whom, when)
- Nation-state network surveillance
- The counterparty sharing decrypted content
- Screen photography
- A PIN brute-force attack on a stolen device (mitigated by lockout)
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
