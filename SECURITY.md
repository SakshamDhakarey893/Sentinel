# Sentinel Security Policy & Threat Model

## Threat Model & Metadata Transparency

Sentinel provides client-side end-to-end encryption (E2EE) using the Signal Protocol (X3DH + Double Ratchet with AES-256-GCM) combined with cryptographic challenge-response authentication. To maintain realistic security expectations, this document specifies what the relay server can and cannot observe.

### What the Relay Server Can See
- **Usernames involved in connections**: The sender and recipient usernames for routed messages and active WebSocket sessions.
- **Approximate timing**: Connection timestamps, online status, and when messages are routed or queued.
- **Message ciphertext size & packet cadence**: Even with Sentinel's constant-length tier padding (128B to 4096B+), traffic analysis on packet frequency and high-volume burst patterns remains possible for an active network observer or compromised relay.
- **Client IP addresses**: Standard TCP/IP networking metadata (mitigated if using VPN or Tor).

### What the Relay Server Cannot See
- **Message plaintext**: All payload contents are encrypted client-side using ephemeral message keys negotiated via X3DH and Double Ratchet.
- **Private keys**: Identity private keys, signed prekey private keys, and one-time prekey private keys are generated locally and never transmitted across the network.
- **Master passphrases & Cloud Vault plaintext**: The relay and cloud storage never receive passphrases. Zero-knowledge cloud backups are encrypted client-side via PBKDF2 (600,000 iterations) and AES-256-GCM before upload.

### Metadata Minimization
"Metadata minimization" means Sentinel avoids collecting unnecessary user attributes (no phone numbers, email addresses, real names, device identifiers, read receipts, or typing indicators). It does **not** mean the relay is metadata-blind. The relay necessarily coordinates routing between usernames and stores unconsumed public prekeys and transient offline queues.

### Safety Number Verification
Because the relay acts as the public key directory, a compromised relay could theoretically attempt a man-in-the-middle (MITM) attack by serving unauthorized public keys to new contacts.
- **Recommendation**: Users should always verify **Safety Numbers** or **Visual Emoji Fingerprints** (`/verify <peer>`) out-of-band (e.g., in person, or via trusted secondary voice/video channel).
- Sentinel implements Trust-On-First-Use (TOFU) warning banners to detect when a contact's identity key unexpectedly changes.

---

## Key Storage Architecture (Desktop & Web)

- **Current Implementation**:
  - Private keys and session states are encrypted client-side using AES-256-GCM with a 256-bit key derived via PBKDF2 (100,000 iterations) from the user's local passphrase.
  - Encrypted ciphertext is stored in `localStorage`.
  - In memory, keys and ratchet states are scrubbed and zeroized (`zeroizeBuffer`) upon logout, app lock, or emergency panic purge (`/panic`).
- **Future Hardening Roadmap**:
  - Migration to native OS-backed hardware keychains (Windows Credential Manager / DPAPI, macOS Keychain, Linux Secret Service) using Tauri native plugins (`tauri-plugin-stronghold` or native keystore FFI).
  - Pure memory-only sessions with hardware security module (HSM) backing.

---

## Reporting a Security Vulnerability

If you discover a security vulnerability in Sentinel, please report it responsibly rather than opening a public issue. Contact the repository maintainers or security team directly with reproduction steps and cryptographic analysis.
