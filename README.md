# Sentinel

**End-to-end encrypted anonymous messaging** with a terminal aesthetic.

## Features (v1 goals)

- End-to-End Encryption (Signal Protocol — X3DH + Double Ratchet)
- 1:1 encrypted chat
- Disappearing / self-destructing messages
- Fully anonymous (username + passphrase, no phone/email)
- Forward secrecy & post-compromise security
- Metadata minimization
- **Desktop application** (Windows / macOS / Linux) via Tauri

## Tech Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Frontend  | Next.js 15 + TypeScript + Tailwind  |
| Desktop   | **Tauri 2** (Rust + system webview) |
| Backend   | Rust + Axum                         |
| Real-time | WebSockets                          |
| Crypto    | Signal Protocol + libsodium/WebCrypto |
| Database  | PostgreSQL + Redis (planned)        |

## UI

Terminal / CMD-window style:
- Dark background
- Monospace green/amber text
- Command-driven interface (`/help`, `/register`, `/new`, etc.)

## Project Structure

```
sentinel/
├── frontend/                 # Next.js + Tauri
│   ├── src/app/              # Terminal UI
│   ├── src-tauri/            # Tauri (desktop shell)
│   │   ├── src/              # Rust entry points
│   │   ├── capabilities/     # Permissions
│   │   ├── icons/            # App icons
│   │   ├── Cargo.toml
│   │   └── tauri.conf.json
│   └── package.json
├── backend/                  # Rust Axum server (relay)
└── README.md
```

## Prerequisites

- **Node.js** 18+
- **Rust** 1.77.2+ (install via [rustup](https://rustup.rs))
- System dependencies for Tauri:  
  See → https://v2.tauri.app/start/prerequisites/

## Getting Started

### 1. Frontend (web / Tauri)

```bash
cd frontend
npm install
```

#### Run as website (browser)

```bash
npm run dev
```
Open http://localhost:3000

#### Run as **desktop app** (recommended)

```bash
npm run tauri:dev
```

This starts the Next.js dev server and opens a native window.

#### Build installable desktop app

```bash
npm run tauri:build
```

Output appears in `frontend/src-tauri/target/release/bundle/`  
(Windows installer, macOS `.app` / `.dmg`, Linux AppImage / deb / rpm)

### 2. Backend (message relay)

```bash
cd backend
cargo run
```

Server runs on http://localhost:8080 by default.

### 3. Server Configuration & Remote Deployment

You can point the Sentinel frontend or desktop app to any local or remote relay server:

- **Via Environment Variables (`frontend/.env.local`):**
  ```env
  NEXT_PUBLIC_SENTINEL_API_URL=https://relay.yourdomain.com
  NEXT_PUBLIC_SENTINEL_WS_URL=wss://relay.yourdomain.com/ws
  ```
- **Via In-App Terminal Command (runtime override in Desktop App):**
  * View active server & latency: `/server`
  * Switch to remote server: `/server https://relay.yourdomain.com`
  * Reset to default: `/server reset`

## Current Status

- [x] Project scaffolding
- [x] Terminal-style UI mockup & UX commands
- [x] **Tauri desktop integration (Windows/macOS/Linux)**
- [x] Anti-screen capture protection (`SetWindowDisplayAffinity`)
- [x] User registration + local key generation
- [x] Signal Protocol integration (X3DH + Double Ratchet + AES-256-GCM)
- [x] WebSocket messaging + offline queue delivery
- [x] Disappearing / self-destructing messages
- [x] Constant-size message padding (Traffic analysis defense)
- [x] Safety numbers, visual emoji fingerprints, and QR verification
- [x] Zero-knowledge cloud vault backup & restore (AES-GCM + PBKDF2)
- [x] Dynamic server configuration (environment variables & runtime `/server` command)
- [ ] Backend SQL database persistence (SQLite / PostgreSQL)
- [ ] Cryptographic challenge-response authentication on relay

## License

Private / Project internal for now.
