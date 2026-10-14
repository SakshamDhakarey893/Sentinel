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

Server runs on http://localhost:8080

> The desktop app currently talks to the local backend the same way the browser does.
> Later we can start the Axum server from inside Tauri or connect to a remote instance.

## Current Status

- [x] Project scaffolding
- [x] Terminal-style UI mockup (client-side only)
- [x] **Tauri desktop integration**
- [ ] User registration + local key generation
- [ ] Signal Protocol integration
- [ ] WebSocket messaging
- [ ] Disappearing messages
- [ ] Backend persistence

## License

Private / Project internal for now.
