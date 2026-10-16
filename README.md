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
| Database  | Embedded SQLite (WAL mode, bundled engine) |

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

#### Build installable desktop app (.exe / .msi)

You can build the production desktop application locally with a single click:
```cmd
sentinel\scripts\build-desktop-exe.bat
```
Or using npm directly:
```bash
cd frontend
npm run tauri:build
```
Output appears in `sentinel/dist/` or `frontend/src-tauri/target/release/bundle/nsis/`.

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

For 24/7 cloud server hosting via Docker Compose and automated Let's Encrypt SSL/TLS, see [DEPLOYMENT.md](DEPLOYMENT.md).

### 4. Automated CI/CD Releases (GitHub Actions)

Push a version tag to trigger an automated release build:
```bash
git tag v0.2.0
git push origin v0.2.0
```
GitHub Actions will automatically compile:
* **Sentinel-Desktop-Setup-x64.exe** (Windows installer)
* **Sentinel-Desktop-Portable-x64.zip** (Portable standalone executable)
* **sentinel-backend-windows-x64.zip** & **sentinel-backend-linux-x86_64.tar.gz**

And publish them directly to your repository's **GitHub Releases** with SHA-256 checksums.

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
- [x] Cryptographic challenge-response authentication on relay (ECDH + HMAC-SHA256 zero-knowledge proof)
- [x] Embedded SQLite database persistence (WAL mode, atomic one-time prekey consumption, auto-migration)
- [x] 24/7 Production Deployment stack (Docker Compose, Caddy auto-TLS reverse proxy, systemd, Windows background auto-start)
- [x] Automated GitHub Actions CI/CD release pipeline for Windows .exe releases & desktop bundling

## License

Private / Project internal for now.
