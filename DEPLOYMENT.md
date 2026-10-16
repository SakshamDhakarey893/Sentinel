# Sentinel Relay Server — Production Deployment & 24/7 Hosting Guide

This guide explains how to host the **Sentinel Message Relay** so it runs **24/7** with automated crash recovery and secure SSL/TLS encryption.

---

## Architecture Overview

```
                      ┌──────────────────────────────────────┐
                      │            Internet (WSS)            │
                      └──────────────────┬───────────────────┘
                                         │
                         https://relay.yourdomain.com
                                         │
                      ┌──────────────────▼───────────────────┐
                      │   Caddy Reverse Proxy (Port 443)     │
                      │   • Automated Let's Encrypt TLS      │
                      │   • Instant WebSocket proxying       │
                      └──────────────────┬───────────────────┘
                                         │  http://127.0.0.1:8080
                      ┌──────────────────▼───────────────────┐
                      │   Sentinel Axum Backend (Rust)       │
                      │   • Challenge-Response Auth (ECDH)   │
                      │   • Ephemeral WebSocket Hub          │
                      └──────────────────┬───────────────────┘
                                         │
                      ┌──────────────────▼───────────────────┐
                      │   Embedded SQLite (data/sentinel.db) │
                      │   • WAL mode (high concurrency)      │
                      │   • Atomic prekey consumption        │
                      └──────────────────────────────────────┘
```

---

## Option 1: 24/7 Cloud VPS Deployment (Docker Compose + Auto-SSL)
*Recommended for production. Works on any Linux VPS ($4-$5/month on Hetzner, DigitalOcean, Linode, AWS Lightsail, or Oracle Cloud free tier).*

### Step 1: Point your Domain DNS to the VPS
In your DNS provider (Cloudflare, Namecheap, GoDaddy, etc.), create an **A Record**:
* **Name:** `relay` (or `@` for root domain)
* **Target IP:** `<Your-VPS-Public-IP>`

### Step 2: Clone & Configure on your VPS
SSH into your VPS and run:
```bash
# Install Docker & Docker Compose (if not already installed)
curl -fsSL https://get.docker.com | sh

# Clone your repository
git clone https://github.com/SakshamDhakarey893/Sentinel.git
cd Sentinel/sentinel

# Configure domain and email for automatic SSL
cp .env.example .env
nano .env
```

Set your configuration in `.env`:
```env
DOMAIN=relay.yourdomain.com
CONTACT_EMAIL=admin@yourdomain.com

# Lock CORS origins for production (comma-separated):
ALLOWED_ORIGINS=https://relay.yourdomain.com,tauri://localhost,http://localhost:3000

# Session token expiry TTL (in seconds, default: 604800 = 7 days):
SESSION_TTL_SECS=604800
```

### Step 3: Launch with Docker Compose
```bash
docker compose up -d
```

Caddy will automatically provision a valid **Let's Encrypt TLS/SSL certificate** in ~5 seconds.

### Step 4: Verify Deployment
```bash
# Check container status
docker compose ps

# View live relay logs
docker compose logs -f

# Test the health endpoint over public HTTPS
curl https://relay.yourdomain.com/health
```

Expected output:
```json
{"status":"ok","version":"0.3.0","users_registered":0,"users_online":0}
```

---

## Option 2: 24/7 Hosting on a Windows Machine / Home Server
*Run the relay 24/7 in the background on your Windows PC without keeping a command prompt open.*

### Step 1: Build the Optimized Production Binary
In the repository root on Windows:
```cmd
cd sentinel\backend
cargo build --release
```
This produces `sentinel\backend\target\release\sentinel-backend.exe` (~4.7 MB, self-contained).

### Step 2: Install as a 24/7 Silent Background Service
Run the setup script:
```cmd
sentinel\scripts\install-windows-autostart.bat
```
* Registers `sentinel-backend.exe` to launch silently upon system boot/logon.
* Launches the process immediately in the background with no command prompt window.
* Verifies `http://127.0.0.1:8080/health`.

### Management Commands:
* **Stop Relay:** Run [`sentinel/scripts/stop-backend.bat`](file:///c:/Users/Lenovo/Desktop/Sentinel-Desktop_App/sentinel/scripts/stop-backend.bat)
* **Remove Auto-Start:** Run [`sentinel/scripts/uninstall-windows-autostart.bat`](file:///c:/Users/Lenovo/Desktop/Sentinel-Desktop_App/sentinel/scripts/uninstall-windows-autostart.bat)

---

## Option 3: Linux VPS Native Deployment (Systemd Service)
*Run directly on Linux without Docker.*

```bash
# 1. Compile backend on the server
cd sentinel/backend
cargo build --release

# 2. Copy binary and create sentinel user
sudo useradd -r -s /bin/false sentinel
sudo mkdir -p /opt/sentinel/data
sudo cp target/release/sentinel-backend /opt/sentinel/
sudo chown -R sentinel:sentinel /opt/sentinel

# 3. Install systemd service
sudo cp sentinel-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-relay

# 4. Check status & logs
sudo systemctl status sentinel-relay
journalctl -u sentinel-relay -f
```

---

## Connecting Desktop Clients to Your 24/7 Server

### Method A: In-App Terminal Command (Runtime)
Any user running the Sentinel desktop app can connect directly to your server:
```
/server https://relay.yourdomain.com
```
* The app automatically validates the connection, derives `wss://relay.yourdomain.com/ws`, tests latency, and reconnects in real time.
* Saved persistently in local storage across app restarts.
* Run `/server` to view status or `/server reset` to return to default.

### Method B: Environment Variable (Build-Time Default)
In `sentinel/frontend/.env.local`:
```env
NEXT_PUBLIC_SENTINEL_API_URL=https://relay.yourdomain.com
NEXT_PUBLIC_SENTINEL_WS_URL=wss://relay.yourdomain.com/ws
```

---

## Backup & Maintenance

### Backing Up the SQLite Database
SQLite with WAL mode can be safely backed up while the server is running 24/7:
```bash
# Using SQLite CLI online backup
sqlite3 /path/to/sentinel.db ".backup /path/to/sentinel_backup_$(date +%F).db"
```
Or for Docker:
```bash
docker compose exec sentinel-backend cp /app/data/sentinel.db /app/data/backup.db
```
