# Sentinel Frontend + Desktop

Next.js terminal UI wrapped with **Tauri 2** for native desktop apps.

## Quick Start

```bash
npm install
```

### Browser

```bash
npm run dev
```
→ http://localhost:3000

### Desktop app (Tauri)

```bash
npm run tauri:dev
```

This opens a native window with the terminal UI.

### Build installers

```bash
npm run tauri:build
```

Binaries land in `src-tauri/target/release/bundle/`.

## Notes

- Configured for **static export** (`output: "export"`) — required by Tauri.
- Window title, size and dark theme are set in `src-tauri/tauri.conf.json`.
- The existing Rust Axum backend (`../backend`) still runs separately for now.
