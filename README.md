# thr34ds

A cross-platform **threads** application for desktop and mobile, built with [Tauri v2](https://v2.tauri.app/) (Rust + web frontend).

## Features

- 💾 **Browser-local storage** – all data is stored locally on-device using SQLite (via `rusqlite`). No account, no server.
- ⏱ **Atomic clock sync** – on demand, the app queries public NTP servers (Cloudflare, Google, pool.ntp.org) that are disciplined by national atomic clocks, ensuring your timestamps are always accurate.
- 🖥 **All major platforms** – desktop (Windows, macOS, Linux) and mobile (iOS, Android) via Tauri v2.

## Tech stack

| Layer | Technology |
|-------|------------|
| Desktop/mobile shell | [Tauri v2](https://v2.tauri.app/) |
| Backend language | Rust |
| Local storage | SQLite via [`rusqlite`](https://crates.io/crates/rusqlite) (bundled) |
| Time sync | NTP via raw UDP (pool.ntp.org, Cloudflare time, Google time) |
| Frontend | Vanilla HTML / CSS / JavaScript |

## Project structure

```
thr34ds/
├── src/                  # Web frontend (HTML + CSS + JS)
│   ├── index.html
│   ├── main.js
│   └── styles.css
├── src-tauri/            # Rust backend
│   ├── src/
│   │   ├── main.rs       # Tauri entry point
│   │   ├── lib.rs        # Shared library root
│   │   ├── db.rs         # SQLite database (threads + messages)
│   │   ├── timesync.rs   # NTP atomic clock sync
│   │   └── commands.rs   # Tauri IPC commands
│   ├── Cargo.toml
│   ├── build.rs
│   └── tauri.conf.json
├── Cargo.toml            # Workspace root
└── package.json
```

## Getting started

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [Node.js](https://nodejs.org/) ≥ 18
- Tauri v2 system dependencies – see <https://v2.tauri.app/start/prerequisites/>

### Development

```bash
npm install
npm run dev
```

### Build for release

```bash
npm run build
```

Tauri bundles installers for the current host platform automatically.
For mobile builds, see the [Tauri mobile guide](https://v2.tauri.app/develop/mobile/).

## Data & privacy

All thread and message data lives exclusively in a local SQLite database on your device. Nothing is transmitted to any server. The optional time-sync feature sends a standard NTP UDP packet to the configured NTP pool servers – no application data is included.
