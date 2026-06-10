<div align="center">
  <br/>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/badge/OXYPHER-00ff88?style=for-the-badge&labelColor=0a0a0a&logo=lock&logoColor=00ff88">
    <img alt="OXYPHER" src="https://img.shields.io/badge/OXYPHER-00aa66?style=for-the-badge&labelColor=ffffff&logo=lock&logoColor=00aa66" width="320">
  </picture>
  <br/><br/>
  <p><strong>End-to-end encrypted P2P file transfer · Zero servers · Zero logs</strong></p>

  <br/>

  <a href="#features"><img alt="Features" src="https://img.shields.io/badge/Features-0a0a0a?style=flat-square"></a>
  <a href="#security-architecture"><img alt="Security" src="https://img.shields.io/badge/Security-0a0a0a?style=flat-square"></a>
  <a href="#how-it-works"><img alt="How it works" src="https://img.shields.io/badge/How_It_Works-0a0a0a?style=flat-square"></a>
  <a href="#tech-stack"><img alt="Tech Stack" src="https://img.shields.io/badge/Tech_Stack-0a0a0a?style=flat-square"></a>
  <a href="#getting-started"><img alt="Getting started" src="https://img.shields.io/badge/Getting_Started-0a0a0a?style=flat-square"></a>
  <a href="#development"><img alt="Development" src="https://img.shields.io/badge/Development-0a0a0a?style=flat-square"></a>

  <br/>

  <p>
    <img alt="License" src="https://img.shields.io/badge/license-MIT-00ff88?style=flat-square&labelColor=0a0a0a">
    <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.8-3178c6?style=flat-square&labelColor=0a0a0a">
    <img alt="React" src="https://img.shields.io/badge/React-19-61dafb?style=flat-square&labelColor=0a0a0a">
    <img alt="Vite" src="https://img.shields.io/badge/Vite-6-ffc107?style=flat-square&labelColor=0a0a0a">
    <img alt="WebRTC" src="https://img.shields.io/badge/WebRTC-P2P-ff3e00?style=flat-square&labelColor=0a0a0a">
    <img alt="WebCrypto" src="https://img.shields.io/badge/WebCrypto-AES_256-ff6b6b?style=flat-square&labelColor=0a0a0a">
    <img alt="PFS" src="https://img.shields.io/badge/PFS-Double_Ratchet-ae8ff7?style=flat-square&labelColor=0a0a0a">
  </p>

  <br/>
</div>

---

<br/>

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/webrtc.svg">
    <img alt="OXYPHER Demo" src="https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/webrtc.svg" width="48">
  </picture>
</div>

<br/>

**OXYPHER** is a zero-knowledge, peer-to-peer file transfer application that runs entirely in your browser. Files are encrypted before they leave your device, transmitted directly via WebRTC, and decrypted only on the recipient's device. No intermediaries ever see your data — not even the signaling server.

```
Sender                         Receiver
   │                              │
   │  ┌──────────────────────┐    │
   ├──┤ 1. Derive session    │    │
   │  │    keys from password │    │
   │  └──────────┬───────────┘    │
   │             │                │
   │  ┌──────────▼───────────┐    │
   ├──┤ 2. Create PeerJS     │    │
   │  │    signaling channel  │    │
   │  └──────────┬───────────┘    │
   │             │                │
   │  ┌──────────▼───────────┐    │
   ├──┤ 3. ECDH P-256 key    │    │
   │  │    exchange (PFS)     │────┤
   │  └──────────┬───────────┘    │
   │             │                │
   │  ┌──────────▼───────────┐    │
   ├──┤ 4. Encrypt chunks    │    │
   │  │    AES-256-GCM + HMAC│    │
   │  │    over WebRTC       │────┤
   │  └──────────┬───────────┘    │
   │             │                │
   │  ┌──────────▼───────────┐    │
   ├──┤ 5. Verify HMAC &     │    │
   │  │    decrypt & assemble │    │
   │  └──────────────────────┘    │
```

<br/>

---

## Features

| | |
|---|---|
| **🔒 End-to-End Encrypted** | AES-256-GCM with 128-bit authentication tags |
| **🔑 Password-Derived Keys** | HKDF-SHA256 key derivation from a shared secret |
| **🔄 Perfect Forward Secrecy** | ECDH P-256 with Double Ratchet key rotation every 100 chunks |
| **📦 No Servers** | Pure P2P via WebRTC — signaling only at connection time |
| **🗑️ Zero Persistence** | Everything lives in memory; nothing is stored |
| **📱 QR Code Sharing** | Built-in QR code generator for easy link transfer |
| **🕵️ No Accounts** | Anonymous — no registration, no identity, no tracking |
| **🔀 Entropy Obfuscation** | 10% dummy chunks mixed with real data to frustrate traffic analysis |
| **🌐 Cross-Browser** | Works on any modern browser with WebCrypto + WebRTC support |
| **📂 Up to 4 GB** | File size limit limited only by browser memory |

---

## Security Architecture

```
                         ┌─────────────────────────────────────────┐
                         │          Shared Secret (Password)        │
                         └────────────────┬────────────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────────────┐
                         │            HKDF-SHA-256                  │
                         │  (salt = empty, info = context string)   │
                         └────┬────────────┬────────────┬───────────┘
                              │            │            │
                              ▼            ▼            ▼
                    ┌─────────────┐ ┌──────────┐ ┌─────────────┐
                    │  Room ID    │ │ AES-256  │ │  HMAC key   │
                    │  (16 bytes) │ │  key     │ │  (32 bytes) │
                    └─────────────┘ └────┬─────┘ └──────┬──────┘
                                         │              │
                                         ▼              ▼
                          ┌──────────────────────────────────┐
                          │     ECDH P-256 Key Exchange       │
                          │   (ephemeral keys, one-shot)       │
                          └──────────────┬───────────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────────┐
                          │     HKDF-Combine (AES+HMAC+ECDH)  │
                          └──────────────┬───────────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────────┐
                          │    Session AES-256-GCM Key        │
                          │    Session HMAC-SHA256 Key        │
                          │    ↻ Rotated every 100 chunks      │
                          │      (Double Ratchet algorithm)    │
                          └──────────────────────────────────┘
```

### Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|---|---|---|
| **KDF** | HKDF-SHA-256 | Key derivation from password |
| **Symmetric Encryption** | AES-256-GCM (128-bit tag) | Per-chunk encryption |
| **Integrity** | HMAC-SHA-256 | Per-chunk tamper verification |
| **Key Exchange** | ECDH P-256 (ephemeral) | Perfect Forward Secrecy |
| **Ratchet** | ECDH Double Ratchet | Key rotation during transfer |
| **Hashing** | SHA-256 | File integrity verification |
| **Entropy** | `crypto.getRandomValues()` | All IVs and key material |

---

## How It Works

### Sender Flow

1. **Select** a file and enter a secret password
2. **Derive** encryption keys + a unique Room ID from the password via HKDF
3. **Generate** a shareable link and QR code containing the Room ID
4. **Share** the link and password through separate channels (out of band)
5. **Wait** for the recipient to connect via PeerJS signaling
6. **Authenticate** via ECDH P-256 key exchange (combining ephemeral keys with the derived keys)
7. **Stream** encrypted chunks over WebRTC data channel with periodic key rotation

### Receiver Flow

1. **Open** the link (contains the Room ID)
2. **Enter** the secret password (shared out of band)
3. **Derive** the same keys → verify Room ID matches
4. **Connect** to the sender via PeerJS signaling
5. **Authenticate** via ECDH P-256 key exchange
6. **Receive** encrypted chunks, verify HMAC, decrypt, assemble
7. **Verify** SHA-256 file hash → auto-download

---

## Tech Stack

| Technology | Version | Role |
|---|---|---|
| [React](https://react.dev) | 19 | UI framework |
| [TypeScript](https://www.typescriptlang.org) | 5.8 | Type safety |
| [Vite](https://vitejs.dev) | 6 | Build tool & dev server |
| [PeerJS](https://peerjs.com) | 1.5 | WebRTC signaling abstraction |
| [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) | — | All cryptographic operations |
| [WebRTC API](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API) | — | P2P data channel transport |
| QR Code (custom) | — | Inline QR generation (no dependencies) |

---

## Getting Started

### Prerequisites

- Node.js ≥ 18
- npm ≥ 9

### Install

```bash
git clone https://github.com/yourusername/oxy
cd oxy
npm install
```

### Development

```bash
npm run dev
```

Opens at `http://localhost:5173/oxy/` (or next available port).

### Production Build

```bash
npm run build
npm run preview
```

---

## Development

### Project Structure

```
oxy/
├── src/
│   ├── App.tsx          # Main application component & P2P logic
│   ├── crypto.ts         # All cryptographic operations
│   ├── qrcode.ts         # QR code generation (pure TypeScript)
│   ├── style.css         # Dark mode UI styles
│   ├── main.tsx          # React entry point
│   └── vite-env.d.ts     # Vite type declarations
├── assets/               # Static assets
├── index.html            # HTML entry point
├── package.json          # Dependencies & scripts
├── tsconfig.json         # TypeScript configuration
└── vite.config.ts        # Vite configuration
```

### Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start development server with HMR |
| `npm run build` | Type-check and build for production |
| `npm run preview` | Preview production build locally |

---

## Security Considerations

- **The password must be shared out of band** (e.g., encrypted chat, phone call). Anyone with the link + password can decrypt the file.
- **No metadata protection**: while the file content is encrypted, an observer could see that an OXYPHER transfer occurred and estimate its size.
- **Browser security**: the security of this application depends entirely on the security of your browser's WebCrypto implementation.
- **No forward secrecy after session ends**: the Double Ratchet provides PFS during the transfer, but if an attacker captures the password and the full WebRTC stream, they could derive the base keys. Always use a strong, unique password.
- **STUN is optional**: by default STUN is disabled. Enable it only if the P2P connection cannot be established (you are behind a NAT that prevents direct connection).

---

## License

[MIT](LICENSE) © 2025

---

<div align="center">
  <sub>Built with 🔒 by people who believe privacy is a right, not a feature.</sub>
  <br/><br/>
  <img alt="OXYPHER" src="https://img.shields.io/badge/──OXYPHER──-0a0a0a?style=flat-square&labelColor=0a0a0a&color=00ff88">
</div>
