# Chapto

Chapto is a modern, copy-paste, end-to-end encrypted chat app built as a web UI. It focuses on local key management, compact packets, one-time sessions, and session history. Networking is intentionally out of scope: you copy packets between clients (clipboard, file, or any channel) and Chapto handles encryption/decryption.

## Features

- Auto-manages username, UUID, and X25519 keypair
- Compact packet format (`CT1`) using JSON + zlib + base64url
- One-time sessions with session cards + ack packets
- Multiple sessions per peer are supported
- Encrypted message packets with X25519 + HKDF + ChaCha20-Poly1305
- Paste CT1 message packets to decode, or type plaintext to encrypt + copy
- Session packets (`S`/`A`) are handled in the "Receive Session" input
- Select any message and click `Copy` to copy plaintext or the CT1 packet
- Local account/session/message storage in `localStorage`

## Requirements

- Node.js 18+ (for Vite)

## Install

```bash
cd web
npm install
```

## Run (dev)

```bash
cd web
npm run dev
```

## Build

```bash
cd web
npm run build
```

## Preview production build

```bash
cd web
npm run preview
```

## Session Flow

1. Create a session and copy the session card.
2. Recipient pastes the session card into the "Receive Session" box; an ack packet is copied.
3. Initiator pastes the ack packet into the "Receive Session" box to activate the session.

## Packet Format (CT1)

All packets are:

```
CT1.<base64url(zlib(json_bytes))>
```

Minimal keys (short names for compactness):

- `v`: version (1)
- `t`: type (`S` session card, `A` ack, `M` message)

Session card (`S`) and ack (`A`):

- `s`: session id
- `d`: session name
- `u`: username
- `i`: uuid
- `k`: X25519 public key (base64url)
- `m`: optional note

Message:

- `s`: session id
- `f`: sender uuid
- `r`: recipient uuid
- `n`: nonce
- `c`: ciphertext

## Notes

- Encryption uses X25519 with `HKDF(SHA256)` and `ChaCha20-Poly1305` for AEAD.
- Messages are only decryptable by the recipient.
- Sessions are one-time; share a session card, then paste the ack packet back to the initiator to sync both sides.
- Accounts, sessions, and messages are stored in `localStorage` per browser.

## License

This project is licensed under the [GPL-3.0 license](./LICENSE).