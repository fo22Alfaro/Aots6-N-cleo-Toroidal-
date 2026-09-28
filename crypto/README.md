# AOTS6 Cryptographic Core
- SHA-256, HMAC-SHA-256, HKDF-SHA-256
- Ed25519 signatures
- X25519 key agreement
- AES-256-GCM and ChaCha20-Poly1305 AEAD
- ML-DSA-65 post-quantum signatures when the backend exposes them
- ML-KEM-768 post-quantum KEM when the backend exposes it
- public-key fingerprinting and revocation
- SHA-256 manifests
- GitHub Actions regression/security gate

No private keys, real tokens or deployment secrets are committed. PQ capability is reported rather than assumed.
