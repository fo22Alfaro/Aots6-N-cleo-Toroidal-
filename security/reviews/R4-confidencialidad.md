# R4 — Confidencialidad y post-cuántica
PASS. X25519+HKDF-SHA-256 y AEAD (AES-256-GCM/ChaCha20-Poly1305) están implementados. Cuando el backend lo permite, ML-KEM-768 añade KEM post-cuántico; la prueba exige que encapsulación y decapsulación produzcan el mismo secreto. La disponibilidad PQ se detecta explícitamente y no se presupone.
