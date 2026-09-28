# AOTS6 — Núcleo Simbiótico Vivo
## R1 Inventario
Primitivas permitidas: SHA-256, HMAC-SHA-256, HKDF-SHA-256, Ed25519, X25519, AES-256-GCM y ChaCha20-Poly1305. No hay cifrado, firma, KDF ni RNG casero. **PASS**
## R2 Integridad
Manifiestos SHA-256 detectan modificación, ausencia y archivos inesperados. **PASS**
## R3 Autenticidad
Ed25519 verifica firmas criptográficamente; la huella es SHA-256 de la clave pública. **PASS**
## R4 Confidencialidad
X25519+HKDF y AEAD con nonces de 96 bits generados por CSPRNG. **PASS**
## R5 Ciclo de vida
Registro sólo de claves públicas/huellas; revocación explícita con razón y timestamp. **PASS**
## R6 Despliegue
CI compila, ejecuta pruebas y busca patrones de secretos; el estado final queda condicionado al resultado observable de Actions. **PENDING-CI**
