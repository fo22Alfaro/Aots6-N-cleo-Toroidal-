from __future__ import annotations
import hashlib,hmac,secrets
try:
 from cryptography.hazmat.primitives import hashes
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
 from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
 from cryptography.hazmat.primitives.kdf.hkdf import HKDF
 from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
 try:
  from cryptography.hazmat.primitives.asymmetric import mlkem,mldsa
  PQ_AVAILABLE=True
 except ImportError:
  PQ_AVAILABLE=False
 CRYPTOGRAPHY_AVAILABLE=True
except ImportError: CRYPTOGRAPHY_AVAILABLE=False

def sha256_hex(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def hmac_sha256(key:bytes,data:bytes)->bytes: return hmac.new(key,data,hashlib.sha256).digest()
def hkdf_sha256(ikm:bytes,*,salt:bytes=b"",info:bytes=b"AOTS6",length:int=32)->bytes:
 if not 0<length<=8160: raise ValueError("length out of HKDF-SHA256 range")
 if CRYPTOGRAPHY_AVAILABLE:
  return HKDF(algorithm=hashes.SHA256(),length=length,salt=salt or None,info=info).derive(ikm)
 salt=salt or b"\0"*32; prk=hmac_sha256(salt,ikm); out=b""; t=b""
 for i in range(1,(length+31)//32+1): t=hmac_sha256(prk,t+info+bytes([i])); out+=t
 return out[:length]
def secure_token(nbytes:int=32)->bytes:
 if nbytes<16: raise ValueError("minimum 128 bits of entropy")
 return secrets.token_bytes(nbytes)
def _require()->None:
 if not CRYPTOGRAPHY_AVAILABLE: raise RuntimeError("install requirements-crypto.txt")
def generate_signing_key():
 _require(); sk=Ed25519PrivateKey.generate(); return sk.private_bytes_raw(),sk.public_key().public_bytes_raw()
def sign(private_key:bytes,message:bytes)->bytes:
 _require(); return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)
def verify(public_key:bytes,message:bytes,signature:bytes)->bool:
 _require()
 try: Ed25519PublicKey.from_public_bytes(public_key).verify(signature,message); return True
 except Exception: return False
def generate_key_exchange_key():
 _require(); sk=X25519PrivateKey.generate(); return sk.private_bytes_raw(),sk.public_key().public_bytes_raw()
def derive_shared_key(private_key:bytes,peer_public_key:bytes,*,context:bytes=b"AOTS6-X25519")->bytes:
 _require(); shared=X25519PrivateKey.from_private_bytes(private_key).exchange(X25519PublicKey.from_public_bytes(peer_public_key)); return hkdf_sha256(shared,info=context)
def aead_encrypt(key:bytes,plaintext:bytes,*,aad:bytes=b"",nonce:bytes|None=None,algorithm:str="AESGCM"):
 _require()
 if len(key)!=32: raise ValueError("AEAD key must be 32 bytes")
 nonce=secrets.token_bytes(12) if nonce is None else nonce
 if len(nonce)!=12: raise ValueError("nonce must be 12 bytes")
 c=AESGCM(key).encrypt(nonce,plaintext,aad) if algorithm=="AESGCM" else ChaCha20Poly1305(key).encrypt(nonce,plaintext,aad) if algorithm=="CHACHA20POLY1305" else None
 if c is None: raise ValueError("unsupported AEAD algorithm")
 return nonce,c
def aead_decrypt(key:bytes,nonce:bytes,ciphertext:bytes,*,aad:bytes=b"",algorithm:str="AESGCM")->bytes:
 _require()
 if len(key)!=32 or len(nonce)!=12: raise ValueError("invalid key/nonce size")
 if algorithm=="AESGCM": return AESGCM(key).decrypt(nonce,ciphertext,aad)
 if algorithm=="CHACHA20POLY1305": return ChaCha20Poly1305(key).decrypt(nonce,ciphertext,aad)
 raise ValueError("unsupported AEAD algorithm")

def pq_capabilities()->dict[str,bool]:
    return {"ML-KEM-768": bool(CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE),
            "ML-DSA-65": bool(CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE)}

def generate_pq_signing_key():
    if not (CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE): raise RuntimeError("ML-DSA unavailable in current cryptography backend")
    sk=mldsa.MLDSA65PrivateKey.generate()
    return sk.private_bytes_raw(),sk.public_key().public_bytes_raw()

def pq_sign(private_key:bytes,message:bytes)->bytes:
    if not (CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE): raise RuntimeError("ML-DSA unavailable")
    return mldsa.MLDSA65PrivateKey.from_private_bytes(private_key).sign(message)

def pq_verify(public_key:bytes,message:bytes,signature:bytes)->bool:
    if not (CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE): raise RuntimeError("ML-DSA unavailable")
    try: mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature,message); return True
    except Exception: return False

def generate_pq_kem_key():
    if not (CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE): raise RuntimeError("ML-KEM unavailable")
    sk=mlkem.MLKEM768PrivateKey.generate()
    return sk.private_bytes_raw(),sk.public_key().public_bytes_raw()

def pq_encapsulate(public_key:bytes)->tuple[bytes,bytes]:
    if not (CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE): raise RuntimeError("ML-KEM unavailable")
    shared,ciphertext=mlkem.MLKEM768PublicKey.from_public_bytes(public_key).encapsulate()
    return ciphertext,shared

def pq_decapsulate(private_key:bytes,ciphertext:bytes)->bytes:
    if not (CRYPTOGRAPHY_AVAILABLE and PQ_AVAILABLE): raise RuntimeError("ML-KEM unavailable")
    return mlkem.MLKEM768PrivateKey.from_private_bytes(private_key).decapsulate(ciphertext)
