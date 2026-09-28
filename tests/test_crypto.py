import os,tempfile,unittest
from crypto.core import *
from crypto.manifest import manifest,verify_manifest
from crypto.revocation import RevocationRegistry
class CryptoTests(unittest.TestCase):
 def test_hash_kdf_hmac_rng(self):
  self.assertEqual(len(hmac_sha256(b"k",b"m")),32); self.assertEqual(len(hkdf_sha256(b"x",length=64)),64); self.assertEqual(len(secure_token()),32)
 def test_manifest(self):
  with tempfile.TemporaryDirectory() as d:
   open(os.path.join(d,"a"),"wb").write(b"x"); m=manifest(d); self.assertTrue(verify_manifest(d,m)[0]); open(os.path.join(d,"a"),"wb").write(b"y"); self.assertFalse(verify_manifest(d,m)[0])
 def test_revocation(self):
  r=RevocationRegistry(); fp=r.register(b"pub"); self.assertTrue(r.is_active(fp)); r.revoke(fp,reason="rotation"); self.assertFalse(r.is_active(fp))
 @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE,"cryptography unavailable")
 def test_ed25519_x25519_aead(self):
  a,b=generate_signing_key(); s=sign(a,b"payload"); self.assertTrue(verify(b,b"payload",s)); self.assertFalse(verify(b,b"tampered",s))
  x,xp=generate_key_exchange_key(); y,yp=generate_key_exchange_key(); k1=derive_shared_key(x,yp); k2=derive_shared_key(y,xp); self.assertEqual(k1,k2)
  n,c=aead_encrypt(k1,b"secret",aad=b"AOTS6"); self.assertEqual(aead_decrypt(k2,n,c,aad=b"AOTS6"),b"secret")
def test_pq_if_available(self):
  caps=pq_capabilities()
  if not all(caps.values()): self.skipTest("PQ backend unavailable")
  sk,pk=generate_pq_signing_key(); sig=pq_sign(sk,b"pq"); self.assertTrue(pq_verify(pk,b"pq",sig)); self.assertFalse(pq_verify(pk,b"bad",sig))
  sk,pk=generate_pq_kem_key(); ct,k1=pq_encapsulate(pk); k2=pq_decapsulate(sk,ct); self.assertEqual(k1,k2)

if __name__=="__main__": unittest.main()
