import hashlib,json,time
class RevocationRegistry:
 def __init__(self): self._records={}
 @staticmethod
 def fingerprint(public_key:bytes)->str: return hashlib.sha256(public_key).hexdigest()
 def register(self,public_key:bytes,*,label:str="")->str:
  fp=self.fingerprint(public_key); self._records[fp]={"status":"active","label":label,"created_at":int(time.time())}; return fp
 def revoke(self,fingerprint:str,*,reason:str)->None:
  if fingerprint not in self._records: raise KeyError("unknown key fingerprint")
  if not reason.strip(): raise ValueError("revocation reason required")
  self._records[fingerprint].update(status="revoked",reason=reason,revoked_at=int(time.time()))
 def is_active(self,fingerprint:str)->bool: return self._records.get(fingerprint,{}).get("status")=="active"
 def to_json(self)->str: return json.dumps(self._records,sort_keys=True,separators=(",",":"))
 @classmethod
 def from_json(cls,payload:str):
  x=cls(); x._records=json.loads(payload); return x
