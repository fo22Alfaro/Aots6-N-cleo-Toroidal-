import hashlib,pathlib
def manifest(root:str,exclude:set[str]|None=None)->dict[str,str]:
 base=pathlib.Path(root); excluded=exclude or set(); out={}
 for p in sorted(base.rglob("*")):
  if p.is_file() and str(p.relative_to(base)) not in excluded: out[str(p.relative_to(base))]=hashlib.sha256(p.read_bytes()).hexdigest()
 return out
def verify_manifest(root:str,expected:dict[str,str])->tuple[bool,list[str]]:
 actual=manifest(root); bad=[p for p,d in expected.items() if actual.get(p)!=d]; bad+=sorted(set(actual)-set(expected)); return not bad,bad
