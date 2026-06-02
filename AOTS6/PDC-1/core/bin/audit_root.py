import datetime
import os

root_path = os.path.expanduser("~/AOTS6/PDC-1")
log_file = os.path.join(root_path, "auditoria/logs/sys_audit.log")

with open(log_file, "a") as f:
    f.write(f"[{datetime.datetime.now()}] ENSAMBLAJE PROFESIONAL COMPLETADO. AUTORIDAD: ALFREDO JHOVANY ALFARO GARCIA\n")
print("[+] RAIZ DE AUDITORIA PROFESIONAL ESTABLECIDA.")
