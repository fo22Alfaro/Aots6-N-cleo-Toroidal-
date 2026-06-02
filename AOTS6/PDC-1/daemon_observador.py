import time
import hashlib
from pathlib import Path

# Definicion de ruta segura solo para archivos
def calcular_hash_total():
    h = hashlib.sha512()
    # Filtramos para leer solo archivos, ignorando subdirectorios como 'logs'
    for f in sorted(Path.home().glob("AOTS6/PDC-1/auditoria/**/*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()[:40]

print(f"[*] Iniciando Daemon de Observación AOTS6...")
hash_base = calcular_hash_total()

while True:
    try:
        hash_actual = calcular_hash_total()
        if hash_actual != hash_base:
            print(f"[!] ALTERACIÓN DETECTADA EN BÓVEDA. RE-SINCRONIZANDO ...")
            hash_base = hash_actual
        time.sleep(5)
    except Exception as e:
        print(f"[ERROR] Auditoría interrumpida: {e}")
        time.sleep(5)

# Inyección de telemetría activa
def registrar_latido():
    with open("/data/data/com.termux/files/home/AOTS6/PDC-1/auditoria/logs/sys_audit.log", "a") as f:
        f.write(f"[LATIDO] Sistema operativo estable. Hash: {hash_actual}\n")
