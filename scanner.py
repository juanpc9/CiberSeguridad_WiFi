import sys
import os
import platform
import subprocess
import json
import re


# ─── Deteccion de plataforma ───────────────────────────────────────────────────

def detectar_plataforma():
    if os.environ.get("TERMUX_VERSION") or os.path.exists("/data/data/com.termux"):
        return "android"
    elif platform.system() == "Windows":
        return "windows"
    return "linux"

PLATAFORMA = detectar_plataforma()


# ─── Utilidades ────────────────────────────────────────────────────────────────

def limpiar():
    os.system("cls" if PLATAFORMA == "windows" else "clear")


def dbm_a_pct(dbm):
    if dbm >= -50: return 100
    if dbm <= -100: return 0
    return 2 * (dbm + 100)


def frecuencia_a_canal(freq):
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    return "?"


def barra(pct):
    b = int(pct / 10)
    return f"[{'#'*b}{'.'*(10-b)}] {pct:>3}%"


def clasificar_seguridad(raw):
    r = raw.upper()
    if "WPA3" in r:                          return "WPA3  [Muy segura]"
    if "WPA2" in r and "CCMP" in r:          return "WPA2  [Segura]"
    if "WPA2" in r and "TKIP" in r:          return "WPA2/TKIP [Debil]"
    if "WPA" in r:                           return "WPA   [Antigua]"
    if "WEP" in r:                           return "WEP   [Rota]"
    if "ESS" in r and "WPA" not in r and "WEP" not in r:
        return "ABIERTA [Sin cifrado]"
    return raw[:30] if raw else "Desconocida"


# ─── Escaneo Android (termux-wifi-scaninfo) ────────────────────────────────────

def escanear_android():
    try:
        r = subprocess.run(
            ["termux-wifi-scaninfo"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0 or not r.stdout.strip():
            print("\n  ERROR: termux-wifi-scaninfo fallo.")
            print("  Asegurate de tener:")
            print("  1. App 'Termux:API' instalada (F-Droid)")
            print("  2. pkg install termux-api")
            print("  3. Permiso de Ubicacion otorgado a Termux:API\n")
            return []

        datos = json.loads(r.stdout)

        # termux-wifi-scaninfo puede devolver lista de dicts o un solo dict
        if isinstance(datos, dict):
            datos = [datos]

        redes = []
        for d in datos:
            if not isinstance(d, dict):
                continue  # ignorar entradas malformadas
            pct   = dbm_a_pct(int(d.get("level", -100)))
            canal = frecuencia_a_canal(int(d.get("frequency", 0)))
            redes.append({
                "ssid":      d.get("ssid", "Oculto") or "Oculto",
                "bssid":     d.get("bssid", "N/A"),
                "senal_pct": pct,
                "canal":     str(canal),
                "seguridad": clasificar_seguridad(d.get("capabilities", "")),
                "raw_caps":  d.get("capabilities", ""),
            })
        return redes

    except FileNotFoundError:
        print("\n  ERROR: termux-wifi-scaninfo no encontrado.")
        print("  Ejecuta: pkg install termux-api\n")
        return []
    except json.JSONDecodeError:
        print("\n  ERROR: respuesta inesperada de termux-wifi-scaninfo\n")
        return []


# ─── Escaneo Windows (netsh) ───────────────────────────────────────────────────

def escanear_windows():
    try:
        r = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        salida = r.stdout

        if "permiso de ubicaci" in salida or "elevaci" in salida or "administrador" in salida.lower():
            print("\n  ACCION REQUERIDA:")
            print("  1. Activa Ubicacion: Inicio -> Configuracion -> Privacidad")
            print("     -> Servicios de ubicacion -> Activar")
            print("  2. Ejecuta como Administrador (clic derecho -> admin)\n")
            # Fallback: red conectada actual
            r2 = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, encoding="utf-8", errors="ignore"
            )
            return parsear_interfaces_windows(r2.stdout)

        return parsear_networks_windows(salida)

    except FileNotFoundError:
        print("  ERROR: netsh no disponible.\n")
        return []


def parsear_networks_windows(raw):
    redes = []
    bloques = re.split(r"SSID \d+ :", raw)[1:]
    for bloque in bloques:
        lineas = bloque.strip().splitlines()

        def ex(pat):
            for l in lineas:
                m = re.search(pat, l, re.IGNORECASE)
                if m: return m.group(1).strip()
            return "N/A"

        auth    = ex(r"Autenticaci[oó]n\s*:\s*(.+)")
        cifrado = ex(r"Cifrado\s*:\s*(.+)")
        caps    = f"[{auth}-{cifrado}]"

        senal_s = ex(r"Intensidad.*?:\s*(\d+)%")
        pct = int(senal_s) if senal_s != "N/A" else 0

        redes.append({
            "ssid":      lineas[0].strip() if lineas else "Oculto",
            "bssid":     ex(r"BSSID \d+\s*:\s*(.+)"),
            "senal_pct": pct,
            "canal":     ex(r"Canal\s*:\s*(\d+)"),
            "seguridad": clasificar_seguridad(caps),
            "raw_caps":  caps,
        })
    return redes


def parsear_interfaces_windows(raw):
    def ex(pat):
        m = re.search(pat, raw, re.IGNORECASE)
        return m.group(1).strip() if m else "N/A"

    ssid = ex(r"SSID\s*:\s*(.+)")
    if ssid == "N/A":
        return []

    auth    = ex(r"Autenticaci[oó]n\s*:\s*(.+)")
    cifrado = ex(r"Cifrado\s*:\s*(.+)")
    senal_s = ex(r"Se[ñn]al\s*:\s*(\d+)%")

    return [{
        "ssid":      ssid,
        "bssid":     ex(r"BSSID\s*:\s*(.+)"),
        "senal_pct": int(senal_s) if senal_s != "N/A" else 0,
        "canal":     ex(r"Canal\s*:\s*(\d+)"),
        "seguridad": clasificar_seguridad(f"[{auth}-{cifrado}]"),
        "raw_caps":  f"[{auth}-{cifrado}]",
    }]


# ─── Escaneo unificado ─────────────────────────────────────────────────────────

def escanear():
    if PLATAFORMA == "android":
        return escanear_android()
    else:
        return escanear_windows()


# ─── Display ───────────────────────────────────────────────────────────────────

SEP = "-" * 82

def mostrar_tabla(redes):
    if not redes:
        print("  Sin redes encontradas.\n")
        return

    ordenadas = sorted(redes, key=lambda r: r["senal_pct"], reverse=True)
    print(f"\n{'REDES WIFI DISPONIBLES':^82}")
    print(SEP)
    print(f"  {'#':<4} {'SSID':<22} {'SENAL':<25} {'SEGURIDAD':<22} CANAL")
    print(SEP)
    for i, r in enumerate(ordenadas, 1):
        ssid = r["ssid"][:21]
        seg  = r["seguridad"][:21]
        print(f"  {i:<4} {ssid:<22} {barra(r['senal_pct']):<25} {seg:<22} {r['canal']}")
    print(SEP)
    print(f"  Total: {len(redes)} redes\n")
    return ordenadas


def mostrar_detalle(ordenadas, num):
    if 1 <= num <= len(ordenadas):
        r = ordenadas[num - 1]
        print(f"\n{'─'*42}".replace("─", "-"))
        print(f"  SSID       : {r['ssid']}")
        print(f"  BSSID      : {r['bssid']}")
        print(f"  Senal      : {r['senal_pct']}%  {barra(r['senal_pct'])}")
        print(f"  Canal      : {r['canal']}")
        print(f"  Seguridad  : {r['seguridad']}")
        print(f"  Capacidades: {r['raw_caps']}")
        print(f"{'─'*42}\n".replace("─", "-"))
    else:
        print("  Numero fuera de rango.\n")


# ─── Menu ──────────────────────────────────────────────────────────────────────

def menu(ordenadas):
    while True:
        print("  [R] Reescanear  [D #] Detalle (ej: D 3)  [S] Salir")
        entrada = input("  > ").strip().upper()
        if entrada == "R":
            return True
        if entrada == "S":
            print("\n  Hasta luego.\n")
            return False
        if entrada.startswith("D "):
            try:
                mostrar_detalle(ordenadas, int(entrada.split()[1]))
            except (ValueError, IndexError):
                print("  Uso: D <numero>")
        else:
            print("  Opcion no valida.")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    limpiar()
    print(f"\n  WiFi Scanner - Proyecto Ciberseguridad")
    print(f"  Plataforma: {PLATAFORMA.upper()}")
    print(f"  Solo lectura pasiva - no modifica redes.\n")

    continuar = True
    ordenadas = []
    while continuar:
        print("  Escaneando...\n")
        redes = escanear()
        ordenadas = mostrar_tabla(redes) or []
        continuar = menu(ordenadas)
        if continuar:
            limpiar()


if __name__ == "__main__":
    main()
