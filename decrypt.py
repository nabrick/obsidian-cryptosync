## librerías
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import argparse
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

## Constantes
SALT_LENGTH = 16
IV_LENGTH = 12
PBKDF2_ITERATIONS = 250_000
CRYPTOSYNC_DIR = ".cryptosync"
MAP_LOCAL = ".cryptosync/vaultsync-map.enc"
CANARY_PATH = ".cryptosync/vaultsync.enc"
CANARY_TEXT = "vaultsync-ok"

## Funciones Crypto
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,)
    return kdf.derive(passphrase.encode("utf-8"))

def decrypt_buffer(passphrase: str, data: bytes) -> bytes:
    salt       = data[:SALT_LENGTH]
    iv         = data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = data[SALT_LENGTH + IV_LENGTH:]
    key        = derive_key(passphrase, salt)
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)

## Función de verificación
def verify_passphrase(vault_path: Path, passphrase: str) -> bool:
    canary_file = vault_path / CANARY_PATH
    if not canary_file.exists():
        print(f"Error: no se encontró el canary en {canary_file}")
        return False
    try:
        data  = canary_file.read_bytes()
        plain = decrypt_buffer(passphrase, data)
        return plain.decode("utf-8") == CANARY_TEXT
    except Exception:
        return False

## Función de mapa
def load_map(vault_path: Path, passphrase: str) -> dict:
    map_file = vault_path / MAP_LOCAL
    if not map_file.exists():
        print(f"Error: no se encontró el mapa en {map_file}")
        sys.exit(1)
    try:
        data  = map_file.read_bytes()
        plain = decrypt_buffer(passphrase, data)
        return json.loads(plain.decode("utf-8"))
    except Exception as e:
        print(f"Error leyendo mapa: {e}")
        sys.exit(1)

## Descrifrar vault completo
def decrypt_vault(vault_path: Path, output_path: Path, passphrase: str):
    path_map = load_map(vault_path, passphrase)

    if not path_map:
        print("El mapa está vacío — no hay archivos que descifrar.")
        return

    output_path.mkdir(parents=True, exist_ok=True)

    success = 0
    errors  = 0

    print(f"\nDescifrado de {len(path_map)} archivos...\n")

    for hashed_path, original_path in path_map.items():
        enc_file = vault_path / hashed_path

        if not enc_file.exists():
            print(f"  ⚠ No encontrado: {hashed_path}")
            errors += 1
            continue

        out_file = output_path / original_path
        out_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            data  = enc_file.read_bytes()
            plain = decrypt_buffer(passphrase, data)
            out_file.write_bytes(plain)
            print(f"  ✓ {original_path}")
            success += 1
        except Exception as e:
            print(f"  ✗ {original_path} — {e}")
            errors += 1

    print(f"\n{'─'*50}")
    print(f"✓ {success} archivos descifrados")
    if errors:
        print(f"✗ {errors} errores")
    print(f"Salida: {output_path}")


## Función principal
def main():
    parser = argparse.ArgumentParser(
        description="CryptoSync: descifra tu vault sin Obsidian")
    
    parser.add_argument(
        "--vault",
        required=True,
        help="Ruta al vault cifrado, donde está .cryptosync/")
    
    parser.add_argument(
        "--output",
        required=True,
        help="Ruta donde guardar los archivos descifrados")
    
    args = parser.parse_args()

    vault_path  = Path(args.vault).resolve()
    output_path = Path(args.output).resolve()

    if not vault_path.exists():
        print(f"Error: vault no encontrado en {vault_path}")
        sys.exit(1)

    if not (vault_path / CRYPTOSYNC_DIR).exists():
        print(f"Error: no se encontró .cryptosync/ en {vault_path}")
        print("Asegúrate de apuntar a la raíz del vault.")
        sys.exit(1)

    print(f"\nVault:  {vault_path}")
    print(f"Salida: {output_path}\n")

    # Pedir passphrase
    passphrase = getpass.getpass("Passphrase: ")

    print("\nVerificando passphrase...")
    if not verify_passphrase(vault_path, passphrase):
        print("✗ Passphrase incorrecta.")
        sys.exit(1)

    print("✓ Passphrase correcta\n")
    decrypt_vault(vault_path, output_path, passphrase)

if __name__ == "__main__":
    main()

## Ejemplo:
## py decrypt.py --vault "/ruta/a/tu/vault" --output "/ruta/de/salida"