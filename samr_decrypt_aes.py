#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
samr_decrypt_aes.py
===================
Descifrado pasivo del cambio de credenciales sobre MS-SAMR con cifrado AES
(SamrSetInformationUser2 / UserInternal8Information -> SAMPR_ENCRYPTED_PASSWORD_AES,
esquema AEAD-AES-256-CBC-HMAC-SHA512). Post-parche CVE-2021-33757 (KB5004605).

Es el gemelo AES de samr_decrypt.py (que cubre el caso RC4/UserInternal4). NO los mezcles.

Esquema (MS-SAMR 3.2.2.4 + 'AEAD-AES-256-CBC-HMAC-SHA512 Constants'):
    CEK (Content Encryption Key) = clave de sesion SMB de 16 bytes
        - SamrSetInformationUser2 / UserInternal8  -> CEK = clave de sesion SMB   (PBKDF2Iterations = 0)
        - SamrUnicodeChangePasswordUser4           -> CEK = PBKDF2(NT-hash pwd antigua, Salt, Iterations)  (5000..1e6)
    enc_key = HMAC-SHA512(CEK, "Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16\\0")[:32]
    mac_key = HMAC-SHA512(CEK, "Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16\\0")   (64 B)
    plaintext = AES-256-CBC_decrypt(enc_key, IV=Salt, Cipher)          # 528 B (datos + relleno PKCS7)
    AuthData  = HMAC-SHA512(mac_key, 0x01 || Salt || Cipher || 0x01)    # verificacion de integridad
    password  = layout AES (verificado): [uint16LE longitud][contrasena UTF-16LE] al INICIO del plaintext
                (distinto a RC4, donde la contrasena va al final)

Requiere: pycryptodome (Crypto.Cipher.AES).  En Kali suele venir con Impacket.

Uso (manual, si ya tienes la clave de sesion / CEK):
    python3 samr_decrypt_aes.py manual \
        --cek     <hex 16B>   (o --ntlm-sesskey <16B> --preauth <64B> para derivarla en SMB 3.1.1) \
        --salt    <hex 16B> \
        --cipher  <hex 528B> \
        --auth-data <hex 64B>   (opcional, para verificar el MAC)

Uso (pcap):
    python3 samr_decrypt_aes.py pcap --pcap captura.pcapng --keytab servicio.keytab
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import struct
import subprocess
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("[-] Falta pycryptodome. Instala:  pip install pycryptodome")


# --------------------------------------------------------------------------- #
#  Constantes MS-SAMR (AEAD-AES-256-CBC-HMAC-SHA512)                           #
# --------------------------------------------------------------------------- #

# Cadenas ANSI terminadas en NULL (el nulo cuenta: longitudes 61 y 54).
SAM_AES256_ENC_KEY_STRING = b"Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16\x00"
SAM_AES256_MAC_KEY_STRING = b"Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16\x00"
VERSIONBYTE = b"\x01"          # Versionbyte
VERSIONBYTE_LEN = b"\x01"      # versionbyte_length = 1


# --------------------------------------------------------------------------- #
#  Derivacion de la clave de sesion SMB 3.1.1 (para obtener el CEK)            #
# --------------------------------------------------------------------------- #

def kdf_counter_mode(ki: bytes, label: bytes, context: bytes, length_bits: int = 128) -> bytes:
    """SP800-108 modo contador con HMAC-SHA256 (igual que en el caso RC4)."""
    data = struct.pack(">I", 1) + label + b"\x00" + context + struct.pack(">I", length_bits)
    return hmac.new(ki, data, hashlib.sha256).digest()[: length_bits // 8]


def application_key(ntlm_sesskey: bytes, preauth_hash: bytes | None):
    """
    ApplicationKey de SMB (la 'clave de sesion SMB de 16 bytes' de MS-SAMR).
    SMB 3.1.1 -> KDF(sesskey, "SMBAppKey\\0", preauth). Sin preauth -> SMB 3.0 (SMB2APP).
    """
    if preauth_hash:
        return kdf_counter_mode(ntlm_sesskey, b"SMBAppKey\x00", preauth_hash)
    return kdf_counter_mode(ntlm_sesskey, b"SMB2APP\x00", b"SmbRpc\x00")


# --------------------------------------------------------------------------- #
#  Nucleo AEAD-AES-256-CBC-HMAC-SHA512                                          #
# --------------------------------------------------------------------------- #

def aead_keys(cek: bytes):
    """Deriva (enc_key 32B, mac_key 64B) del CEK."""
    enc_key = hmac.new(cek, SAM_AES256_ENC_KEY_STRING, hashlib.sha512).digest()[:32]
    mac_key = hmac.new(cek, SAM_AES256_MAC_KEY_STRING, hashlib.sha512).digest()
    return enc_key, mac_key


def compute_authdata(mac_key: bytes, salt: bytes, cipher: bytes) -> bytes:
    """AuthData = HMAC-SHA512(mac_key, versionbyte || IV || Cipher || versionbyte_length)."""
    return hmac.new(mac_key, VERSIONBYTE + salt + cipher + VERSIONBYTE_LEN, hashlib.sha512).digest()


def extract_password(plaintext: bytes):
    """
    Formato del plaintext AES (verificado empiricamente, distinto al de RC4):
        [uint16 LE: longitud de la contrasena en bytes] [contrasena UTF-16LE] [relleno + PKCS7]
    (En RC4 la contrasena va al FINAL; en AES va al INICIO, precedida por su longitud.)
    Devuelve (password, length) o None si no es valido.
    """
    if len(plaintext) < 2:
        return None
    length = struct.unpack("<H", plaintext[0:2])[0]
    if length < 2 or length > 512 or length % 2 != 0 or 2 + length > len(plaintext):
        return None
    try:
        pwd = plaintext[2:2 + length].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return (pwd, length) if pwd.isprintable() else None


def decrypt_aes(cek: bytes, salt: bytes, cipher: bytes, auth_data: bytes | None = None, verbose=True):
    """
    Descifra un SAMPR_ENCRYPTED_PASSWORD_AES dado el CEK (clave de sesion SMB).
    Devuelve (password, dict_info) o None.
    """
    enc_key, mac_key = aead_keys(cek)

    mac_ok = None
    if auth_data:
        mac_ok = hmac.compare_digest(compute_authdata(mac_key, salt, cipher), auth_data)

    if len(cipher) % 16 != 0:
        return None
    plaintext = AES.new(enc_key, AES.MODE_CBC, salt).decrypt(cipher)
    res = extract_password(plaintext)
    if not res:
        return None
    pwd, length = res
    if verbose:
        print(f"[+] CEK valido: {cek.hex()}")
        print(f"    enc_key : {enc_key.hex()}")
        print(f"    MAC     : {'OK' if mac_ok else ('NO VERIFICADO' if mac_ok is None else 'INVALIDO')}")
        print(f"    long pwd: {length} bytes ({length // 2} caracteres)")
    return pwd, dict(cek=cek, mac_ok=mac_ok, length=length)


def try_ceks(ceks, salt, cipher, auth_data=None):
    """Prueba varios CEK candidatos; devuelve el primero que produzca una contrasena valida.
    Si hay auth_data, exige ademas MAC valido (validacion exacta, sin falsos positivos)."""
    for cek in ceks:
        res = decrypt_aes(cek, salt, cipher, auth_data, verbose=False)
        if res:
            pwd, info = res
            if auth_data and info["mac_ok"] is False:
                continue
            decrypt_aes(cek, salt, cipher, auth_data)   # reimprime con verbose
            return pwd, info
    return None


# --------------------------------------------------------------------------- #
#  Extraccion desde el pcap (tshark)                                           #
# --------------------------------------------------------------------------- #

def _tshark(args, keytab=None, nt_password=None):
    cmd = ["tshark"] + args
    if keytab:
        cmd += ["-o", "kerberos.decrypt:TRUE", "-K", keytab]
    if nt_password:
        cmd += ["-o", f"ntlmssp.nt_password:{nt_password}"]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        sys.exit("[-] tshark no esta en el PATH.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[-] tshark fallo:\n{e.stderr}")


def fields(pcap, dfilter, flds, keytab=None, nt_password=None):
    args = ["-r", pcap, "-Y", dfilter, "-T", "fields"]
    for f in flds:
        args += ["-e", f]
    out = _tshark(args, keytab, nt_password)
    return [ln.split("\t") for ln in out.splitlines() if ln.strip()]


def parse_bytes_field(s: str) -> bytes:
    """Convierte el valor de un campo de bytes de tshark a bytes.
    Admite 'd1,d2,d3' (decimales), 'aa:bb:cc' (hex) o 'aabbcc' (hex)."""
    s = s.strip()
    if not s:
        return b""
    if "," in s:
        return bytes(int(x) for x in s.split(","))
    if ":" in s:
        return bytes.fromhex(s.replace(":", ""))
    return bytes.fromhex(s)


def session_keys_for_stream(pcap, stream, keytab, nt_password):
    """NTLMSSP SessionKeys del stream (caso NTLM). Vacio si la auth es Kerberos."""
    flt = f"tcp.stream=={stream} && _ws.expert" if stream is not None else "_ws.expert"
    keys = []
    for row in fields(pcap, flt, ["_ws.expert.message"], keytab, nt_password):
        for m in re.findall(r"NTLMSSP SessionKey \(([0-9a-fA-F]{32})\)", row[0] if row else ""):
            keys.append(bytes.fromhex(m))
    return list(dict.fromkeys(keys))


def kerberos_keys_for_stream(pcap, stream, keytab, nt_password):
    """
    Claves Kerberos que Wireshark aprende al descifrar la sesion (con el keytab que
    contiene la clave del servicio/DC). Incluye subclaves del AP-REQ/AP-REP y la clave
    del ticket; la clave de sesion SMB es una de ellas (tipicamente la del AP-REP).
    """
    flt = f"tcp.stream=={stream} && kerberos.keyvalue" if stream is not None else "kerberos.keyvalue"
    keys = []
    for row in fields(pcap, flt, ["kerberos.keyvalue"], keytab, nt_password):
        for k in (row[0] if row else "").split(","):
            k = k.strip()
            if len(k) in (32, 64):     # AES128 (16B) o AES256 (32B) en hex
                keys.append(bytes.fromhex(k))
    return list(dict.fromkeys(keys))


def preauth_hashes_for_stream(pcap, stream, keytab, nt_password):
    flt = f"tcp.stream=={stream} && smb2.preauth_hash" if stream is not None else "smb2.preauth_hash"
    hs = []
    for row in fields(pcap, flt, ["smb2.preauth_hash"], keytab, nt_password):
        for h in (row[0] if row else "").split(","):
            h = h.strip()
            if len(h) == 128:
                hs.append(bytes.fromhex(h))
    return list(dict.fromkeys(hs))


AES_FIELDS = {
    "auth": "samr.samr_EncryptedPasswordAES.auth_data",
    "salt": "samr.samr_EncryptedPasswordAES.salt",
    "cipher": "samr.samr_EncryptedPasswordAES.cipher",
    "iters": "samr.samr_EncryptedPasswordAES.PBKDF2Iterations",
}


def extract_from_pcap(pcap, keytab, nt_password):
    print(f"[*] Extrayendo campos AES de {pcap} con tshark ...")

    rows = fields(pcap, "samr.opnum==58 && samr.samr_EncryptedPasswordAES.salt",
                  ["frame.number", "tcp.stream", AES_FIELDS["auth"], AES_FIELDS["salt"],
                   AES_FIELDS["cipher"], AES_FIELDS["iters"]], keytab, nt_password)
    if not rows:
        sys.exit("[-] No se encontro SetUserInfo2 con SAMPR_ENCRYPTED_PASSWORD_AES "
                 "(UserInternal8). Verifica que el cambio use el esquema AES.")
    r = rows[0]
    frame, stream = r[0], (r[1] if len(r) > 1 and r[1] else None)
    auth_data = parse_bytes_field(r[2]) if len(r) > 2 else b""
    salt = parse_bytes_field(r[3]) if len(r) > 3 else b""
    cipher = parse_bytes_field(r[4]) if len(r) > 4 else b""
    iters = int(r[5]) if len(r) > 5 and r[5] else 0

    print(f"    SAMR setinfo AES   : frame {frame}, tcp.stream {stream}")
    print(f"    auth_data          : {len(auth_data)} bytes")
    print(f"    salt (IV)          : {salt.hex()}")
    print(f"    cipher             : {len(cipher)} bytes")
    print(f"    PBKDF2Iterations   : {iters}")

    if iters != 0:
        print("[!] PBKDF2Iterations != 0: el CEK deriva de la contrasena ANTIGUA "
              "(SamrUnicodeChangePasswordUser4), no de la clave de sesion. Se necesita "
              "el NT-hash de la contrasena previa; el descifrado pasivo por clave de sesion no aplica.")

    # Semillas de clave de sesion del stream: NTLMSSP (caso NTLM) y/o claves Kerberos
    # aprendidas (caso Kerberos). La clave de sesion SMB es una de estas (o su 1ros 16 B).
    ntlm_keys = session_keys_for_stream(pcap, stream, keytab, nt_password)
    kerb_keys = kerberos_keys_for_stream(pcap, stream, keytab, nt_password)
    preauths = preauth_hashes_for_stream(pcap, stream, keytab, nt_password)

    seeds = []
    for k in ntlm_keys + kerb_keys:
        seeds.append(k)              # tal cual (16 B)
        if len(k) > 16:
            seeds.append(k[:16])     # primeros 16 B (clave de sesion SMB de una clave AES256)
    seeds = list(dict.fromkeys(seeds))

    ceks = []
    for sk in seeds:
        for pre in preauths:
            ceks.append(application_key(sk, pre))     # SMB 3.1.1 (SMBAppKey + preauth)
        ceks.append(application_key(sk, None))         # SMB 3.0 (SMB2APP)
        ceks.append(sk if len(sk) == 16 else sk[:16])  # SMB 2.x (clave directa)
    ceks = list(dict.fromkeys(ceks))

    print(f"    claves NTLM/Kerberos: {len(ntlm_keys)} / {len(kerb_keys)}   preauth: {len(preauths)}")
    print(f"    CEK candidatos     : {len(ceks)}")
    if not ceks:
        print()
        print("[-] No se obtuvo ninguna clave de sesion del stream. Verifica: (a) el keytab "
              "contiene la clave del SERVICIO (cuenta de maquina del DC) para descifrar el "
              "Kerberos; (b) la captura incluye el SMB2 Negotiate (necesario para el preauth "
              "de SMB 3.1.1). Alternativa: pasa la clave con --cek.")
        sys.exit(2)

    return ceks, salt, cipher, auth_data


# --------------------------------------------------------------------------- #
#  CLI                                                                          #
# --------------------------------------------------------------------------- #

def hexarg(s):
    return bytes.fromhex(s.replace(" ", "").replace(":", ""))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode", required=True)

    m = sub.add_parser("manual", help="Descifrar con valores en hex")
    m.add_argument("--cek", "--session-key", dest="cek", type=hexarg,
                   help="Clave de sesion SMB de 16 B (Content Encryption Key)")
    m.add_argument("--ntlm-sesskey", type=hexarg, help="Clave NTLMSSP; se derivara la ApplicationKey")
    m.add_argument("--preauth", type=hexarg, help="smb2.preauth_hash (SMB 3.1.1) para derivar la CEK")
    m.add_argument("--salt", type=hexarg, required=False, help="Salt/IV (16 B)")
    m.add_argument("--cipher", type=hexarg, required=False, help="Cipher (528 B)")
    m.add_argument("--auth-data", dest="auth_data", type=hexarg, help="AuthData (64 B), para verificar MAC")

    c = sub.add_parser("pcap", help="Extraer del pcap y descifrar")
    c.add_argument("--pcap", required=True)
    c.add_argument("--keytab", help="keytab con la clave del SERVICIO (para descifrar Kerberos)")
    c.add_argument("--nt-password", help="Contrasena de la cuenta autenticadora (auth NTLM)")
    c.add_argument("--cek", type=hexarg, help="Forzar la clave de sesion (si la obtienes por otra via)")

    args = p.parse_args()

    if args.mode == "manual":
        if not args.salt or not args.cipher:
            sys.exit("[-] Faltan --salt y --cipher.")
        if args.cek:
            ceks = [args.cek]
        elif args.ntlm_sesskey:
            ceks = [application_key(args.ntlm_sesskey, args.preauth)]
        else:
            sys.exit("[-] Falta la clave: usa --cek o --ntlm-sesskey (+ --preauth).")
        salt, cipher, auth_data = args.salt, args.cipher, args.auth_data
    else:
        if args.cek:
            # Extraer estructura del pcap pero usar la CEK provista.
            _, salt, cipher, auth_data = extract_from_pcap(args.pcap, args.keytab, args.nt_password)
            ceks = [args.cek]
        else:
            ceks, salt, cipher, auth_data = extract_from_pcap(args.pcap, args.keytab, args.nt_password)

    print()
    result = try_ceks(ceks, salt, cipher, auth_data)
    print()
    if result is None:
        print("[-] No se pudo descifrar. Revisa que el CEK (clave de sesion SMB) sea el correcto.")
        sys.exit(1)
    pwd, _ = result
    print("=" * 50)
    print(f"  New password: {pwd}")
    print("=" * 50)


if __name__ == "__main__":
    main()
