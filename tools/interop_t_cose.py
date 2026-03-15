#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Ensure local python-cwt is importable
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PYTHON_CWT_ROOT = REPO_ROOT / "python-cwt"
if PYTHON_CWT_ROOT.exists():
    sys.path.insert(0, str(PYTHON_CWT_ROOT))

from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, Recipient  # noqa: E402


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def to_base_hpke_alg(alg: int) -> int:
    if alg == COSEAlgs.HPKE_0_KE:
        return COSEAlgs.HPKE_0
    if alg == COSEAlgs.HPKE_1_KE:
        return COSEAlgs.HPKE_1
    if alg == COSEAlgs.HPKE_2_KE:
        return COSEAlgs.HPKE_2
    if alg == COSEAlgs.HPKE_3_KE:
        return COSEAlgs.HPKE_3
    if alg == COSEAlgs.HPKE_4_KE:
        return COSEAlgs.HPKE_4
    if alg == COSEAlgs.HPKE_5_KE:
        return COSEAlgs.HPKE_5
    if alg == COSEAlgs.HPKE_6_KE:
        return COSEAlgs.HPKE_6
    if alg == COSEAlgs.HPKE_7_KE:
        return COSEAlgs.HPKE_7
    return alg


def generate_keypair_for_alg(alg: int):
    base_alg = to_base_hpke_alg(alg)
    if base_alg in (COSEAlgs.HPKE_0, COSEAlgs.HPKE_7):
        return ec.generate_private_key(ec.SECP256R1())
    if base_alg == COSEAlgs.HPKE_1:
        return ec.generate_private_key(ec.SECP384R1())
    if base_alg == COSEAlgs.HPKE_2:
        return ec.generate_private_key(ec.SECP521R1())
    if base_alg in (COSEAlgs.HPKE_3, COSEAlgs.HPKE_4):
        return x25519.X25519PrivateKey.generate()
    if base_alg in (COSEAlgs.HPKE_5, COSEAlgs.HPKE_6):
        return x448.X448PrivateKey.generate()
    raise ValueError(f"Unsupported HPKE alg: {alg}")


def write_cose_key_files(tmp_dir: Path, alg: int, kid: bytes) -> tuple[Path, Path, COSEKey]:
    priv = generate_keypair_for_alg(alg)
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    rsk = COSEKey.from_pem(priv_pem, alg=alg, kid=kid, key_ops=[8])
    rpk = COSEKey.from_pem(pub_pem, alg=alg, kid=kid)

    pub_path = tmp_dir / "recipient.pub.cbor"
    priv_path = tmp_dir / "recipient.priv.cbor"
    pub_path.write_bytes(cbor2.dumps(rpk.to_dict()))
    priv_path.write_bytes(cbor2.dumps(rsk.to_dict()))
    return pub_path, priv_path, rsk


def python_encrypt_to_file(
    plaintext: bytes,
    recipient_key: COSEKey,
    out_path: Path,
    external_aad: bytes,
    alg: int,
) -> None:
    sender = COSE.new()
    encoded = sender.encode(
        plaintext,
        recipient_key,
        protected={COSEHeaders.ALG: alg},
        unprotected={COSEHeaders.KID: recipient_key.kid},
        external_aad=external_aad,
    )
    out_path.write_bytes(encoded)


def python_encrypt_ke_to_file(
    plaintext: bytes,
    recipient_key: COSEKey,
    out_path: Path,
    external_aad: bytes,
    alg: int,
) -> None:
    sender = COSE.new()
    content_key = COSEKey.from_symmetric_key(alg="A128GCM")
    recipient = Recipient.new(
        protected={COSEHeaders.ALG: alg},
        unprotected={COSEHeaders.KID: recipient_key.kid},
        recipient_key=recipient_key,
    )
    encoded = sender.encode_and_encrypt(
        plaintext,
        content_key,
        protected={COSEHeaders.ALG: COSEAlgs.A128GCM},
        recipients=[recipient],
        external_aad=external_aad,
    )
    out_path.write_bytes(encoded)


def python_decrypt_from_file(
    cose_path: Path,
    recipient_key: COSEKey,
    external_aad: bytes,
) -> bytes:
    recipient = COSE.new()
    encoded = cose_path.read_bytes()
    return recipient.decode(encoded, recipient_key, external_aad=external_aad)


def main() -> int:
    repo_root = REPO_ROOT
    hpke_cli = Path(os.environ.get("HPKE_CLI", repo_root / "build" / "hpke_cli"))
    if not hpke_cli.exists():
        print(f"hpke_cli not found: {hpke_cli}", file=sys.stderr)
        return 2

    variants = {
        "base": b"",
        "aad": b"external-aad:python-cwt",
    }

    integrated_algs = [
        ("HPKE-0", COSEAlgs.HPKE_0),
        ("HPKE-1", COSEAlgs.HPKE_1),
        ("HPKE-2", COSEAlgs.HPKE_2),
        ("HPKE-3", COSEAlgs.HPKE_3),
        ("HPKE-4", COSEAlgs.HPKE_4),
        ("HPKE-5", COSEAlgs.HPKE_5),
        ("HPKE-6", COSEAlgs.HPKE_6),
        ("HPKE-7", COSEAlgs.HPKE_7),
    ]
    ke_algs = [
        ("HPKE-0-KE", COSEAlgs.HPKE_0_KE),
        ("HPKE-1-KE", COSEAlgs.HPKE_1_KE),
        ("HPKE-2-KE", COSEAlgs.HPKE_2_KE),
        ("HPKE-3-KE", COSEAlgs.HPKE_3_KE),
        ("HPKE-4-KE", COSEAlgs.HPKE_4_KE),
        ("HPKE-5-KE", COSEAlgs.HPKE_5_KE),
        ("HPKE-6-KE", COSEAlgs.HPKE_6_KE),
        ("HPKE-7-KE", COSEAlgs.HPKE_7_KE),
    ]

    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        for alg_name, alg_id in integrated_algs:
            kid = f"kid-{alg_name}".encode("utf-8")
            pub_path, priv_path, rsk = write_cose_key_files(tmp_dir, alg_id, kid)

            # Load public key for python-cwt from CBOR to ensure t_cose-compatible encoding.
            rpk = COSEKey.from_bytes(pub_path.read_bytes())

            for name, aad in variants.items():
                print(f"== {alg_name} Encrypt0 interop ({name}) ==")

                # python-cwt -> t_cose
                py_cose = tmp_dir / f"python_to_tcose_{alg_name}_{name}.cbor"
                out_plain = tmp_dir / f"python_to_tcose_{alg_name}_{name}.txt"
                python_encrypt_to_file(b"hello from python-cwt", rpk, py_cose, aad, alg_id)
                cmd = [
                    str(hpke_cli),
                    "decrypt",
                    "--mode",
                    "encrypt0",
                    "--my-key",
                    str(priv_path),
                    "--in",
                    str(py_cose),
                    "--out",
                    str(out_plain),
                ]
                if aad:
                    aad_path = tmp_dir / f"aad_{alg_name}_{name}.bin"
                    aad_path.write_bytes(aad)
                    cmd += ["--aad", str(aad_path)]
                run(cmd)
                if out_plain.read_text() != "hello from python-cwt":
                    print(f"FAIL: t_cose decrypt mismatch ({alg_name}, {name})", file=sys.stderr)
                    return 1
                print(f"PASS: python-cwt -> t_cose ({alg_name}, {name})")

                # t_cose -> python-cwt
                tcose_cose = tmp_dir / f"tcose_to_python_{alg_name}_{name}.cbor"
                payload = tmp_dir / f"payload_{alg_name}_{name}.txt"
                payload.write_text("hello from t_cose")
                cmd = [
                    str(hpke_cli),
                    "encrypt",
                    "--mode",
                    "encrypt0",
                    "--recipient-key",
                    str(pub_path),
                    "--payload",
                    str(payload),
                    "--out",
                    str(tcose_cose),
                    "--attach",
                ]
                if aad:
                    aad_path = tmp_dir / f"aad_{alg_name}_{name}.bin"
                    cmd += ["--aad", str(aad_path)]
                run(cmd)
                try:
                    decoded = python_decrypt_from_file(tcose_cose, rsk, aad)
                except Exception as err:
                    try:
                        data = cbor2.loads(tcose_cose.read_bytes())
                        unprotected = data.value[1] if hasattr(data, "value") and len(data.value) > 1 else {}
                    except Exception:
                        unprotected = {}
                    if isinstance(unprotected, dict) and 4 not in unprotected:
                        print(
                            "FAIL: t_cose -> python-cwt (missing kid in unprotected header; "
                            "python-cwt requires kid for HPKE decrypt)",
                            file=sys.stderr,
                        )
                    else:
                        print(f"FAIL: t_cose -> python-cwt ({alg_name}, {name}): {err}", file=sys.stderr)
                    return 1
                if decoded != b"hello from t_cose":
                    print(f"FAIL: python-cwt decrypt mismatch ({alg_name}, {name})", file=sys.stderr)
                    return 1
                print(f"PASS: t_cose -> python-cwt ({alg_name}, {name})")

        for alg_name, alg_id in ke_algs:
            kid = f"kid-{alg_name}".encode("utf-8")
            pub_path, priv_path, rsk = write_cose_key_files(tmp_dir, alg_id, kid)

            # Load public key for python-cwt from CBOR to ensure t_cose-compatible encoding.
            rpk = COSEKey.from_bytes(pub_path.read_bytes())

            for name, aad in variants.items():
                print(f"== {alg_name} COSE_Encrypt interop ({name}) ==")

                # python-cwt -> t_cose
                py_cose = tmp_dir / f"python_to_tcose_{alg_name}_{name}.cbor"
                out_plain = tmp_dir / f"python_to_tcose_{alg_name}_{name}.txt"
                python_encrypt_ke_to_file(b"hello from python-cwt", rpk, py_cose, aad, alg_id)
                cmd = [
                    str(hpke_cli),
                    "decrypt",
                    "--mode",
                    "encrypt",
                    "--my-key",
                    str(priv_path),
                    "--in",
                    str(py_cose),
                    "--out",
                    str(out_plain),
                ]
                if aad:
                    aad_path = tmp_dir / f"aad_{alg_name}_{name}.bin"
                    aad_path.write_bytes(aad)
                    cmd += ["--aad", str(aad_path)]
                run(cmd)
                if out_plain.read_text() != "hello from python-cwt":
                    print(f"FAIL: t_cose decrypt mismatch ({alg_name}, {name})", file=sys.stderr)
                    return 1
                print(f"PASS: python-cwt -> t_cose ({alg_name}, {name})")

                # t_cose -> python-cwt
                tcose_cose = tmp_dir / f"tcose_to_python_{alg_name}_{name}.cbor"
                payload = tmp_dir / f"payload_{alg_name}_{name}.txt"
                payload.write_text("hello from t_cose")
                cmd = [
                    str(hpke_cli),
                    "encrypt",
                    "--mode",
                    "encrypt",
                    "--recipient-key",
                    str(pub_path),
                    "--payload",
                    str(payload),
                    "--out",
                    str(tcose_cose),
                    "--attach",
                ]
                if aad:
                    aad_path = tmp_dir / f"aad_{alg_name}_{name}.bin"
                    cmd += ["--aad", str(aad_path)]
                run(cmd)
                try:
                    decoded = python_decrypt_from_file(tcose_cose, rsk, aad)
                except Exception as err:
                    print(f"FAIL: t_cose -> python-cwt ({alg_name}, {name}): {err}", file=sys.stderr)
                    return 1
                if decoded != b"hello from t_cose":
                    print(f"FAIL: python-cwt decrypt mismatch ({alg_name}, {name})", file=sys.stderr)
                    return 1
                print(f"PASS: t_cose -> python-cwt ({alg_name}, {name})")

    print("Interop OK (HPKE-0..7 and HPKE-0-KE..7-KE)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
