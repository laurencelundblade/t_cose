#!/usr/bin/env python3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPENSSL_DIR = ROOT / "openssl"
OPENSSL_SEAL = ROOT / "build" / "openssl_hpke_seal_dump"
OPENSSL_OPEN = ROOT / "build" / "openssl_hpke_open_dump"
TCOSE_DEC = ROOT / "build" / "hpke_decrypt_tool"
TCOSE_ENC = ROOT / "build" / "hpke_encrypt_tool"


def build_openssl_tools():
    required = [OPENSSL_SEAL, OPENSSL_OPEN, TCOSE_DEC, TCOSE_ENC]
    if all(p.exists() for p in required):
        return

    build_cmd = [
        "cmake",
        "--build",
        str(ROOT / "build"),
        "--target",
        "openssl_hpke_seal_dump",
        "openssl_hpke_open_dump",
        "hpke_decrypt_tool",
        "hpke_encrypt_tool",
    ]
    subprocess.run(build_cmd, check=True)


def run_case(case):
    lines = [
        f"mode={case['mode']}",
        f"kem_id={case['kem_id']}",
        f"kdf_id={case['kdf_id']}",
        f"aead_id={case['aead_id']}",
        f"ikmR={case['ikmR']}",
        f"ikmE={case['ikmE']}",
        f"ikmAuth={case.get('ikmAuth','')}",
        f"psk={case.get('psk','')}",
        f"psk_id={case.get('psk_id','')}",
        f"info={case.get('info','')}",
        f"aad={case.get('aad','')}",
        f"pt={case.get('pt','')}",
    ]
    inp = "\n".join(lines) + "\n"
    env = dict(**{"LD_LIBRARY_PATH": str(OPENSSL_DIR)})
    cp = subprocess.run(
        [str(OPENSSL_SEAL)],
        input=inp.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.decode(errors="ignore"))
    res = {}
    for line in cp.stdout.decode().splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def run_tcose_dec(case, out):
    lines = [
        f"mode={case['mode']}",
        f"kem_id={case['kem_id']}",
        f"kdf_id={case['kdf_id']}",
        f"aead_id={case['aead_id']}",
        f"psk={case.get('psk','')}",
        f"psk_id={case.get('psk_id','')}",
        f"pkS={out.get('pkSm','')}",
        f"skR={out.get('skRm','')}",
        f"enc={out.get('enc','')}",
        f"ct={out.get('ct','')}",
        f"aad={case.get('aad','')}",
        f"info={case.get('info','')}",
    ]
    inp = "\n".join(lines) + "\n"
    cp = subprocess.run(
        [str(TCOSE_DEC)],
        input=inp.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.decode(errors="ignore"))
    res = {}
    for line in cp.stdout.decode().splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def run_tcose_enc(case, out):
    lines = [
        f"mode={case['mode']}",
        f"kem_id={case['kem_id']}",
        f"kdf_id={case['kdf_id']}",
        f"aead_id={case['aead_id']}",
        f"psk={case.get('psk','')}",
        f"psk_id={case.get('psk_id','')}",
        f"pkR={out.get('pkRm','')}",
        f"skE={case.get('ikmE','')}",
        f"skS={case.get('ikmAuth','')}",
        f"aad={case.get('aad','')}",
        f"info={case.get('info','')}",
        f"pt={case.get('pt','')}",
    ]
    inp = "\n".join(lines) + "\n"
    cp = subprocess.run(
        [str(TCOSE_ENC)],
        input=inp.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.decode(errors="ignore"))
    res = {}
    for line in cp.stdout.decode().splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def run_openssl_open(case, tcose_out, open_keys):
    lines = [
        f"mode={case['mode']}",
        f"kem_id={case['kem_id']}",
        f"kdf_id={case['kdf_id']}",
        f"aead_id={case['aead_id']}",
        f"ikmR={case.get('ikmR','')}",
        f"psk={case.get('psk','')}",
        f"psk_id={case.get('psk_id','')}",
        f"pkS={tcose_out.get('pkS','')}",
        f"skR={open_keys.get('skRm','')}",
        f"enc={tcose_out.get('enc','')}",
        f"ct={tcose_out.get('ct','')}",
        f"aad={case.get('aad','')}",
        f"info={case.get('info','')}",
    ]
    inp = "\n".join(lines) + "\n"
    env = dict(**{"LD_LIBRARY_PATH": str(OPENSSL_DIR)})
    cp = subprocess.run(
        [str(OPENSSL_OPEN)],
        input=inp.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.decode(errors="ignore"))
    res = {}
    for line in cp.stdout.decode().splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def main() -> int:
    build_openssl_tools()

    # We intentionally keep to X25519/X448 because raw private key
    # import/export paths are straightforward in both t_cose and OpenSSL helpers.
    common_case = {
        "info": "4f6465206f6e2061204772656369616e2055726e",
        "aad": "436f756e742d30",
        "pt": "4265617574792069732074727574682c20747275746820626561757479",
    }
    psk_fields = {
        "psk": "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
        "psk_id": "456e6e796e20447572696e206172616e204d6f726961",
    }

    kem_profiles = [
        {
            "name": "x25519",
            "kem_id": 0x0020,
            "ikmR": "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098",
            "ikmE": "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b",
            "ikmAuth": "59c77f5734aef369f30d83c7e30c6bf372e120391cdaf13f34c915030284b75d",
            "kdfs": [
                ("hkdf-sha256", 0x0001),
                ("hkdf-sha384", 0x0002),
                ("hkdf-sha512", 0x0003),
            ],
            "all_modes_for_all_kdfs": False,
        },
        {
            "name": "x448",
            "kem_id": 0x0021,
            "ikmR": (
                "1f1e1d1c1b1a19181716151413121110"
                "0f0e0d0c0b0a09080706050403020100"
                "ffeeddccbbaa99887766554433221100"
                "0123456789abcdef"
            ),
            "ikmE": (
                "00112233445566778899aabbccddeeff"
                "102132435465768798a9bacbdcedfe0f"
                "8899aabbccddeeff0011223344556677"
                "deadbeefcafebabe"
            ),
            "ikmAuth": (
                "abcdef0123456789fedcba9876543210"
                "0011aabbccddeeff1122334455667788"
                "99aabbccddeeff001122334455667788"
                "a1b2c3d4e5f60718"
            ),
            "kdfs": [
                ("hkdf-sha512", 0x0003),
            ],
            "all_modes_for_all_kdfs": False,
        },
        {
            "name": "p256",
            "kem_id": 0x0010,
            "ikmR": "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
            "ikmE": "ffeeddccbbaa998877665544332211000102030405060708090a0b0c0d0e0f10",
            "ikmAuth": "112233445566778899aabbccddeeff000f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "kdfs": [
                ("hkdf-sha256", 0x0001),
                ("hkdf-sha512", 0x0003),
            ],
            "all_modes_for_all_kdfs": False,
        },
        {
            "name": "p521",
            "kem_id": 0x0012,
            "ikmR": (
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "0001"
            ),
            "ikmE": (
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "0002"
            ),
            "ikmAuth": (
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "0003"
            ),
            "kdfs": [
                ("hkdf-sha512", 0x0003),
            ],
            "all_modes_for_all_kdfs": True,
        },
    ]

    mode_profiles = [
        ("base", 0),
        ("psk", 1),
        ("auth", 2),
        ("pskauth", 3),
    ]
    aead_profiles = [
        ("aes128gcm", 0x0001),
        ("aes256gcm", 0x0002),
        ("chacha20poly1305", 0x0003),
    ]

    cases = []
    for kem in kem_profiles:
        for kdf_name, kdf_id in kem["kdfs"]:
            for mode_name, mode_id in mode_profiles:
                for aead_name, aead_id in aead_profiles:
                    # Keep matrix practical by default: for non-default KDFs,
                    # run base only unless the KEM profile explicitly asks for
                    # full mode coverage.
                    if (
                        kdf_id != 0x0001
                        and mode_id != 0
                        and not kem.get("all_modes_for_all_kdfs", False)
                    ):
                        continue
                    case = {
                        "name": f"{kem['name']}/{mode_name}/{aead_name}-{kdf_name}",
                        "mode": mode_id,
                        "kem_id": kem["kem_id"],
                        "kdf_id": kdf_id,
                        "aead_id": aead_id,
                        "ikmR": kem["ikmR"],
                        "ikmE": kem["ikmE"],
                        **common_case,
                    }
                    if mode_id in (1, 3):
                        case.update(psk_fields)
                    if mode_id in (2, 3):
                        case["ikmAuth"] = kem["ikmAuth"]
                    cases.append(case)

    passed_open_ssl_to_tcose = 0
    passed_tcose_to_open_ssl = 0
    for case in cases:
        # OpenSSL seal -> t_cose decrypt
        try:
            out = run_case(case)
        except Exception as e:
            print(f"{case['name']}: OpenSSL seal error: {e}")
            continue
        try:
            dec = run_tcose_dec(case, out)
        except Exception as e:
            print(f"{case['name']}: t_cose decrypt error: {e}")
            dec = None

        exp_pt = case.get("pt", "")
        if dec is not None:
            got_pt = dec.get("pt", "")
            if exp_pt != got_pt:
                print(f"{case['name']}: OpenSSL->t_cose plaintext mismatch")
                print(f"  expected {exp_pt}")
                print(f"  got      {got_pt}")
            else:
                print(f"{case['name']}: openssl->t_cose ok")
                passed_open_ssl_to_tcose += 1

        # t_cose encrypt -> OpenSSL open
        try:
            tcose_out = run_tcose_enc(case, out)
        except Exception as e:
            print(f"{case['name']}: t_cose encrypt error: {e}")
            continue
        try:
            opened = run_openssl_open(case, tcose_out, out)
        except Exception as e:
            print(f"{case['name']}: OpenSSL open error: {e}")
            continue

        got_pt = opened.get("pt", "")
        if exp_pt != got_pt:
            print(f"{case['name']}: t_cose->OpenSSL plaintext mismatch")
            print(f"  expected {exp_pt}")
            print(f"  got      {got_pt}")
        else:
            print(f"{case['name']}: t_cose->openssl ok")
            passed_tcose_to_open_ssl += 1

    print(f"OpenSSL seal -> t_cose decrypt: {passed_open_ssl_to_tcose}/{len(cases)} passed")
    print(f"t_cose encrypt -> OpenSSL open: {passed_tcose_to_open_ssl}/{len(cases)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
