import sys
import os
import cbor2
import binascii
import re

LABEL_NAMES = {}
ALG_NAMES = {}
CRV_NAMES = {}
HEADER_LABELS = {}


def load_maps_from_cddl(path):
    alg_re = re.compile(r";\s*([-+]?\d+)\s*;\s*(.+)")
    label_re = re.compile(r";\s*label\s+([-+]?\d+)\s+(\S+)", re.IGNORECASE)
    crv_re = re.compile(r";\s*crv\s+([-+]?\d+)\s+(.+)", re.IGNORECASE)
    header_re = re.compile(r";\s*header\s+([-+]?\d+)\s+(\S+)", re.IGNORECASE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                m_alg = alg_re.search(line)
                if m_alg:
                    ALG_NAMES[int(m_alg.group(1))] = m_alg.group(2).strip()
                m_lab = label_re.search(line)
                if m_lab:
                    LABEL_NAMES[int(m_lab.group(1))] = m_lab.group(2).strip()
                m_crv = crv_re.search(line)
                if m_crv:
                    CRV_NAMES[int(m_crv.group(1))] = m_crv.group(2).strip()
                m_hdr = header_re.search(line)
                if m_hdr:
                    HEADER_LABELS[int(m_hdr.group(1))] = m_hdr.group(2).strip()
    except OSError:
        pass


def format_bytes(bstr, indent):
    hexs = binascii.hexlify(bstr).decode()
    max_len = 72 - len(indent) - 3  # h' + ' plus indent
    chunks = [hexs[i:i + max_len] for i in range(0, len(hexs), max_len)]
    if len(chunks) == 1:
        return "h'" + chunks[0] + "'"
    lines = []
    lines.append(indent + "h'" + chunks[0])
    for c in chunks[1:]:
        lines.append(indent + "  " + c)
    lines[-1] = lines[-1] + "'"
    return "\n".join(lines)


def diag(obj, level=0, label_map=None):
    indent = "  " * level
    def indent_multiline(text, pad):
        if "\n" not in text:
            return text
        lines = text.split("\n")
        return ("\n" + pad).join(lines)
    if isinstance(obj, bytes):
        return format_bytes(obj, indent)
    if isinstance(obj, list):
        inner = []
        for idx, x in enumerate(obj):
            elem = diag(x, level + 1, label_map)
            elem = indent_multiline(elem, indent + "  ")
            comma = "," if idx < len(obj) - 1 else ""
            inner.append(indent + "  " + elem + comma)
        return "[\n" + "\n".join(inner) + "\n" + indent + "]"
    if isinstance(obj, dict):
        lines = []
        items = list(obj.items())
        active_labels = label_map if label_map else (LABEL_NAMES if all(isinstance(k, int) for k, _ in items) else {})
        for idx, (k, v) in enumerate(items):
            comma = "," if idx < len(items) - 1 else ""
            k_txt = diag(k, level + 1, label_map)
            if isinstance(k, int) and active_labels and k in active_labels:
                k_txt = f"{k_txt} /{active_labels[k]}/"
            next_map = label_map
            if k in ("protected", "unprotected"):
                next_map = HEADER_LABELS if HEADER_LABELS else LABEL_NAMES
            v_txt = diag(v, level + 1, next_map)
            if isinstance(k, int) and isinstance(v, int):
                if k in (1, 3) and active_labels and active_labels.get(k) == "alg" and v in ALG_NAMES:
                    v_txt = f"{v_txt} /{ALG_NAMES[v]}/"
                if k == -1 and v in CRV_NAMES:
                    v_txt = f"{v_txt} /{CRV_NAMES[v]}/"
            v_txt = indent_multiline(v_txt, indent + "    ")
            lines.append(f"{indent}  {k_txt}: {v_txt}{comma}")
        inner = "\n".join(lines)
        return "{\n" + inner + "\n" + indent + "}"
    if isinstance(obj, str):
        return '"' + obj + '"'
    return str(obj)


def wrap_diag(text, width=72):
    lines = []
    for raw_line in text.splitlines():
        parts = raw_line.split(" ")
        current = ""
        for part in parts:
            if current and len(current) + 1 + len(part) > width:
                lines.append(current)
                current = part
            else:
                current = part if not current else current + " " + part
        if current:
            lines.append(current)
    return "\n".join(lines)


def decode_protected(protected):
    try:
        return cbor2.loads(protected) if isinstance(protected, (bytes, bytearray)) else protected
    except Exception:
        return protected


def unwrap_sign1(seq):
    if not isinstance(seq, list) or len(seq) != 4:
        return seq
    prot = decode_protected(seq[0])
    return {
        "protected": prot,
        "unprotected": seq[1],
        "payload": seq[2],
        "signature": seq[3],
    }


def unwrap_encrypt0(seq):
    if not isinstance(seq, list) or len(seq) != 3:
        return seq
    prot = decode_protected(seq[0])
    return {
        "protected": prot,
        "unprotected": seq[1],
        "ciphertext": seq[2],
    }


def unwrap_recipient(seq):
    if not isinstance(seq, list) or len(seq) != 3:
        return seq
    prot = decode_protected(seq[0])
    return {
        "protected": prot,
        "unprotected": seq[1],
        "encrypted_cek": seq[2],
    }


def unwrap_encrypt(seq):
    if not isinstance(seq, list) or len(seq) != 4:
        return seq
    prot = decode_protected(seq[0])
    recipients = [unwrap_recipient(r) for r in (seq[3] if isinstance(seq[3], list) else [])]
    return {
        "protected": prot,
        "unprotected": seq[1],
        "ciphertext": seq[2],
        "recipients": recipients if isinstance(seq[3], list) else seq[3],
    }


default_cddl = os.path.join(os.path.dirname(__file__), "cose_hpke.cddl")
load_maps_from_cddl(default_cddl)
if len(sys.argv) >= 3:
    load_maps_from_cddl(sys.argv[2])

with open(sys.argv[1], "rb") as f:
    data = cbor2.load(f)

if isinstance(data, cbor2.CBORTag):
    if getattr(data, "tag", None) == 18:
        data = unwrap_sign1(data.value)
    elif getattr(data, "tag", None) == 16:
        data = unwrap_encrypt0(data.value)
    elif getattr(data, "tag", None) == 96:
        data = unwrap_encrypt(data.value)
    else:
        data = data.value
elif isinstance(data, list):
    if len(data) == 4 and isinstance(data[3], (bytes, bytearray)):
        data = unwrap_sign1(data)
    elif len(data) == 4 and isinstance(data[3], list):
        data = unwrap_encrypt(data)
    elif len(data) == 3:
        data = unwrap_encrypt0(data)

print(wrap_diag(diag(data)))
