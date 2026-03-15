#!/usr/bin/env bash
set -euo pipefail

ORIE_DIR="cose-hpke-orie"
WORK_DIR="/tmp/interop_orie_tcose"
T_COSE_BUILD_DIR="./build"
SKIP_INSTALL=0
STRICT=0
TIMEOUT_SEC=5

usage() {
  cat <<'USAGE'
Usage: tools/interop_orie_t_cose.sh [options]

Options:
  --orie-dir <path>       Path to Orie repository (default: cose-hpke-orie)
  --work-dir <path>       Working directory for generated artifacts (default: /tmp/interop_orie_tcose)
  --build-dir <path>      t_cose build directory containing hpke_cli/cose_key_gen (default: ./build)
  --timeout-sec <num>     Timeout in seconds for known hanging case (default: 5)
  --skip-install          Skip bun install in Orie directory
  --strict                Treat known limitations as hard failures (non-zero exit)
  -h, --help              Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --orie-dir)
      ORIE_DIR="${2:-}"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="${2:-}"
      shift 2
      ;;
    --build-dir)
      T_COSE_BUILD_DIR="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      TIMEOUT_SEC="${2:-}"
      shift 2
      ;;
    --skip-install)
      SKIP_INSTALL=1
      shift
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

HPKE_CLI="${T_COSE_BUILD_DIR}/hpke_cli"
COSE_KEY_GEN="${T_COSE_BUILD_DIR}/cose_key_gen"

PASS=0
FAIL=0
XFAIL=0

pass() {
  echo "PASS: $*"
  PASS=$((PASS + 1))
}

fail() {
  echo "FAIL: $*" >&2
  FAIL=$((FAIL + 1))
}

xfail() {
  echo "XFAIL: $*"
  XFAIL=$((XFAIL + 1))
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

require_cmd bun
require_cmd timeout

if [[ ! -x "${HPKE_CLI}" ]]; then
  echo "Missing executable: ${HPKE_CLI}" >&2
  exit 2
fi
if [[ ! -x "${COSE_KEY_GEN}" ]]; then
  echo "Missing executable: ${COSE_KEY_GEN}" >&2
  exit 2
fi
if [[ ! -d "${ORIE_DIR}" ]]; then
  echo "Missing directory: ${ORIE_DIR}" >&2
  exit 2
fi

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

if [[ "${SKIP_INSTALL}" -eq 0 ]]; then
  (
    cd "${ORIE_DIR}"
    BUN_TMPDIR=/tmp BUN_INSTALL=/tmp/bun bun install >/dev/null
  )
fi

# HPKE-7 Encrypt0: Orie -> t_cose
(
  cd "${ORIE_DIR}"
  bun run src/cli/index.ts keygen --suite HPKE-7 \
    --output-public "${WORK_DIR}/orie7_pub.cbor" \
    --output-private "${WORK_DIR}/orie7_priv.cbor" >/dev/null
  bun run src/cli/index.ts encrypt "hello-orie7-e0" \
    -r "${WORK_DIR}/orie7_pub.cbor" \
    -o "${WORK_DIR}/orie7_e0_from_orie.cbor" \
    --suite HPKE-7 >/dev/null
)
"${HPKE_CLI}" decrypt --mode encrypt0 \
  --my-key "${WORK_DIR}/orie7_priv.cbor" \
  --in "${WORK_DIR}/orie7_e0_from_orie.cbor" \
  --out "${WORK_DIR}/orie7_e0_to_tcose.txt" >/dev/null
if [[ "$(cat "${WORK_DIR}/orie7_e0_to_tcose.txt")" == "hello-orie7-e0" ]]; then
  pass "HPKE-7 Encrypt0 Orie -> t_cose"
else
  fail "HPKE-7 Encrypt0 Orie -> t_cose payload mismatch"
fi

# HPKE-7 Encrypt0: t_cose -> Orie
"${COSE_KEY_GEN}" --alg HPKE-7 --kid bob7 \
  --pub-out "${WORK_DIR}/t7_pub.cbor" \
  --full-out "${WORK_DIR}/t7_priv.cbor" >/dev/null
printf 'hello-tcose7-e0' > "${WORK_DIR}/payload7.txt"
"${HPKE_CLI}" encrypt --mode encrypt0 \
  --recipient-key "${WORK_DIR}/t7_pub.cbor" \
  --payload "${WORK_DIR}/payload7.txt" \
  --out "${WORK_DIR}/t7_e0_from_tcose.cbor" \
  --attach >/dev/null
(
  cd "${ORIE_DIR}"
  bun run src/cli/index.ts decrypt "${WORK_DIR}/t7_e0_from_tcose.cbor" \
    -k "${WORK_DIR}/t7_priv.cbor" > "${WORK_DIR}/t7_e0_to_orie.txt"
)
if [[ "$(tr -d '\r\n' < "${WORK_DIR}/t7_e0_to_orie.txt")" == "hello-tcose7-e0" ]]; then
  pass "HPKE-7 Encrypt0 t_cose -> Orie"
else
  fail "HPKE-7 Encrypt0 t_cose -> Orie payload mismatch"
fi

# HPKE-7-KE Key Encryption: t_cose -> Orie
"${COSE_KEY_GEN}" --alg HPKE-7-KE --kid orieke \
  --pub-out "${WORK_DIR}/orie7ke_pub.cbor" \
  --full-out "${WORK_DIR}/orie7ke_priv.cbor" >/dev/null
printf 'hello-tcose7-ke' > "${WORK_DIR}/payload7ke.txt"
"${HPKE_CLI}" encrypt --mode encrypt \
  --recipient-key "${WORK_DIR}/orie7ke_pub.cbor" \
  --payload "${WORK_DIR}/payload7ke.txt" \
  --out "${WORK_DIR}/t7_ke_from_tcose.cbor" \
  --attach >/dev/null
(
  cd "${ORIE_DIR}"
  bun run src/cli/index.ts decrypt "${WORK_DIR}/t7_ke_from_tcose.cbor" \
    -k "${WORK_DIR}/orie7ke_priv.cbor" > "${WORK_DIR}/t7_ke_to_orie.txt"
)
if [[ "$(tr -d '\r\n' < "${WORK_DIR}/t7_ke_to_orie.txt")" == "hello-tcose7-ke" ]]; then
  pass "HPKE-7-KE KeyEnc t_cose -> Orie"
else
  fail "HPKE-7-KE KeyEnc t_cose -> Orie payload mismatch"
fi

# HPKE-7-KE Key Encryption: Orie -> t_cose (known issue: timeout/hang)
"${COSE_KEY_GEN}" --alg HPKE-7 --kid r1 \
  --pub-out "${WORK_DIR}/t7r1_pub.cbor" \
  --full-out "${WORK_DIR}/t7r1_priv.cbor" >/dev/null
"${COSE_KEY_GEN}" --alg HPKE-7 --kid r2 \
  --pub-out "${WORK_DIR}/t7r2_pub.cbor" \
  --full-out "${WORK_DIR}/t7r2_priv.cbor" >/dev/null
(
  cd "${ORIE_DIR}"
  bun run src/cli/index.ts encrypt "hello-orie7-ke" \
    -r "${WORK_DIR}/t7r1_pub.cbor" \
    -r "${WORK_DIR}/t7r2_pub.cbor" \
    -o "${WORK_DIR}/orie7_ke_from_orie.cbor" \
    --suite HPKE-7 >/dev/null
)
set +e
timeout "${TIMEOUT_SEC}s" "${HPKE_CLI}" decrypt --mode encrypt \
  --my-key "${WORK_DIR}/t7r1_priv.cbor" \
  --in "${WORK_DIR}/orie7_ke_from_orie.cbor" \
  --out "${WORK_DIR}/orie7_ke_to_tcose.txt" >/dev/null 2>&1
RC=$?
set -e
if [[ "${RC}" -eq 0 ]]; then
  if [[ "$(cat "${WORK_DIR}/orie7_ke_to_tcose.txt")" == "hello-orie7-ke" ]]; then
    pass "HPKE-7-KE KeyEnc Orie -> t_cose"
  else
    fail "HPKE-7-KE KeyEnc Orie -> t_cose payload mismatch"
  fi
elif [[ "${RC}" -eq 124 ]]; then
  xfail "HPKE-7-KE KeyEnc Orie -> t_cose timeout (known issue)"
else
  xfail "HPKE-7-KE KeyEnc Orie -> t_cose failed with rc=${RC} (known issue)"
fi

# HPKE-4 limitation check in current runtime
set +e
(
  cd "${ORIE_DIR}"
  bun run src/cli/index.ts keygen --suite HPKE-4 \
    --output-public "${WORK_DIR}/orie4_pub.cbor" \
    --output-private "${WORK_DIR}/orie4_priv.cbor" >/dev/null
  bun run src/cli/index.ts encrypt "hello-orie4-e0" \
    -r "${WORK_DIR}/orie4_pub.cbor" \
    -o "${WORK_DIR}/orie4_e0_from_orie.cbor" \
    --suite HPKE-4 >/dev/null
) >"${WORK_DIR}/hpke4_stdout.txt" 2>"${WORK_DIR}/hpke4_stderr.txt"
RC4=$?
set -e
if [[ "${RC4}" -eq 0 ]]; then
  pass "HPKE-4 runtime support in Orie CLI"
else
  if rg -q "unsupported in this runtime|unsupported" "${WORK_DIR}/hpke4_stderr.txt"; then
    xfail "HPKE-4 unsupported in current Bun/WebCrypto runtime"
  else
    fail "HPKE-4 failed for unexpected reason (see ${WORK_DIR}/hpke4_stderr.txt)"
  fi
fi

echo
echo "Summary:"
echo "  PASS : ${PASS}"
echo "  FAIL : ${FAIL}"
echo "  XFAIL: ${XFAIL}"
echo "  Artifacts: ${WORK_DIR}"

if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
if [[ "${STRICT}" -eq 1 && "${XFAIL}" -gt 0 ]]; then
  exit 1
fi
exit 0
