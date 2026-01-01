#!/usr/bin/env bash
set -euo pipefail

# End-to-end HPKE tests for all COSE HPKE algorithm IDs from draft-19.
# - Key Encryption mode (COSE_Encrypt): HPKE-*-KE (alg 46..53)
# - Integrated Encryption mode (COSE_Encrypt0): HPKE-0..HPKE-7 (alg 35..45)
#
# The script generates keys, encrypts, decrypts, and diffs the plaintexts.

integrated_algs=(HPKE-0 HPKE-1 HPKE-2 HPKE-3 HPKE-4 HPKE-5 HPKE-6 HPKE-7)
ke_algs=(HPKE-0-KE HPKE-1-KE HPKE-2-KE HPKE-3-KE HPKE-4-KE HPKE-5-KE HPKE-6-KE HPKE-7-KE)

overall_status=0
BASE_DIR="__temp"
mkdir -p "${BASE_DIR}"

run_ke() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/ke_${tag}"
  local kid="bob-${tag}"

  mkdir -p "${dir}"
  echo "hello ${alg}" > "${dir}/plaintext.txt"

  echo "== Key Encryption: ${alg} =="
  if ! ./build/cose_key_gen \
    --alg "${alg}" \
    --kid "${kid}" \
    --pub-out "${dir}/pub.cbor" \
    --full-out "${dir}/full.cbor"; then
    echo "${alg} keygen FAILED"
    overall_status=1
    return
  fi

  if ! ./build/hpke_cli encrypt --mode encrypt \
     --recipient-key "${dir}/pub.cbor" \
     --payload "${dir}/plaintext.txt" \
     --out "${dir}/ciphertext.cbor" \
     --attach; then
    echo "${alg} encrypt FAILED"
    overall_status=1
    return
  fi

  if ! ./build/hpke_cli decrypt --mode encrypt \
     --my-key "${dir}/full.cbor"  \
     --in "${dir}/ciphertext.cbor" \
     --out "${dir}/plaintext_out.txt"; then
    echo "${alg} decrypt FAILED"
    overall_status=1
    return
  fi

  if ! diff -u "${dir}/plaintext.txt" "${dir}/plaintext_out.txt"; then
    echo "${alg} diff FAILED"
    overall_status=1
  else
    echo "${alg} round-trip OK"
  fi
}

run_integrated() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/int_${tag}"
  local kid="bob-${tag}-int"

  mkdir -p "${dir}"
  echo "hello integrated ${alg}" > "${dir}/plaintext.txt"

  echo "== Integrated Encryption: ${alg} =="
  if ! ./build/cose_key_gen \
    --alg "${alg}" \
    --kid "${kid}" \
    --pub-out "${dir}/pub.cbor" \
    --full-out "${dir}/full.cbor"; then
    echo "${alg} keygen FAILED"
    overall_status=1
    return
  fi

  if ! ./build/hpke_cli encrypt --mode encrypt0 \
     --recipient-key "${dir}/pub.cbor" \
     --payload "${dir}/plaintext.txt" \
     --out "${dir}/ciphertext.cbor" \
     --attach; then
    echo "${alg} encrypt FAILED"
    overall_status=1
    return
  fi

  if ! ./build/hpke_cli decrypt --mode encrypt0 \
     --my-key "${dir}/full.cbor"  \
     --in "${dir}/ciphertext.cbor" \
     --out "${dir}/plaintext_out.txt"; then
    echo "${alg} decrypt FAILED"
    overall_status=1
    return
  fi

  if ! diff -u "${dir}/plaintext.txt" "${dir}/plaintext_out.txt"; then
    echo "${alg} integrated diff FAILED"
    overall_status=1
  else
    echo "${alg} integrated round-trip OK"
  fi
}

for alg in "${ke_algs[@]}"; do
  run_ke "${alg}"
done

for alg in "${integrated_algs[@]}"; do
  run_integrated "${alg}"
done

exit "${overall_status}"
