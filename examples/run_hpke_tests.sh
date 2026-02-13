#!/usr/bin/env bash
set -euo pipefail

# End-to-end HPKE tests for all COSE HPKE algorithm IDs from draft-19.
# - Key Encryption mode (COSE_Encrypt): HPKE-*-KE (alg 46..53)
# - Integrated Encryption mode (COSE_Encrypt0): HPKE-0..HPKE-7 (alg 35..45)
#
# The script generates keys, encrypts, decrypts, and diffs the plaintexts.

integrated_algs=(HPKE-0 HPKE-1 HPKE-2 HPKE-3 HPKE-4 HPKE-5 HPKE-6 HPKE-7)
ke_algs=(HPKE-0-KE HPKE-1-KE HPKE-2-KE HPKE-3-KE HPKE-4-KE HPKE-5-KE HPKE-6-KE HPKE-7-KE)
variants=(base aad info aad_info)

LOG_FILE=""
usage() {
  cat <<'USAGE'
Usage: bash examples/run_hpke_tests.sh [--log FILE]

--log FILE   Write detailed HEX logs (COSE_Key + ciphertext) to FILE.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log)
      shift
      LOG_FILE="${1:-}"
      if [[ -z "${LOG_FILE}" ]]; then
        echo "ERROR: --log requires a file path" >&2
        usage
        exit 2
      fi
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

overall_status=0
total_tests=0
passed_tests=0
BASE_DIR="__temp"
mkdir -p "${BASE_DIR}"

PLAINTEXT_CONTENT="hpke test payload"
AAD_CONTENT="external-aad"
INFO_CONTENT="external-info"
HPKE_AAD_CONTENT="external-hpke-aad"

log_line() {
  if [[ -n "${LOG_FILE}" ]]; then
    printf '%s\n' "$*" >> "${LOG_FILE}"
  fi
}

log_blank() {
  if [[ -n "${LOG_FILE}" ]]; then
    printf '\n' >> "${LOG_FILE}"
  fi
}

log_hex_file() {
  local label="$1"
  local path="$2"
  if [[ -n "${LOG_FILE}" ]]; then
    if command -v xxd >/dev/null 2>&1; then
      log_line "${label}: $(xxd -p -c 100000 "${path}")"
    else
      log_line "${label}: $(od -An -tx1 -v "${path}" | tr -d ' \n')"
    fi
  fi
}

write_variant_inputs() {
  local dir="$1"
  local use_aad="$2"
  local use_info="$3"

  local aad_file="${dir}/aad.bin"
  local info_file="${dir}/info.bin"
  if [[ "${use_aad}" == "1" ]]; then
    printf "%s" "${AAD_CONTENT}" > "${aad_file}"
  fi
  if [[ "${use_info}" == "1" ]]; then
    printf "%s" "${INFO_CONTENT}" > "${info_file}"
  fi
}

hpke_cli_args_for_variant() {
  local dir="$1"
  local use_aad="$2"
  local use_info="$3"

  if [[ "${use_aad}" == "1" ]]; then
    printf -- "--aad %q " "${dir}/aad.bin"
  fi
  if [[ "${use_info}" == "1" ]]; then
    printf -- "--info %q " "${dir}/info.bin"
  fi
}

describe_variant() {
  local base_desc="$1"
  local variant="$2"
  local hpke_aad_variant="${3:-}"
  local aad_desc="default aad"
  local info_desc="default info"
  case "${variant}" in
    base) aad_desc="default aad"; info_desc="default info" ;;
    aad) aad_desc="external aad"; info_desc="default info" ;;
    info) aad_desc="default aad"; info_desc="external info" ;;
    aad_info) aad_desc="external aad"; info_desc="external info" ;;
  esac
  if [[ -n "${hpke_aad_variant}" ]]; then
    local hpke_desc="default hpke aad"
    if [[ "${hpke_aad_variant}" == "provided" ]]; then
      hpke_desc="external hpke aad"
    fi
    printf "%s with %s, %s, %s" "${base_desc}" "${aad_desc}" "${info_desc}" "${hpke_desc}"
  else
    printf "%s with %s and %s" "${base_desc}" "${aad_desc}" "${info_desc}"
  fi
}

run_ke() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/ke_${tag}"
  local kid="bob-${tag}"
  local hpke_aad_file="${dir}/hpke_aad.bin"

  mkdir -p "${dir}"
  printf "%s" "${HPKE_AAD_CONTENT}" > "${hpke_aad_file}"

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

  log_blank
  log_hex_file "${alg} COSE_Key:" "${dir}/full.cbor"
  log_blank

  # For Key Encryption mode there are two independent "AAD-like" inputs:
  # - Layer 0: COSE Enc_structure.external_aad (passed via --aad)
  # - Layer 1: HPKE Seal/Open aad for CEK wrapping (passed via --hpke-aad, defaults to empty)
  # Cover both cases for HPKE aad: default (no flag) and externally provided (flag).
  local hpke_aad_variants=(default provided)

  for variant in "${variants[@]}"; do
    local use_aad=0
    local use_info=0
    case "${variant}" in
      base) use_aad=0; use_info=0 ;;
      aad) use_aad=1; use_info=0 ;;
      info) use_aad=0; use_info=1 ;;
      aad_info) use_aad=1; use_info=1 ;;
    esac

    for hpke_aad_variant in "${hpke_aad_variants[@]}"; do
      local vdir="${dir}/${variant}/${hpke_aad_variant}"
      mkdir -p "${vdir}"
      printf "%s" "${PLAINTEXT_CONTENT}" > "${vdir}/plaintext.txt"
      write_variant_inputs "${vdir}" "${use_aad}" "${use_info}"
      local var_args
      var_args="$(hpke_cli_args_for_variant "${vdir}" "${use_aad}" "${use_info}")"

      local hpke_aad_args=""
      if [[ "${hpke_aad_variant}" == "provided" ]]; then
        hpke_aad_args="--hpke-aad \"${hpke_aad_file}\""
      fi

      total_tests=$((total_tests+1))
      if ! eval ./build/hpke_cli encrypt --mode encrypt \
           --recipient-key "\"${dir}/pub.cbor\"" \
           --payload "\"${vdir}/plaintext.txt\"" \
           --out "\"${vdir}/ciphertext.cbor\"" \
           ${var_args} \
           ${hpke_aad_args} \
           --attach; then
        echo "${alg} ${variant} ${hpke_aad_variant} encrypt FAILED"
        overall_status=1
        continue
      fi
      log_blank
      log_line "$(describe_variant "${alg}" "${variant}" "${hpke_aad_variant}")"
      log_blank
      log_hex_file "Ciphertext" "${vdir}/ciphertext.cbor"
      log_blank

      if ! eval ./build/hpke_cli decrypt --mode encrypt \
           --my-key "\"${dir}/full.cbor\""  \
           --in "\"${vdir}/ciphertext.cbor\"" \
           --out "\"${vdir}/plaintext_out.txt\"" \
           ${var_args} \
           ${hpke_aad_args}; then
        echo "${alg} ${variant} ${hpke_aad_variant} decrypt FAILED"
        overall_status=1
        continue
      fi

      if ! diff -u "${vdir}/plaintext.txt" "${vdir}/plaintext_out.txt"; then
        echo "${alg} ${variant} ${hpke_aad_variant} diff FAILED"
        overall_status=1
      else
        echo "${alg} ${variant} ${hpke_aad_variant} round-trip OK"
        passed_tests=$((passed_tests+1))
      fi
    done
  done
}

run_ke_psk() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/ke_psk_${tag}"
  local kid="bob-${tag}"
  local psk_file="${dir}/psk.bin"
  local psk_id="psk-${tag}"
  local hpke_aad_file="${dir}/hpke_aad.bin"

  mkdir -p "${dir}"
  printf "psk-%s" "${tag}" > "${psk_file}"
  printf "%s" "${HPKE_AAD_CONTENT}" > "${hpke_aad_file}"

  echo "== Key Encryption + PSK: ${alg} =="
  if ! ./build/cose_key_gen \
    --alg "${alg}" \
    --kid "${kid}" \
    --pub-out "${dir}/pub.cbor" \
    --full-out "${dir}/full.cbor"; then
    echo "${alg} keygen FAILED"
    overall_status=1
    return
  fi

  log_blank
  log_hex_file "${alg} COSE_Key" "${dir}/full.cbor"
  log_blank

  local hpke_aad_variants=(default provided)
  for variant in "${variants[@]}"; do
    local use_aad=0
    local use_info=0
    case "${variant}" in
      base) use_aad=0; use_info=0 ;;
      aad) use_aad=1; use_info=0 ;;
      info) use_aad=0; use_info=1 ;;
      aad_info) use_aad=1; use_info=1 ;;
    esac

    for hpke_aad_variant in "${hpke_aad_variants[@]}"; do
      local vdir="${dir}/${variant}/${hpke_aad_variant}"
      mkdir -p "${vdir}"
      printf "%s" "${PLAINTEXT_CONTENT}" > "${vdir}/plaintext.txt"
      write_variant_inputs "${vdir}" "${use_aad}" "${use_info}"
      local var_args
      var_args="$(hpke_cli_args_for_variant "${vdir}" "${use_aad}" "${use_info}")"

      local hpke_aad_args=""
      if [[ "${hpke_aad_variant}" == "provided" ]]; then
        hpke_aad_args="--hpke-aad \"${hpke_aad_file}\""
      fi

      total_tests=$((total_tests+1))
      if ! eval ./build/hpke_cli encrypt --mode encrypt \
           --recipient-key "\"${dir}/pub.cbor\"" \
           --payload "\"${vdir}/plaintext.txt\"" \
           --out "\"${vdir}/ciphertext.cbor\"" \
           ${var_args} \
           ${hpke_aad_args} \
           --psk "\"${psk_file}\"" \
           --psk-id "\"${psk_id}\"" \
           --attach; then
        echo "${alg} ${variant} ${hpke_aad_variant} encrypt+psk FAILED"
        overall_status=1
        continue
      fi
      log_blank
      log_line "$(describe_variant "${alg} KE+PSK" "${variant}" "${hpke_aad_variant}")"
      log_blank
      log_hex_file "Ciphertext" "${vdir}/ciphertext.cbor"
      log_blank

      if ! eval ./build/hpke_cli decrypt --mode encrypt \
           --my-key "\"${dir}/full.cbor\""  \
           --in "\"${vdir}/ciphertext.cbor\"" \
           ${var_args} \
           ${hpke_aad_args} \
           --psk "\"${psk_file}\"" \
           --psk-id "\"${psk_id}\"" \
           --out "\"${vdir}/plaintext_out.txt\""; then
        echo "${alg} ${variant} ${hpke_aad_variant} decrypt+psk FAILED"
        overall_status=1
        continue
      fi

      if ! diff -u "${vdir}/plaintext.txt" "${vdir}/plaintext_out.txt"; then
        echo "${alg} ${variant} ${hpke_aad_variant} diff+psk FAILED"
        overall_status=1
      else
        echo "${alg} ${variant} ${hpke_aad_variant} round-trip+psk OK"
        passed_tests=$((passed_tests+1))
      fi
    done
  done
}

run_integrated() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/int_${tag}"
  local kid="bob-${tag}-int"

  mkdir -p "${dir}"

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
  log_blank
  log_hex_file "${alg} COSE_Key" "${dir}/full.cbor"
  log_blank

  for variant in "${variants[@]}"; do
    local use_aad=0
    local use_info=0
    case "${variant}" in
      base) use_aad=0; use_info=0 ;;
      aad) use_aad=1; use_info=0 ;;
      info) use_aad=0; use_info=1 ;;
      aad_info) use_aad=1; use_info=1 ;;
    esac

    local vdir="${dir}/${variant}"
    mkdir -p "${vdir}"
    printf "%s" "${PLAINTEXT_CONTENT}" > "${vdir}/plaintext.txt"
    write_variant_inputs "${vdir}" "${use_aad}" "${use_info}"
    local var_args
    var_args="$(hpke_cli_args_for_variant "${vdir}" "${use_aad}" "${use_info}")"

    if ! eval ./build/hpke_cli encrypt --mode encrypt0 \
         --recipient-key "\"${dir}/pub.cbor\"" \
         --payload "\"${vdir}/plaintext.txt\"" \
         --out "\"${vdir}/ciphertext.cbor\"" \
         ${var_args} \
         --attach; then
      echo "${alg} ${variant} encrypt FAILED"
      overall_status=1
      continue
    fi
    log_blank
    log_line "$(describe_variant "${alg} Encrypt0" "${variant}")"
    log_blank
    log_hex_file "Ciphertext" "${vdir}/ciphertext.cbor"
    log_blank

    if ! eval ./build/hpke_cli decrypt --mode encrypt0 \
         --my-key "\"${dir}/full.cbor\""  \
         --in "\"${vdir}/ciphertext.cbor\"" \
         --out "\"${vdir}/plaintext_out.txt\"" \
         ${var_args}; then
      echo "${alg} ${variant} decrypt FAILED"
      overall_status=1
      continue
    fi

    total_tests=$((total_tests+1))
    if ! diff -u "${vdir}/plaintext.txt" "${vdir}/plaintext_out.txt"; then
      echo "${alg} ${variant} integrated diff FAILED"
      overall_status=1
    else
      echo "${alg} ${variant} integrated round-trip OK"
      passed_tests=$((passed_tests+1))
    fi
  done
}

run_integrated_psk() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/int_psk_${tag}"
  local kid="bob-${tag}-int"
  local psk_file="${dir}/psk.bin"
  local psk_id="psk-${tag}-int"

  mkdir -p "${dir}"
  printf "psk-int-%s" "${tag}" > "${psk_file}"

  echo "== Integrated Encryption + PSK: ${alg} =="
  if ! ./build/cose_key_gen \
    --alg "${alg}" \
    --kid "${kid}" \
    --pub-out "${dir}/pub.cbor" \
    --full-out "${dir}/full.cbor"; then
    echo "${alg} keygen FAILED"
    overall_status=1
    return
  fi

  log_blank
  log_hex_file "${alg} COSE_Key:" "${dir}/full.cbor"
  log_blank

  for variant in "${variants[@]}"; do
    local use_aad=0
    local use_info=0
    case "${variant}" in
      base) use_aad=0; use_info=0 ;;
      aad) use_aad=1; use_info=0 ;;
      info) use_aad=0; use_info=1 ;;
      aad_info) use_aad=1; use_info=1 ;;
    esac

    local vdir="${dir}/${variant}"
    mkdir -p "${vdir}"
    printf "%s" "${PLAINTEXT_CONTENT}" > "${vdir}/plaintext.txt"
    write_variant_inputs "${vdir}" "${use_aad}" "${use_info}"
    local var_args
    var_args="$(hpke_cli_args_for_variant "${vdir}" "${use_aad}" "${use_info}")"

    if ! eval ./build/hpke_cli encrypt --mode encrypt0 \
         --recipient-key "\"${dir}/pub.cbor\"" \
         --payload "\"${vdir}/plaintext.txt\"" \
         --out "\"${vdir}/ciphertext.cbor\"" \
         ${var_args} \
         --psk "\"${psk_file}\"" \
         --psk-id "\"${psk_id}\"" \
         --attach; then
      echo "${alg} ${variant} encrypt+psk FAILED"
      overall_status=1
      continue
    fi
    log_blank
    log_line "$(describe_variant "${alg} Encrypt0+PSK" "${variant}")"
    log_blank
    log_hex_file "Ciphertext" "${vdir}/ciphertext.cbor"
    log_blank

    if ! eval ./build/hpke_cli decrypt --mode encrypt0 \
         --my-key "\"${dir}/full.cbor\""  \
         --in "\"${vdir}/ciphertext.cbor\"" \
         ${var_args} \
         --psk "\"${psk_file}\"" \
         --psk-id "\"${psk_id}\"" \
         --out "\"${vdir}/plaintext_out.txt\""; then
      echo "${alg} ${variant} decrypt+psk FAILED"
      overall_status=1
      continue
    fi

    total_tests=$((total_tests+1))
    if ! diff -u "${vdir}/plaintext.txt" "${vdir}/plaintext_out.txt"; then
      echo "${alg} ${variant} integrated diff+psk FAILED"
      overall_status=1
    else
      echo "${alg} ${variant} integrated round-trip+psk OK"
      passed_tests=$((passed_tests+1))
    fi
  done
}

for alg in "${ke_algs[@]}"; do
  run_ke "${alg}"
done

for alg in "${integrated_algs[@]}"; do
  run_integrated "${alg}"
done

for alg in "${ke_algs[@]}"; do
  run_ke_psk "${alg}"
done

for alg in "${integrated_algs[@]}"; do
  run_integrated_psk "${alg}"
done

echo
echo "HPKE tests: ${passed_tests}/${total_tests} passed"

exit "${overall_status}"
