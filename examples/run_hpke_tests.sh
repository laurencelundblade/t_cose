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

overall_status=0
total_tests=0
passed_tests=0
BASE_DIR="__temp"
mkdir -p "${BASE_DIR}"

write_variant_inputs() {
  local dir="$1"
  local use_aad="$2"
  local use_info="$3"

  local aad_file="${dir}/aad.bin"
  local info_file="${dir}/info.bin"

  if [[ "${use_aad}" == "1" ]]; then
    printf "external-aad:%s" "${dir}" > "${aad_file}"
  fi
  if [[ "${use_info}" == "1" ]]; then
    printf "external-info:%s" "${dir}" > "${info_file}"
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

run_ke() {
  local alg="$1"
  local tag="${alg//-/_}"
  tag="${tag,,}"
  local dir="${BASE_DIR}/ke_${tag}"
  local kid="bob-${tag}"

  mkdir -p "${dir}"

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
    echo "hello ${alg} (${variant})" > "${vdir}/plaintext.txt"
    write_variant_inputs "${vdir}" "${use_aad}" "${use_info}"
    local var_args
    var_args="$(hpke_cli_args_for_variant "${vdir}" "${use_aad}" "${use_info}")"

    if ! eval ./build/hpke_cli encrypt --mode encrypt \
         --recipient-key "\"${dir}/pub.cbor\"" \
         --payload "\"${vdir}/plaintext.txt\"" \
         --out "\"${vdir}/ciphertext.cbor\"" \
         ${var_args} \
         --attach; then
      echo "${alg} ${variant} encrypt FAILED"
      overall_status=1
      continue
    fi

    if ! eval ./build/hpke_cli decrypt --mode encrypt \
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
      echo "${alg} ${variant} diff FAILED"
      overall_status=1
    else
      echo "${alg} ${variant} round-trip OK"
      passed_tests=$((passed_tests+1))
    fi
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

  mkdir -p "${dir}"
  printf "psk-%s" "${tag}" > "${psk_file}"

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
    echo "hello ${alg} psk (${variant})" > "${vdir}/plaintext.txt"
    write_variant_inputs "${vdir}" "${use_aad}" "${use_info}"
    local var_args
    var_args="$(hpke_cli_args_for_variant "${vdir}" "${use_aad}" "${use_info}")"

    if ! eval ./build/hpke_cli encrypt --mode encrypt \
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

    if ! eval ./build/hpke_cli decrypt --mode encrypt \
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
      echo "${alg} ${variant} diff+psk FAILED"
      overall_status=1
    else
      echo "${alg} ${variant} round-trip+psk OK"
      passed_tests=$((passed_tests+1))
    fi
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
    echo "hello integrated ${alg} (${variant})" > "${vdir}/plaintext.txt"
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
    echo "hello integrated ${alg} psk (${variant})" > "${vdir}/plaintext.txt"
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
