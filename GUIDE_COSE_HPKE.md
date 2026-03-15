# COSE HPKE

This code implements version -23 of the COSE HPKE implementation. The draft is available at:
https://www.ietf.org/archive/id/draft-ietf-cose-hpke-23.txt

## Relevant Repositories

- `t_cose` (this project): https://github.com/hannestschofenig/t_cose
- `python-cwt` (Daisuke implementation): https://github.com/dajiaji/python-cwt
- COSE HPKE draft: https://github.com/cose-wg/draft-ietf-cose-hpke

## Build Code


## Build Mbed TLS

This code requires the crypto of an older version of Mbed TLS. The latest version of Mbed TLS release introduced backwards-compatibility-breaking change in their PSA Crypto API, which requires numerous changes in the code. Since the goal of this implementation was to demonstrate a working example of the code there is no need to switch to the latest version of the PSA Crypto API yet. There is also no technical benefit with the switch. A future version of this code might switch to the new API version.

Currently, Mbed TLS 3.6.5 branch released 2025-10-15 is used. Only libmbedcrypto.a will be needed.

The following build configuration has been used:

```
cmake -S . -B build -DENABLE_TESTING=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DENABLE_PROGRAMS=Off -DMBEDTLS_CONFIG_FILE="mbedtls_config_cose_hpke.h" -DCMAKE_C_FLAGS="-I${PWD}"

cmake --build build --target mbedcrypto -j$(nproc)
```

Note: Put the two configuration files into a place where cmake can find them. I put them in the
Root-directory of MbedTLS and include the -DCMAKE_C_FLAGS="-I${PWD}" as a command line parameter.
The two config-files are: mbedtls_config_cose_hpke.h and crypto_config_custom.h

## Building QCBOR

t_cose depends on QCBOR and hence QCBOR needs to be available on the system.

## Building t_cose

Adjust the paths as necessary.

```
CCACHE_DISABLE=1 cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_COSE_KEY_GEN=ON -DBUILD_CLI=ON -DBUILD_TESTS=ON \
  -DBUILD_EXAMPLES=ON -DBUILD_OPENSSL_INTEROP_TOOLS=ON \
  -DOPENSSL_INTEROP_ROOT=./openssl \
  -DCRYPTO_PROVIDER=MbedTLS \
  -DMbedTLS_DIR=/tmp/mbedtls-fixed-cmake \
  -DQCBOR_INCLUDE_DIR=../QCBOR/inc \
  -DQCBOR_LIBRARY=../QCBOR/build/libqcbor.a \
  -DCMAKE_C_FLAGS='-fno-pie' \
  -DCMAKE_EXE_LINKER_FLAGS='-no-pie' \
  -DCMAKE_C_COMPILER_LAUNCHER= -DCMAKE_CXX_COMPILER_LAUNCHER=

CCACHE_DISABLE=1 cmake --build build -j$(nproc)
```

This builds four programs:
 - cose_key_gen
 - hpke_cli
 - t_cose_examples
 - t_cose_test

With `-DBUILD_OPENSSL_INTEROP_TOOLS=ON` it also builds:
 - openssl_hpke_seal_dump
 - openssl_hpke_open_dump
 - hpke_encrypt_tool
 - hpke_decrypt_tool
 
Using the tool cose_key_gen you can generate COSE Key structures for use with the hpke_cli program. 

## Using COSE HPKE

Let us create two key pairs - one for alice and another one for bob:

```
./build/cose_key_gen \
  --alg HPKE-0 \
  --kid alice \
  --pub-out hpke0_alice_pub.cbor \
  --full-out hpke0_alice_full.cbor
```

This generates:
  
  - hpke0_alice_pub.cbor: contains only the public key in a COSE Key Format.
  - hpke0_full.cbor: public and private key for decryption tests.

Now we create the key pair for Bob:

```
./build/cose_key_gen \
  --alg HPKE-0 \
  --kid bob \
  --pub-out hpke0_bob_pub.cbor \
  --full-out hpke0_bob_full.cbor
```

Next, running the hpke_cli program allows Alice to encrypt a plaintext file with the recipient public key of Bob.

Note that this example does not sign the resulting message.

We use the integrated encryption mode in this example using the HPKE-0 ciphersuite with an externally supplied info value.

```
echo "This is the content." > plaintext.txt
echo "test" > info.bin
```

```
./build/hpke_cli encrypt --mode encrypt0 \
   --recipient-key hpke0_bob_pub.cbor \
   --payload plaintext.txt \
   --out ciphertext.cbor \
   --attach \
   --info info.bin
```

```
./build/hpke_cli decrypt --mode encrypt0 \
   --my-key hpke0_bob_full.cbor  \
   --in ciphertext.cbor \
   --info info.bin \
   --out plaintext_out.txt
```

## Pretty-Print COSE Structures

To pretty-print the result, several options are available. A Python program is available, which produces output in CBOR diagnostic notation. With the extra programs "yq" and "fmt" the output can be displayed better. Additionally, there is the cbor-diag tool 

Install the tools via the following commands:

```
cargo install cbor-diag-cli

export PATH="$HOME/.cargo/bin:$PATH"

sudo dnf install yq
```

cbor-diag produces pretty-printed CBOR output:

```
cat ciphertext.cbor | cbor-diag --to diag
```
 
The custom Python program offers even more debug information:

```
python3 examples/pretty_print.py ciphertext.cbor examples/cose_hpke.cddl | yq eval -P . | fmt -w 72
```


## Testing COSE HPKE

## HPKE Tests

The test the HPKE implementation against the RFC 9180 Appendix A provided test vectors use the following command:

```
./examples/run_rfc9180_vectors.sh
```

## COSE HPKE Test Script

To test the functionality a test script is available, which runs through all combinations of the program.

To execute the test script run:

```
./examples/run_hpke_tests.sh
```

To write detailed test vectors (full COSE_Key and ciphertext in HEX) to a file:

```
./examples/run_hpke_tests.sh --log testvectors.md
```

The script covers:
- Integrated Encryption (`encrypt0`) and Key Encryption (`encrypt`)
- HPKE-0 .. HPKE-7 and HPKE-0-KE .. HPKE-7-KE
- Variants: base, external aad, external info, external aad+info
- PSK and non-PSK runs

## OpenSSL Interoperability Tests

The OpenSSL interop tooling tests raw HPKE in both directions:
- OpenSSL `seal` -> t_cose `decrypt`
- t_cose `encrypt` -> OpenSSL `open`

Run:

```
python3 tools/run_openssl_seal_cases.py
```

### Build only the interop tools

If you only want to build the OpenSSL interop tooling targets:

```
CCACHE_DISABLE=1 cmake -S . -B build \
  -DBUILD_OPENSSL_INTEROP_TOOLS=ON \
  -DOPENSSL_INTEROP_ROOT=./openssl \
  -DCRYPTO_PROVIDER=MbedTLS

CCACHE_DISABLE=1 cmake --build build --target \
  openssl_hpke_seal_dump \
  openssl_hpke_open_dump \
  hpke_encrypt_tool \
  hpke_decrypt_tool -j$(nproc)
```

Then run:

```
python3 tools/run_openssl_seal_cases.py
```

The script currently covers:

- KEMs: X25519, X448, P-256, P-521
- Modes:
  - X25519, P-256: base, psk, auth, pskauth (for primary KDF)
  - X448: base
  - P-521: base, psk, auth, pskauth
- KDFs:
  - X25519: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512
  - X448: HKDF-SHA512
  - P-256: HKDF-SHA256, HKDF-SHA512
  - P-521: HKDF-SHA512
- AEADs: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305

The interop script uses helper binaries and OpenSSL helper tools:
  - `hpke_encrypt_tool`
  - `hpke_decrypt_tool`
  - `openssl_hpke_seal_dump`
  - `openssl_hpke_open_dump`

OpenSSL must be available and loadable via `LD_LIBRARY_PATH`.

## Python-Cwt Interoperability Tests

This section describes how to set up `python-cwt` and run interoperability
tests between `t_cose` and `python-cwt` for all HPKE ciphersuites.

### 1) Build and configure python-cwt

Create and activate a Python virtual environment (from repository root):

```sh
python3 -m venv .venv-python-cwt
source .venv-python-cwt/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ./python-cwt
```

This installs `python-cwt` in editable mode together with required
dependencies (`cbor2`, `cryptography`, `pyhpke`).

Optional quick self-check:

```sh
pytest -q python-cwt/tests/test_cose_hpke.py
```

### 2) Run t_cose <-> python-cwt interoperability tests

Build `t_cose` first so that `build/hpke_cli` exists, then run:

```sh
python3 tools/interop_t_cose.py
```

If `hpke_cli` is in a non-default location, set:

```sh
HPKE_CLI=/path/to/hpke_cli python3 tools/interop_t_cose.py
```

### 3) What is covered

The interop script performs bidirectional tests:
- `python-cwt -> t_cose`
- `t_cose -> python-cwt`

for:
- Integrated mode (`COSE_Encrypt0`): `HPKE-0 .. HPKE-7`
- Key Encryption mode (`COSE_Encrypt`): `HPKE-0-KE .. HPKE-7-KE`
- AAD variants: default AAD and external AAD

## COSE-HPKE Interoperability Tests

This section covers interoperability tests between `t_cose` and Orie's
implementation.

Repository:
- https://github.com/tradeverifyd/cose-hpke

### 1) Recommended: run the interop script

Use the provided script:

```sh
bash tools/interop_orie_t_cose.sh
```

Useful options:

```sh
# Keep known limitations as non-fatal (default behavior)
bash tools/interop_orie_t_cose.sh --timeout-sec 5

# Skip dependency installation if already done
bash tools/interop_orie_t_cose.sh --skip-install

# Treat known limitations as hard failures
bash tools/interop_orie_t_cose.sh --strict
```

The script currently executes:
- HPKE-7 Encrypt0: Orie -> t_cose (pass expected)
- HPKE-7 Encrypt0: t_cose -> Orie (pass expected)
- HPKE-7-KE Encrypt: t_cose -> Orie (pass expected)
- HPKE-7-KE Encrypt: Orie -> t_cose (currently timeout/known issue)
- HPKE-4 runtime check (currently unsupported in this runtime)

### 2) Manual setup (if running steps by hand)

From repository root:

```sh
cd cose-hpke-orie
BUN_TMPDIR=/tmp BUN_INSTALL=/tmp/bun bun install
cd ..
```

### 3) Manual interop test: HPKE-7 (COSE_Encrypt0, integrated mode)

Orie -> t_cose:

```sh
W=/tmp/interop_orie_tcose
rm -rf "$W" && mkdir -p "$W"

cd cose-hpke-orie
bun run src/cli/index.ts keygen --suite HPKE-7 \
  --output-public "$W/orie7_pub.cbor" \
  --output-private "$W/orie7_priv.cbor"
bun run src/cli/index.ts encrypt "hello-orie7-e0" \
  -r "$W/orie7_pub.cbor" \
  -o "$W/orie7_e0_from_orie.cbor" \
  --suite HPKE-7
cd ..

./build/hpke_cli decrypt --mode encrypt0 \
  --my-key "$W/orie7_priv.cbor" \
  --in "$W/orie7_e0_from_orie.cbor" \
  --out "$W/orie7_e0_to_tcose.txt"
cat "$W/orie7_e0_to_tcose.txt"
```

t_cose -> Orie:

```sh
./build/cose_key_gen --alg HPKE-7 --kid bob7 \
  --pub-out "$W/t7_pub.cbor" \
  --full-out "$W/t7_priv.cbor"
printf 'hello-tcose7-e0' > "$W/payload7.txt"

./build/hpke_cli encrypt --mode encrypt0 \
  --recipient-key "$W/t7_pub.cbor" \
  --payload "$W/payload7.txt" \
  --out "$W/t7_e0_from_tcose.cbor" \
  --attach

cd cose-hpke-orie
bun run src/cli/index.ts decrypt "$W/t7_e0_from_tcose.cbor" \
  -k "$W/t7_priv.cbor" > "$W/t7_e0_to_orie.txt"
cd ..
cat "$W/t7_e0_to_orie.txt"
```

Expected:
- Orie -> t_cose: `hello-orie7-e0`
- t_cose -> Orie: `hello-tcose7-e0`

### 4) Manual interop test: HPKE-7-KE (COSE_Encrypt, key encryption mode)

t_cose -> Orie:

```sh
./build/cose_key_gen --alg HPKE-7-KE --kid orieke \
  --pub-out "$W/orie7ke_pub.cbor" \
  --full-out "$W/orie7ke_priv.cbor"

printf 'hello-tcose7-ke' > "$W/payload7ke.txt"
./build/hpke_cli encrypt --mode encrypt \
  --recipient-key "$W/orie7ke_pub.cbor" \
  --payload "$W/payload7ke.txt" \
  --out "$W/t7_ke_from_tcose.cbor" \
  --attach

cd cose-hpke-orie
bun run src/cli/index.ts decrypt "$W/t7_ke_from_tcose.cbor" \
  -k "$W/orie7ke_priv.cbor" > "$W/t7_ke_to_orie.txt"
cd ..
cat "$W/t7_ke_to_orie.txt"
```

Expected:
- t_cose -> Orie: `hello-tcose7-ke`

Orie -> t_cose currently hangs in `hpke_cli decrypt --mode encrypt`
(timeout observed), so this direction is currently not passing.

### 5) Current limitation

`HPKE-4` (X25519) tests with Orie's CLI currently fail in this environment with:

```text
DHKEM(X25519, HKDF-SHA256) is unsupported in this runtime
```

So practical interop coverage with Orie's implementation in this setup is
currently HPKE-7 based flows.
