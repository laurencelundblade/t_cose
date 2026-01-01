# COSE HPKE

This code implements version -19 of the COSE HPKE implementation. The draft is available at:
https://www.ietf.org/archive/id/draft-ietf-cose-hpke-19.txt

It implements the following features:


## Build Code


## Build Mbed TLS

This code requires the crypto of an older version of Mbed TLS. The latest version of Mbed TLS release introduced backwards-compatibility-breaking change in their PSA Crypto API, which requires numerous changes in the code. Since the goal of this implementation was to demonstrate a working example of the code there is no need to switch to the latest version of the PSA Crypto API yet. There is also no technical benefit with the switch. A future version of this code might switch to the new API version.

Currently, Mbed TLS 3.6.5 branch released 2025-10-15 is used. Only libmbedcrypto.a will be needed.

The following build configuration has been used:

cmake -S . -B build -DENABLE_TESTING=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DENABLE_PROGRAMS=Off -DMBEDTLS_CONFIG_FILE="mbedtls_config_cose_hpke.h" -DCMAKE_C_FLAGS="-I${PWD}"

cmake --build build --target mbedcrypto -j$(nproc)

Note: Put the two configuration files into a place where cmake can find them. I put them in the
Root-directory of MbedTLS and include the -DCMAKE_C_FLAGS="-I${PWD}" as a command line parameter.
The two config-files are: mbedtls_config_cose_hpke.h and crypto_config_custom.h

## Building QCBOR

t_cose depends on QCBOR and hence QCBOR needs to be available on the system.

## Building t_cose

CCACHE_DISABLE=1 cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_COSE_KEY_GEN=ON -DBUILD_CLI=ON -DBUILD_TESTS=ON \
  -DBUILD_EXAMPLES=ON -DCRYPTO_PROVIDER=MbedTLS \
  -DMbedTLS_DIR=../mbedtls/build_hpke/cmake \
  -DCMAKE_C_COMPILER_LAUNCHER= -DCMAKE_CXX_COMPILER_LAUNCHER=

CCACHE_DISABLE=1 cmake --build build -j$(nproc)

This builds four programs:
 - cose_key_gen
 - hpke_cli
 - t_cose_examples
 - t_cose_test
 
Using the tool cose_key_gen you can generate COSE Key structures for use with the hpke_cli program. 

## Using COSE HPKE

Let us create two key pairs - one for alice and another one for bob:

./build/cose_key_gen \
  --alg HPKE-0 \
  --kid alice \
  --pub-out hpke0_alice_pub.cbor \
  --full-out hpke0_alice_full.cbor

This generates:
  
  - hpke0_alice_pub.cbor: contains only the public key in a COSE Key Format.
  - hpke0_full.cbor: public and private key for decryption tests.

Now we create the key pair for Bob:

./build/cose_key_gen \
  --alg HPKE-0 \
  --kid bob \
  --pub-out hpke0_bob_pub.cbor \
  --full-out hpke0_bob_full.cbor

Next, running the hpke_cli program allows Alice to encrypt a plaintext file with the recipient public key of Bob.
Note that this example does not sign the resulting message.

echo "hello bob" > plaintext.txt

./build/hpke_cli encrypt --mode encrypt \
   --recipient-key hpke0_bob_pub.cbor \
   --payload plaintext.txt \
   --out ciphertext.cbor \
   --attach

./build/hpke_cli decrypt --mode encrypt \
   --my-key hpke0_bob_full.cbor  \
   --in ciphertext.cbor \
   --out plaintext_out.txt

## Testing COSE HPKE

To test the functionality a test script is available, which runs through all combinations of the program.

To execute the test script run:

python3 ./examples/run_hpke_tests.sh

To pretty-print the result, several options are available. A Python program is available, which produces output in CBOR diagnostic notation. With the extra programs "yq" and "fmt" the output can be displayed better. Additionally, there is the cbor-diag tool 

Install the tools via the following commands:

> cargo install cbor-diag-cli

> export PATH="$HOME/.cargo/bin:$PATH"

> sudo dnf install yq

cbor-diag produces pretty-printed CBOR output:

 cat __temp/ke_hpke_6_ke/ciphertext.cbor | cbor-diag --to diag
 
The custom Python program offers even more debug information:
 
python3 examples/pretty_print.py __temp/ke_hpke_6_ke/ciphertext.cbor examples/cose_hpke.cddl | yq eval -P . | fmt -w 72

