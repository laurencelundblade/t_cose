#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "${REPO_ROOT}/tools/gen_rfc9180_vectors.py"

# Build the vector test binary (requires CRYPTO_PROVIDER=MbedTLS)
CCACHE_DISABLE=1 cmake --build "${REPO_ROOT}/build" --target hpke_rfc9180_vectors -j4

"${REPO_ROOT}/build/hpke_rfc9180_vectors"
