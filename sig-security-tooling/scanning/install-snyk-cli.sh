#!/usr/bin/env bash
# Copyright 2022 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Downloads the Snyk CLI binary, verifies its PGP signature and SHA-256 checksum,
# then installs it to /usr/local/bin/snyk.
#
# Trust model:
#   - Binary and checksums fetched from Snyk's CDN (downloads.snyk.io/cli/stable/).
#   - PGP signing key fetched from an INDEPENDENT public keyserver (keys.openpgp.org)
#     using the hardcoded fingerprint — separating key trust from the binary host.
#   - Fingerprint re-verified after import before any signature is trusted.
#   - All GPG operations use an isolated temporary keyring cleaned up on EXIT.
#

# Snyk's code-signing key (code-signing@snyk.io), per:
#   https://docs.snyk.io/snyk-cli/getting-started-with-the-snyk-cli
#   https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli/verifying-cli-standalone-binaries
snyk_key_fingerprint="467717A30B2B4658415975629691DA64D0025194"

# Update this variable to install a different version of the Snyk CLI
snyk_cli_version="1.1305.0" # 1.1305.0 is the latest stable version as of 2026-06-17

set -euo pipefail
apt update && apt -y install curl gnupg

tmpdir=$(mktemp -d)
gpghome="${tmpdir}/gnupg"
mkdir -p "${gpghome}"
chmod 700 "${gpghome}"
trap 'rm -rf "${tmpdir}"' INT TERM EXIT

echo "Downloading snyk-linux binary and signed checksums..."
curl -sSfL -o "${tmpdir}/snyk-linux"         "https://downloads.snyk.io/cli/v${snyk_cli_version}/snyk-linux"
curl -sSfL -o "${tmpdir}/sha256sums.txt.asc" "https://downloads.snyk.io/cli/v${snyk_cli_version}/sha256sums.txt.asc"

# snyk-code-signing.asc is the public PGP key used by Snyk to sign their CLI releases,
# and was downloaded from https://keys.openpgp.org/vks/v1/by-fingerprint/${snyk_key_fingerprint}
GNUPGHOME="${gpghome}" gpg --import "$(dirname "$0")/snyk-code-signing.asc"

# Re-verify the imported fingerprint before trusting any signature.
echo "Verifying imported key fingerprint..."
GNUPGHOME="${gpghome}" gpg --with-colons --fingerprint "${snyk_key_fingerprint}" \
  | grep "^fpr" | grep --quiet "${snyk_key_fingerprint}" \
  || { echo "ERROR: Snyk key fingerprint ${snyk_key_fingerprint} not found. Aborting."; exit 1; }

# Verify PGP signature on the checksums file.
echo "Verifying PGP signature on checksums file..."
GNUPGHOME="${gpghome}" gpg --export "${snyk_key_fingerprint}" > "${tmpdir}/snyk-verify.gpg"
gpgv --keyring "${tmpdir}/snyk-verify.gpg" "${tmpdir}/sha256sums.txt.asc"

# Extract hash lines from the PGP cleartext body (avoids armor-header format warnings)
# and verify the SHA-256 digest of the downloaded binary.
echo "Verifying SHA-256 digest of snyk-linux..."
awk '/^-----BEGIN PGP SIGNATURE-----/{exit} /^[0-9a-f]{64}  /{print}' \
  "${tmpdir}/sha256sums.txt.asc" > "${tmpdir}/sha256sums.txt"
(cd "${tmpdir}" && sha256sum --strict -c --ignore-missing sha256sums.txt)

install -m 0755 "${tmpdir}/snyk-linux" /usr/local/bin/snyk
