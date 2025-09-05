#!/usr/bin/env bash
# mk_all_keys.sh — generate one RSA keypair and emit multiple formats
# Requires: openssl, ssh-keygen
set -euo pipefail

PREFIX="${1:-wildcard}"

echo "[1/11] Generating RSA private key (PKCS#8) ..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${PREFIX}.pkcs8.key"

echo "[2/11] Deriving RSA private key (PKCS#1) ..."
# Force traditional (PKCS#1) output explicitly
openssl pkey -in "${PREFIX}.pkcs8.key" -traditional -out "${PREFIX}.pkcs1.key"

echo "[3/11] Writing SubjectPublicKeyInfo public key (PEM: -----BEGIN PUBLIC KEY-----) ..."
openssl pkey -in "${PREFIX}.pkcs8.key" -pubout -out "${PREFIX}.spki.pub"

echo "[4/11] Writing SubjectPublicKeyInfo public key (DER) ..."
openssl pkey -in "${PREFIX}.pkcs8.key" -pubout -outform DER -out "${PREFIX}.spki.der"

echo "[5/11] Writing PKCS#1 RSA public key (PEM: -----BEGIN RSA PUBLIC KEY-----) ..."
openssl rsa -in "${PREFIX}.pkcs1.key" -pubout -RSAPublicKey_out -out "${PREFIX}.pkcs1.pub"

echo "[6/11] Writing PKCS#1 RSA public key (DER) ..."
openssl rsa -in "${PREFIX}.pkcs1.key" -pubout -RSAPublicKey_out -outform DER -out "${PREFIX}.pkcs1.der"

echo "[7/11] Creating self-signed X.509 certificate ..."
openssl req -new -x509 -key "${PREFIX}.pkcs8.key" -days 365 \
  -subj "/CN=example" -out "${PREFIX}.x509.crt"

echo "[8/11] Converting private key to OpenSSH private key format ..."
cp "${PREFIX}.pkcs8.key" "${PREFIX}.openssh.key"
# Rewrites the copied key to OpenSSH's native private-key format
ssh-keygen -p -f "${PREFIX}.openssh.key" -N "" -o -q

echo "[9/11] Writing OpenSSH public keys ..."
# From the OpenSSH private key
ssh-keygen -y -f "${PREFIX}.openssh.key" > "${PREFIX}.openssh.pub"
# Also: OpenSSH public key derived from the X.509 cert’s public key
openssl x509 -in "${PREFIX}.x509.crt" -noout -pubkey \
  | ssh-keygen -i -m PKCS8 -f /dev/stdin > "${PREFIX}.from-cert.openssh.pub"

echo "[10/11] Creating PKCS#12 (.p12/.pfx) bundle (no password) ..."
openssl pkcs12 -export -in "${PREFIX}.x509.crt" -inkey "${PREFIX}.pkcs8.key" -out "${PREFIX}.pkcs12.p12" -name "${PREFIX}" -passout pass:
cp "${PREFIX}.pkcs12.p12" "${PREFIX}.pkcs12.pfx"

echo "[11/11] Verifying PKCS#12 bundle ..."
if ! openssl pkcs12 -in "${PREFIX}.pkcs12.p12" -nokeys -passin pass: > /dev/null 2>&1; then
  echo "ERROR: PKCS#12 bundle verification failed" >&2
  exit 1
fi

echo "[PKCS#12] Creating base64 (text) representation ..."
# Single-line base64 (RFC 4648) encoded PKCS#12 for embedding in text files
base64 -w0 "${PREFIX}.pkcs12.p12" > "${PREFIX}.pkcs12.p12.b64"
# Also pretty (wrapped) version for readability
base64 "${PREFIX}.pkcs12.p12" > "${PREFIX}.pkcs12.p12.b64.wrap"
# Round‑trip verification
if ! diff <(base64 -d "${PREFIX}.pkcs12.p12.b64") "${PREFIX}.pkcs12.p12" >/dev/null; then
  echo "ERROR: Base64 (.b64) PKCS#12 round‑trip failed" >&2
  exit 1
fi
if ! diff <(base64 -d "${PREFIX}.pkcs12.p12.b64.wrap") "${PREFIX}.pkcs12.p12" >/dev/null; then
  echo "ERROR: Wrapped base64 PKCS#12 round‑trip failed" >&2
  exit 1
fi

echo "[PKCS#12] Creating PEM-wrapped representation ..."
{
  echo "-----BEGIN PKCS12-----"
  # 64-char wrapped lines for PEM style
  base64 -w64 "${PREFIX}.pkcs12.p12"
  echo "-----END PKCS12-----"
} > "${PREFIX}.pkcs12.p12.pem"
# Verify PEM wrapper round-trip
if ! awk 'BEGIN{ok=0}/-----BEGIN PKCS12-----/{ok=1;next}/-----END PKCS12-----/{ok=0}ok' "${PREFIX}.pkcs12.p12.pem" | base64 -d > "${PREFIX}.pkcs12.p12.pem.bin" 2>/dev/null; then
  echo "ERROR: Could not decode PEM-wrapped PKCS#12" >&2
  exit 1
fi
if ! diff "${PREFIX}.pkcs12.p12" "${PREFIX}.pkcs12.p12.pem.bin" >/dev/null; then
  echo "ERROR: PEM-wrapped PKCS#12 does not match original" >&2
  rm -f "${PREFIX}.pkcs12.p12.pem.bin"
  exit 1
fi
rm -f "${PREFIX}.pkcs12.p12.pem.bin"

# Verification of headers / formats
verify_header() {
  local file="$1" expected="$2"
  local first
  first=$(head -1 "$file" || true)
  if [[ "$first" != "$expected" ]]; then
    echo "ERROR: $file has header '$first' but expected '$expected'" >&2
    exit 1
  fi
}

verify_prefix() {
  local file="$1" prefix="$2"
  if ! grep -q "^${prefix}" "$file"; then
    echo "ERROR: $file does not start with '${prefix}'" >&2
    exit 1
  fi
}

echo "[VERIFY] Checking generated file formats ..."
verify_header "${PREFIX}.pkcs8.key" "-----BEGIN PRIVATE KEY-----"
verify_header "${PREFIX}.pkcs1.key" "-----BEGIN RSA PRIVATE KEY-----"
verify_header "${PREFIX}.spki.pub" "-----BEGIN PUBLIC KEY-----"
verify_header "${PREFIX}.pkcs1.pub" "-----BEGIN RSA PUBLIC KEY-----"
verify_header "${PREFIX}.x509.crt" "-----BEGIN CERTIFICATE-----"
verify_header "${PREFIX}.openssh.key" "-----BEGIN OPENSSH PRIVATE KEY-----"
verify_prefix "${PREFIX}.openssh.pub" "ssh-rsa "
verify_prefix "${PREFIX}.from-cert.openssh.pub" "ssh-rsa "
# Verify DER PKCS#1 public key parses
if ! openssl asn1parse -inform DER -in "${PREFIX}.pkcs1.der" > /dev/null 2>&1; then
  echo "ERROR: ${PREFIX}.pkcs1.der is not valid DER PKCS#1 public key" >&2
  exit 1
fi
# Verify DER SPKI public key parses
if ! openssl pkey -pubin -inform DER -in "${PREFIX}.spki.der" -noout > /dev/null 2>&1; then
  echo "ERROR: ${PREFIX}.spki.der is not valid DER SPKI public key" >&2
  exit 1
fi

# Additional PKCS#12 validations
# 1) friendlyName check
if ! openssl pkcs12 -in "${PREFIX}.pkcs12.p12" -passin pass: -info -nokeys 2>/dev/null | grep -q "friendlyName: ${PREFIX}"; then
  echo "ERROR: PKCS#12 bundle missing expected friendlyName '${PREFIX}'" >&2
  exit 1
fi
# 2) Subject CN check
P12_SUBJ=$(openssl pkcs12 -in "${PREFIX}.pkcs12.p12" -passin pass: -clcerts -nokeys 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)
# Normalize for flexible matching (remove spaces, lowercase)
P12_SUBJ_NORM=$(echo "$P12_SUBJ" | tr 'A-Z' 'a-z' | tr -d ' \t')
if [[ "$P12_SUBJ_NORM" != *"cn=example"* ]]; then
  echo "ERROR: PKCS#12 certificate subject mismatch: $P12_SUBJ" >&2
  exit 1
fi
# 3) Private key matches certificate (modulus comparison)
CERT_MOD=$(openssl x509 -in "${PREFIX}.x509.crt" -noout -modulus | sed 's/Modulus=//')
KEY_MOD=$(openssl rsa -in "${PREFIX}.pkcs8.key" -noout -modulus | sed 's/Modulus=//')
if [[ -z "$CERT_MOD" || -z "$KEY_MOD" || "$CERT_MOD" != "$KEY_MOD" ]]; then
  echo "ERROR: Certificate and private key modulus do not match" >&2
  exit 1
fi

# 4) Key size check (expect 3072 bits)
# Extract only the numeric bit length from line like: Private-Key: (3072 bit, 2 primes)
KEY_BITS=$(openssl rsa -in "${PREFIX}.pkcs1.key" -noout -text 2>/dev/null | sed -n 's/.*(\([0-9][0-9]*\) bit.*/\1/p' | head -1)
if [[ "$KEY_BITS" != "3072" ]]; then
  echo "ERROR: Unexpected RSA key size: ${KEY_BITS} (wanted 3072)" >&2
  exit 1
fi

# 5) Public key modulus consistency (SPKI / PKCS#1 / OpenSSH)
SPKI_MOD=$(openssl rsa -pubin -in "${PREFIX}.spki.pub" -noout -modulus 2>/dev/null | sed 's/Modulus=//')
PKCS1_PUB_MOD=$(openssl rsa -RSAPublicKey_in -in "${PREFIX}.pkcs1.pub" -noout -modulus 2>/dev/null | sed 's/Modulus=//')
if [[ -z "$SPKI_MOD" || "$SPKI_MOD" != "$KEY_MOD" ]]; then
  echo "ERROR: SPKI public key modulus mismatch" >&2
  exit 1
fi
if [[ -z "$PKCS1_PUB_MOD" || "$PKCS1_PUB_MOD" != "$KEY_MOD" ]]; then
  echo "ERROR: PKCS#1 public key modulus mismatch" >&2
  exit 1
fi

# 6) Self-signed certificate check (subject == issuer)
CRT_SUBJ=$(openssl x509 -in "${PREFIX}.x509.crt" -noout -subject 2>/dev/null | sed 's/^subject= *//')
CRT_ISSR=$(openssl x509 -in "${PREFIX}.x509.crt" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
if [[ -z "$CRT_SUBJ" || -z "$CRT_ISSR" || "$CRT_SUBJ" != "$CRT_ISSR" ]]; then
  echo "ERROR: Certificate is not self-signed (subject != issuer)" >&2
  exit 1
fi

# 7) OpenSSH public key modulus matches
OPENSSH_MOD=$(ssh-keygen -e -m PKCS8 -f "${PREFIX}.openssh.pub" 2>/dev/null | \
  openssl rsa -pubin -inform PEM -noout -modulus 2>/dev/null | sed 's/Modulus=//')
if [[ -z "$OPENSSH_MOD" || "$OPENSSH_MOD" != "$KEY_MOD" ]]; then
  echo "ERROR: OpenSSH public key modulus mismatch" >&2
  exit 1
fi

# 8) Base64 PKCS#12 size sanity (non-empty)
if [[ ! -s "${PREFIX}.pkcs12.p12.b64" || ! -s "${PREFIX}.pkcs12.p12.b64.wrap" ]]; then
  echo "ERROR: Base64 PKCS#12 outputs are empty" >&2
  exit 1
fi


cat <<EOF

Done. Files generated:

- ${PREFIX}.pkcs8.key            # RSA private key (PKCS#8, PEM)
- ${PREFIX}.pkcs1.key            # RSA private key (PKCS#1, PEM)
- ${PREFIX}.spki.pub             # Public key (SubjectPublicKeyInfo, PEM: "BEGIN PUBLIC KEY")
- ${PREFIX}.spki.der             # Public key (SubjectPublicKeyInfo, DER)
- ${PREFIX}.pkcs1.pub            # RSA public key (PKCS#1, PEM: "BEGIN RSA PUBLIC KEY")
- ${PREFIX}.pkcs1.der            # RSA public key (PKCS#1, DER)
- ${PREFIX}.x509.crt             # Self-signed X.509 certificate (PEM: "BEGIN CERTIFICATE")
- ${PREFIX}.openssh.key          # OpenSSH private key ("BEGIN OPENSSH PRIVATE KEY")
- ${PREFIX}.openssh.pub          # OpenSSH public key (from private key)
- ${PREFIX}.from-cert.openssh.pub# OpenSSH public key derived from the X.509 cert
- ${PREFIX}.pkcs12.p12          # PKCS#12 bundle (cert+key, empty password)
- ${PREFIX}.pkcs12.p12.b64      # PKCS#12 bundle base64 (single line)
- ${PREFIX}.pkcs12.p12.b64.wrap # PKCS#12 bundle base64 (wrapped)
- ${PREFIX}.pkcs12.p12.pem      # PKCS#12 bundle (PEM wrapped)
- ${PREFIX}.pkcs12.pfx          # PKCS#12 bundle copy (.pfx alias)

Usage:
  ./mk_all_keys.sh                 # writes wildcard.*
  ./mk_all_keys.sh mykey           # writes mykey.*
EOF

