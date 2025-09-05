#!/usr/bin/env bash
# mk_all_keys.sh — generate one RSA keypair and emit multiple formats
# Requires: openssl, ssh-keygen
set -euo pipefail

PREFIX="${1:-wildcard}"

echo "[1/9] Generating RSA private key (PKCS#8) ..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${PREFIX}.pkcs8.key"

echo "[2/9] Deriving RSA private key (PKCS#1) ..."
# Force traditional (PKCS#1) output explicitly
openssl pkey -in "${PREFIX}.pkcs8.key" -traditional -out "${PREFIX}.pkcs1.key"

echo "[3/9] Writing SubjectPublicKeyInfo public key (PEM: -----BEGIN PUBLIC KEY-----) ..."
openssl pkey -in "${PREFIX}.pkcs8.key" -pubout -out "${PREFIX}.spki.pub"

echo "[4/9] Writing SubjectPublicKeyInfo public key (DER) ..."
openssl pkey -in "${PREFIX}.pkcs8.key" -pubout -outform DER -out "${PREFIX}.spki.der"

echo "[5/9] Writing PKCS#1 RSA public key (PEM: -----BEGIN RSA PUBLIC KEY-----) ..."
openssl rsa -in "${PREFIX}.pkcs1.key" -pubout -RSAPublicKey_out -out "${PREFIX}.pkcs1.pub"

echo "[6/9] Writing PKCS#1 RSA public key (DER) ..."
openssl rsa -in "${PREFIX}.pkcs1.key" -pubout -RSAPublicKey_out -outform DER -out "${PREFIX}.pkcs1.der"

echo "[7/9] Creating self-signed X.509 certificate ..."
openssl req -new -x509 -key "${PREFIX}.pkcs8.key" -days 365 \
  -subj "/CN=example" -out "${PREFIX}.x509.crt"

echo "[8/9] Converting private key to OpenSSH private key format ..."
cp "${PREFIX}.pkcs8.key" "${PREFIX}.openssh.key"
# Rewrites the copied key to OpenSSH's native private-key format
ssh-keygen -p -f "${PREFIX}.openssh.key" -N "" -o -q

echo "[9/9] Writing OpenSSH public keys ..."
# From the OpenSSH private key
ssh-keygen -y -f "${PREFIX}.openssh.key" > "${PREFIX}.openssh.pub"
# Also: OpenSSH public key derived from the X.509 cert’s public key
openssl x509 -in "${PREFIX}.x509.crt" -noout -pubkey \
  | ssh-keygen -i -m PKCS8 -f /dev/stdin > "${PREFIX}.from-cert.openssh.pub"

echo "Fingerprint of OpenSSH public key:"
ssh-keygen -lf "${PREFIX}.openssh.pub" | tee "${PREFIX}.openssh.fingerprint"

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

Usage:
  ./mk_all_keys.sh                 # writes wildcard.*
  ./mk_all_keys.sh mykey           # writes mykey.*
EOF

