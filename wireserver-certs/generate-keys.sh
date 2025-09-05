#!/usr/bin/env bash
# mk_all_keys.sh — generate one RSA keypair and emit multiple formats
# Requires: openssl, ssh-keygen
set -euo pipefail

PREFIX="${1:-key_$(date +%Y%m%d_%H%M%S)}"

echo "[1/7] Generating RSA private key (PKCS#8) ..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${PREFIX}.pkcs8.key"

echo "[2/7] Deriving RSA private key (PKCS#1) ..."
openssl rsa -in "${PREFIX}.pkcs8.key" -out "${PREFIX}.pkcs1.key"

echo "[3/7] Writing SubjectPublicKeyInfo public key (-----BEGIN PUBLIC KEY-----) ..."
openssl pkey -in "${PREFIX}.pkcs8.key" -pubout -out "${PREFIX}.spki.pub"

echo "[4/7] Writing PKCS#1 RSA public key (-----BEGIN RSA PUBLIC KEY-----) ..."
openssl rsa -in "${PREFIX}.pkcs1.key" -pubout -RSAPublicKey_out -out "${PREFIX}.pkcs1.pub"

echo "[5/7] Creating self-signed X.509 certificate ..."
openssl req -new -x509 -key "${PREFIX}.pkcs8.key" -days 365 \
  -subj "/CN=example" -out "${PREFIX}.x509.crt"

echo "[6/7] Converting private key to OpenSSH private key format ..."
cp "${PREFIX}.pkcs8.key" "${PREFIX}.openssh.key"
# Rewrites the copied key to OpenSSH's native private-key format
ssh-keygen -p -f "${PREFIX}.openssh.key" -N "" -o -q

echo "[7/7] Writing OpenSSH public keys ..."
# From the OpenSSH private key
ssh-keygen -y -f "${PREFIX}.openssh.key" > "${PREFIX}.openssh.pub"
# Also: OpenSSH public key derived from the X.509 cert’s public key
openssl x509 -in "${PREFIX}.x509.crt" -noout -pubkey \
  | ssh-keygen -i -m PKCS8 -f /dev/stdin > "${PREFIX}.from-cert.openssh.pub"

echo "Fingerprint of OpenSSH public key:"
ssh-keygen -lf "${PREFIX}.openssh.pub" | tee "${PREFIX}.openssh.fingerprint"

cat <<EOF

Done. Files generated:

- ${PREFIX}.pkcs8.key            # RSA private key (PKCS#8, PEM)
- ${PREFIX}.pkcs1.key            # RSA private key (PKCS#1, PEM)
- ${PREFIX}.spki.pub             # Public key (SubjectPublicKeyInfo, PEM: "BEGIN PUBLIC KEY")
- ${PREFIX}.pkcs1.pub            # RSA public key (PKCS#1, PEM: "BEGIN RSA PUBLIC KEY")
- ${PREFIX}.x509.crt             # Self-signed X.509 certificate (PEM: "BEGIN CERTIFICATE")
- ${PREFIX}.openssh.key          # OpenSSH private key ("BEGIN OPENSSH PRIVATE KEY")
- ${PREFIX}.openssh.pub          # OpenSSH public key (from private key)
- ${PREFIX}.from-cert.openssh.pub# OpenSSH public key derived from the X.509 cert

Usage:
  ./mk_all_keys.sh                 # writes key_YYYYmmdd_HHMMSS.*
  ./mk_all_keys.sh mykey           # writes mykey.*
EOF

