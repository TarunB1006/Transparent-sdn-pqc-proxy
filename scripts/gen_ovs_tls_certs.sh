#!/usr/bin/env bash
# Certificates for the native Open vSwitch TLS baseline of the fat-tree
# experiment (ECDSA P-256, one CA). Written to evaluation/tls_certs/.
set -euo pipefail
cd "$(dirname "$0")/.."
D=evaluation/tls_certs
mkdir -p "$D"
openssl ecparam -name prime256v1 -genkey -noout -out "$D/ca-key.pem"
openssl req -x509 -new -key "$D/ca-key.pem" -subj "/CN=pqc-sdn-classical-ca" -days 365 -out "$D/ca-cert.pem"
for who in ctrl sw; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$D/$who-key.pem"
  openssl req -new -key "$D/$who-key.pem" -subj "/CN=pqc-sdn-$who" -out "$D/$who-req.pem"
  openssl x509 -req -in "$D/$who-req.pem" -CA "$D/ca-cert.pem" -CAkey "$D/ca-key.pem" \
    -CAcreateserial -days 365 -out "$D/$who-cert.pem"
done
chmod 600 "$D"/*-key.pem
echo "certificates written to $D"
