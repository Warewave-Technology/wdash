#!/bin/bash
# Certificates for the lab's TLS monitors. Idempotent: it leaves existing
# files alone, so restarting the lab does not shuffle the expiry dates the
# page is showing.
set -e
cd "$(dirname "$0")/certs"

make_one() {
    local name=$1 days=$2 cn=$3
    [ -f "$name.crt" ] && return 0
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$name.key" -out "$name.crt" -days "$days" \
        -subj "/CN=$cn/O=Warewave Lab" \
        -addext "subjectAltName=DNS:$cn,DNS:synthetics-targets" 2>/dev/null
    echo "  generated $name.crt (expires in $days days)"
}

# A year, so one row on the page is untroubled.
make_one healthy 365 healthy.lab.local
# Twelve days: inside the thirty-day warning band and outside the seven-day
# urgent one, so the middle state is the one the lab shows by default.
make_one expiring 12 expiring.lab.local
