#!/bin/sh
# Creates deploy/.env with random secrets for the Docker Compose installation. Safe to run again: an existing file is never changed.
# The values are kept only in that file: back it up like a password (without SHIELD_DATA_KEY the certificates stored in the database cannot be read).
set -eu
F="$(dirname "$0")/.env"
[ -e "$F" ] && { echo "$F already exists (left unchanged)"; exit 0; }
umask 077
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
{
  echo "POSTGRES_PASSWORD=$(rnd 24)"
  echo "SHIELD_DATA_KEY=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n')"
} > "$F"
echo "created $F"
