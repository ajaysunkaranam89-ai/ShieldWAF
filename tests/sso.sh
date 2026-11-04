#!/usr/bin/env bash
# Single sign-on test against Dex (a real OpenID Connect identity provider) with throw-away Docker containers: the panel (image shieldwaf:2.3),
# Dex, and a "browser" script (tests/sso_client.py). Needs Docker, the image shieldwaf:2.3 and internet access to pull ghcr.io/dexidp/dex.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-sso-test
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
WORK="$HERE/.sso-work"
cleanup() { docker rm -f sw-sso-dex sw-sso-panel >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -rf "$WORK"; }
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup
mkdir -p "$WORK"
docker network create --subnet 10.79.0.0/24 $NET >/dev/null || exit 1

# a throw-away certificate authority and a certificate for the identity provider (the panel trusts this CA only for this test)
docker run --rm --entrypoint sh -v "$(WIN "$WORK"):/out" shieldwaf:2.3 -c '
  cd /out &&
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=sso-test-ca" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.pem 2>/dev/null &&
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=dex" -keyout dex.key -out dex.csr 2>/dev/null &&
  printf "subjectAltName=DNS:dex\n" > ext.cnf &&
  openssl x509 -req -in dex.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out dex.crt 2>/dev/null &&
  chmod 644 *.pem *.crt *.key' || exit 1

HASH='$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W'    # the bcrypt hash of the word "password" from Dex's own documentation
cat > "$WORK/dex.yaml" <<EOF
issuer: https://dex:5556/dex
storage: {type: memory}
web: {https: 0.0.0.0:5556, tlsCert: /certs/dex.crt, tlsKey: /certs/dex.key}
oauth2: {skipApprovalScreen: true}
enablePasswordDB: true
staticClients:
  - {id: shieldwaf, name: "A Shield WAF", secret: testsecret, redirectURIs: ["https://panel:9000/sso/callback"]}
staticPasswords:
  - {email: "alice@example.test", hash: "$HASH", username: alice, userID: "11111111-1111-1111-1111-111111111111"}
  - {email: "bob@example.test", hash: "$HASH", username: bob, userID: "22222222-2222-2222-2222-222222222222"}
  - {email: "carol@other.test", hash: "$HASH", username: carol, userID: "33333333-3333-3333-3333-333333333333"}
EOF
docker run -d --name sw-sso-dex --network $NET --network-alias dex -v "$(WIN "$WORK"):/certs:ro" -v "$(WIN "$WORK")/dex.yaml:/etc/dex/config.yaml:ro" \
  ghcr.io/dexidp/dex:v2.41.1 dex serve /etc/dex/config.yaml >/dev/null || exit 1
docker run -d --name sw-sso-panel --network $NET --network-alias panel -e SHIELD_OIDC_TEST_CA=/ca.pem -e SHIELD_OIDC_ALLOW_PRIVATE=1 \
  -v "$(WIN "$WORK")/ca.pem:/ca.pem:ro" shieldwaf:2.3 >/dev/null || exit 1
for i in $(seq 1 40); do
  docker exec sw-sso-panel python3 -c "import ssl,urllib.request as u; c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; u.urlopen('https://127.0.0.1:9000/healthz', context=c, timeout=3)" >/dev/null 2>&1 && break
  sleep 2
done

# configure the panel the way an administrator would (through the settings; here directly, because no one is logged in yet)
docker exec sw-sso-panel python3 -c "
import time, store, oidc
from werkzeug.security import generate_password_hash
store.init_db()
cfg = store.load()
cfg['users']['localadmin'] = {'hash': generate_password_hash('correct-horse-Battery-9'), 'created': time.time(), 'totp_secret': '', 'totp_enabled': False, 'totp_last': 0, 'recovery': [], 'role': 'admin', 'must_change': False}
cfg['settings']['sso'].update(enabled=True, issuer='https://dex:5556/dex', client_id='shieldwaf', redirect_base='https://panel:9000', allowed_domains='example.test',
                              admin_emails='alice@example.test', default_role='viewer', button_label='Sign in with SSO')
assert oidc.validate_settings(cfg['settings']['sso']) is None
oidc.save_secret('testsecret')
store.save(cfg)
print('panel configured')
" || { docker logs sw-sso-panel 2>&1 | tail -20; exit 1; }
sleep 3
docker run --rm --network $NET -v "$ROOT/panel:/panel:ro" -v "$HERE/sso_client.py:/t/sso_client.py:ro" --entrypoint python3 shieldwaf:2.3 -u /t/sso_client.py
RC=$?
if [ $RC != 0 ]; then echo "--- panel log (tail)"; docker logs sw-sso-panel 2>&1 | grep -v healthz | tail -15; fi
exit $RC
