"""Runs once before the panel starts (see panel-entrypoint.sh): makes sure the files every replica must share exist and are in place.
With several replicas starting together, the first one creates each file and publishes it; the others adopt that copy."""
import os
import subprocess
import sys

import sharedfs
import store

DATA = store.DATA


def _challenge_key():
    fd = os.open(os.path.join(DATA, "challenge.key"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(os.urandom(32).hex())


def _panel_cert():
    d = os.path.join(DATA, "certs", "panel")
    os.makedirs(d, mode=0o700, exist_ok=True)
    r = subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "825",
                        "-subj", "/CN=shieldwaf-panel", "-addext", "subjectAltName=DNS:shieldwaf-panel,DNS:localhost,IP:127.0.0.1",
                        "-keyout", os.path.join(d, "privkey.pem"), "-out", os.path.join(d, "fullchain.pem")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("openssl failed: " + r.stderr[-200:])
    os.chmod(os.path.join(d, "privkey.pem"), 0o600)


def main():
    os.umask(0o077)
    os.makedirs(os.path.join(DATA, "logs"), exist_ok=True)
    store.init_db()
    sharedfs.sync_in()
    sharedfs.ensure("challenge.key", _challenge_key)
    # Optional: mount your own certificate at /panel-tls/tls.crt + tls.key (for example from cert-manager) to replace the self-signed one.
    if not (os.path.exists("/panel-tls/tls.crt") and os.path.exists("/panel-tls/tls.key")):
        sharedfs.ensure("certs/panel", _panel_cert)
        if not os.path.exists(os.path.join(DATA, "certs", "panel", "fullchain.pem")):
            _panel_cert()
    return 0


if __name__ == "__main__":
    sys.exit(main())
