"""Break-glass operator tools (run inside the panel container, needs cluster access):
  kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-panel-allow
  kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-2fa <username>
  kubectl exec -i -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py set-password <username>   (new password on stdin)
These need kubectl exec rights, which is why they are safe to offer: whoever has them already controls the pod."""
import sys

from werkzeug.security import generate_password_hash

import store


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cfg = store.load()
    cmd = argv[0]
    if cmd == "reset-panel-allow":
        cfg["settings"]["panel_allow_ips"] = ""
        store.save(cfg)
        store.audit("operator", "reset-panel-allow", "via tools.py")
        print("panel allow-list cleared")
    elif cmd == "reset-2fa" and len(argv) == 2 and argv[1] in cfg["users"]:
        cfg["users"][argv[1]].update({"totp_secret": "", "totp_enabled": False, "recovery": []})
        store.save(cfg)
        store.audit("operator", "reset-2fa", argv[1])
        print("2FA disabled for", argv[1])
    elif cmd == "set-password" and len(argv) == 2 and argv[1] in cfg["users"]:
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < 12:
            print("password must be at least 12 characters")
            return 1
        cfg["users"][argv[1]]["hash"] = generate_password_hash(pw)
        store.save(cfg)
        store.db().execute("DELETE FROM sessions WHERE user=?", (argv[1],))
        store.db().commit()
        store.audit("operator", "set-password", argv[1])
        print("password updated and all sessions of", argv[1], "signed out")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
