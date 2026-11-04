"""CrowdSec bouncer against a REAL CrowdSec Local API (tests/crowdsec.sh creates the server, the bouncer key and the decisions and changes them between the phases).
Runs inside the shieldwaf image; the state directory is shared between the phases. Usage: python3 crowdsec_test.py 1|2   (environment: CS_KEY)"""
import ipaddress
import os
import sys
import time

os.environ.setdefault("SHIELD_DATA", "/state")
sys.path.insert(0, "/panel")
import crowdsec  # noqa: E402
import feeds  # noqa: E402

KEY = os.environ["CS_KEY"]
PHASE = sys.argv[1] if len(sys.argv) > 1 else "1"
RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


def cfg(url="http://crowdsec:8080"):
    return {"settings": {"crowdsec": {"url": url, "enabled": True}, "upstream_private_allow": ""}}


def nets():
    return sorted(str(n) for n in crowdsec.entries())


if PHASE == "1":
    crowdsec.set_key(KEY)
    mode = oct(os.stat(crowdsec.SECRET).st_mode & 0o777)
    check("the bouncer key is stored in the panel-only secrets folder with mode 600", mode == "0o600", mode)
    ok, count, err = crowdsec.pull(cfg())
    check("the first pull (full list) succeeds", ok, err)
    got = nets()
    check("a single address and a range are taken over", "45.9.148.10/32" in got and "91.92.240.0/24" in got, got)
    check("a captcha decision is not a ban and is ignored", "45.9.148.11/32" not in got, got)
    check("a private address and a far too wide range (/4) are dropped (they could lock out real users)", not any(n.startswith("10.") or n.endswith("/4") for n in got), got)
    check("the count equals the usable decisions", count == len(got) == 2, (count, got))
else:
    ok, count, err = crowdsec.pull(cfg())
    got = nets()
    check("an incremental pull removes a deleted decision and adds a new one", ok and "45.9.148.10/32" not in got and "185.220.101.5/32" in got and "91.92.240.0/24" in got, (err, got))
    n = feeds.rebuild([], crowdsec.entries())
    lst = open(os.path.join(feeds.FEED_DIR, "feed.geo")).read()
    check("the engine's list contains the CrowdSec decisions", n == 2 and "185.220.101.5/32 1;" in lst and "91.92.240.0/24 1;" in lst, lst)
    n = feeds.rebuild([ipaddress.ip_network("91.92.240.0/24")], crowdsec.entries())
    check("a protected network (administrators, never_ban) is never listed", n == 1 and "91.92.240" not in open(os.path.join(feeds.FEED_DIR, "feed.geo")).read())
    st = crowdsec._load()
    st["decisions"]["185.220.101.5/32"] = time.time() - 5
    crowdsec._save(st)
    check("a decision whose time is over disappears locally even without asking the server", "185.220.101.5/32" not in nets(), nets())
    crowdsec.set_key("wrong-key")
    ok, count, err = crowdsec.pull(cfg())
    check("a wrong key is reported clearly (HTTP 403) and the old list stays", (not ok) and "403" in err and "91.92.240.0/24" in nets(), (ok, err, nets()))
    crowdsec.set_key(KEY)
    ok, count, err = crowdsec.pull(cfg("http://crowdsec-nonexistent:8080"))
    check("an unreachable server keeps the old list and says so", (not ok) and "91.92.240.0/24" in nets() and bool(err), (ok, err))
    ok, count, err = crowdsec.pull(cfg("http://127.0.0.1:8080"))
    check("a loopback address is refused by the network guard (never allowed)", not ok and "refused" in err.lower(), err)
    ok, count, err = crowdsec.pull(cfg("http://169.254.169.254/latest"))
    check("the cloud metadata address is refused", not ok and "refused" in err.lower(), err)
    check("duration parsing handles CrowdSec's format", crowdsec.duration_seconds("3h59m12.5s") == 3 * 3600 + 59 * 60 + 12 and crowdsec.duration_seconds("30m") == 1800
          and crowdsec.duration_seconds("") == 4 * 3600)

bad = RESULTS.count(False)
print(f"{len(RESULTS) - bad}/{len(RESULTS)} CrowdSec checks passed in phase {PHASE}")
sys.exit(1 if bad else 0)
