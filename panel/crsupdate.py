"""OWASP Core Rule Set updates: detect new releases, download and stage them safely, canary-test, promote or roll back.

Why not "silent automatic updates": rules decide what is blocked, so an unreviewed update could block your users (false positives) or, if the
download were tampered with, weaken protection. The flow is therefore: check (automatic) -> stage (automatic, downloaded over HTTPS from
github.com only, size-capped, safely extracted, version checked, SHA-256 recorded) -> canary (sites set to the "canary" channel run the new
rules in DETECT-ONLY mode, so you can compare behaviour without blocking anyone) -> promote (one click, with a rollback to the previous version)."""
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import time
import urllib.request

import store

CRS_ROOT = os.path.join(store.DATA, "crs")
BAKED = "/etc/modsecurity.d/owasp-crs"
API = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest"
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
ALLOWED_HOSTS = ("api.github.com", "github.com", "codeload.github.com")
MAX_TARBALL = 25 * 1024 * 1024
MAX_FILES = 3000
MAX_UNPACKED = 80 * 1024 * 1024


class UpdateError(ValueError):
    pass


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = re.sub(r"^https://([^/:]+).*$", r"\1", newurl)
        if not newurl.startswith("https://") or host not in ALLOWED_HOSTS:
            raise UpdateError("redirect to a host that is not allowed: " + host[:60])
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url, accept="*/*"):
    host = re.sub(r"^https://([^/:]+).*$", r"\1", url)
    if not url.startswith("https://") or host not in ALLOWED_HOSTS:
        raise UpdateError("download host not allowed")
    opener = urllib.request.build_opener(_SafeRedirect)
    return opener.open(urllib.request.Request(url, headers={"User-Agent": "A-Shield-WAF/2.2", "Accept": accept}), timeout=60)  # nosec B310 - https + host allow-list


def version_of(rules_root):
    """OWASP_CRS version string of a rule-set directory, or ''."""
    try:
        with open(os.path.join(rules_root, "rules", "REQUEST-901-INITIALIZATION.conf"), encoding="utf-8", errors="replace") as f:
            m = re.search(r"ver:'OWASP_CRS/([0-9]+\.[0-9]+\.[0-9]+)", f.read())
        return m.group(1) if m else ""
    except OSError:
        return ""


def active_dir(cfg):
    a = cfg["settings"]["crs"]["active"]
    return BAKED if a == "baked" else os.path.join(CRS_ROOT, a)


def staged_dir(cfg):
    s = cfg["settings"]["crs"]["staged"]
    return os.path.join(CRS_ROOT, s) if s and os.path.isdir(os.path.join(CRS_ROOT, s)) else None


def latest_tag():
    with _open(API, "application/vnd.github+json") as r:
        data = json.loads(r.read(2 * 1024 * 1024))
    tag = str(data.get("tag_name", ""))
    if not TAG_RE.match(tag):
        raise UpdateError(f"latest release tag looks unusual ({tag[:20]}); not a normal version")
    return tag


def stage(tag):
    """Download, safely extract and verify one release into /data/crs/<tag>. Returns (version, sha256)."""
    if not TAG_RE.match(tag):
        raise UpdateError("bad version tag")
    with _open(f"https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz") as r:
        blob = r.read(MAX_TARBALL + 1)
    if len(blob) > MAX_TARBALL:
        raise UpdateError("download larger than allowed")
    sha = hashlib.sha256(blob).hexdigest()
    os.makedirs(CRS_ROOT, exist_ok=True)
    tmp = os.path.join(CRS_ROOT, f".{tag}.tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    total = count = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf:
            parts = m.name.split("/", 1)
            rel = parts[1] if len(parts) == 2 else ""
            if not rel or not (rel.startswith(("rules/", "plugins/")) or rel == "crs-setup.conf.example"):
                continue
            if m.isdir():
                continue
            if not m.isreg() or rel.startswith("/") or ".." in rel.split("/") or "\\" in rel:
                raise UpdateError("unsafe path in the archive: " + rel[:60])
            count += 1
            total += m.size
            if count > MAX_FILES or total > MAX_UNPACKED:
                raise UpdateError("archive has too many or too large files")
            dest = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with tf.extractfile(m) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
    example = os.path.join(tmp, "crs-setup.conf.example")
    if not os.path.exists(example) or not os.path.isdir(os.path.join(tmp, "rules")):
        raise UpdateError("the archive does not look like a CRS release")
    shutil.copy(example, os.path.join(tmp, "crs-setup.conf"))
    ver = version_of(tmp)
    if ver != tag[1:]:
        raise UpdateError(f"version inside the files ({ver or '?'}) does not match the release tag {tag}")
    final = os.path.join(CRS_ROOT, tag)
    shutil.rmtree(final, ignore_errors=True)
    os.replace(tmp, final)
    return ver, sha


def prune(keep):
    """Remove staged versions that are neither active, staged nor previous."""
    if not os.path.isdir(CRS_ROOT):
        return
    for d in os.listdir(CRS_ROOT):
        if d not in keep:
            shutil.rmtree(os.path.join(CRS_ROOT, d), ignore_errors=True)
