"""Container and Kubernetes hardening checks on the throw-away deployment in the namespace "shieldwaf-test" (modules C and K): what each container can see and
write, service accounts, pod security. Runs with `SUITES=hardening bash tests/run.sh`."""
import json
import subprocess
import sys

NS = "shieldwaf-test"
results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


def kube(*args, timeout=60):
    return subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout)


def pods():
    r = kube("get", "pods", "-l", "app=shieldwaf", "-o", "json")
    return [p["metadata"]["name"] for p in json.loads(r.stdout)["items"] if p["status"].get("phase") == "Running"]


def run_in(pod, container, script):
    r = kube("exec", pod, "-c", container, "--", "sh", "-c", script)
    return r.returncode, (r.stdout + r.stderr).strip()


ps = pods()
check("the test deployment has running replicas", len(ps) >= 2, ps)
pod = ps[0]

print("== C: what the engine container can and cannot reach", flush=True)
rc, out = run_in(pod, "panel", "ls -l /private/secret.key && stat -c %a /private/secret.key")
check("the panel keeps its session key in the panel-only folder with mode 600", rc == 0 and out.strip().endswith("600"), out)
rc, out = run_in(pod, "panel", "ls /data/secret.key /data/bootstrap.code /data/secrets 2>&1")
check("...and no copy of the panel-only secrets is left in /data", rc != 0 and "secret.key" in out and "No such file" in out, out)
rc, out = run_in(pod, "engine", "ls /private 2>&1")
check("the engine container has no /private at all (cannot see the panel-only secrets)", rc != 0, out)
rc, out = run_in(pod, "engine", "cat /data/secret.key /data/bootstrap.code 2>&1; ls /data/secrets 2>&1")
check("the engine cannot read the session key, setup code or secrets from /data", "No such file" in out and "secret" not in out.replace("No such file or directory", "").replace("secret.key", "").replace("secrets", ""), out)
rc, out = run_in(pod, "engine", "for f in /data/certs/probe /data/geo/probe /data/probe; do touch $f 2>&1 && echo WROTE $f; done; true")
check("the engine cannot write to /data except its own folders (certificates, rules, feeds are read-only)", "WROTE" not in out and out.count("Read-only file system") >= 2, out)
rc, out = run_in(pod, "engine", "touch /data/rendered/.probe && touch /data/logs/.probe && rm /data/rendered/.probe /data/logs/.probe && echo writable")
check("the engine can write its status files and logs", out.endswith("writable"), out)
rc, out = run_in(pod, "engine", "touch /probe 2>&1; id -u")
check("the engine runs as a non-root user with a read-only root file system", "Read-only file system" in out and out.splitlines()[-1] == "10101", out)
rc, out = run_in(pod, "engine", "wget -qO- -T 3 http://127.0.0.1:8080/__shieldwaf_health")
check("the engine is healthy with the read-only layout", rc == 0 and "gen" in out, out)

print("== C: service accounts", flush=True)
spec = json.loads(kube("get", "pod", pod, "-o", "json").stdout)["spec"]
check("the pods run under their own service account (not 'default')", spec.get("serviceAccountName") == "shieldwaf-app", spec.get("serviceAccountName"))
check("no Kubernetes API token is mounted", spec.get("automountServiceAccountToken") is False)
rc, out = run_in(pod, "panel", "ls /var/run/secrets/kubernetes.io 2>&1")
check("...so there is no token file in the panel container", rc != 0, out)
rc, out = run_in(pod, "engine", "ls /var/run/secrets/kubernetes.io 2>&1")
check("...nor in the engine container", rc != 0, out)
r = subprocess.run(["kubectl", "auth", "can-i", "get", "secrets", f"--as=system:serviceaccount:{NS}:shieldwaf-app", "-n", NS], capture_output=True, text=True)
check("the service account may not read secrets", r.stdout.strip() == "no", r.stdout + r.stderr)
r = subprocess.run(["kubectl", "auth", "can-i", "list", "pods", f"--as=system:serviceaccount:{NS}:shieldwaf-app", "-n", NS], capture_output=True, text=True)
check("...and may not list pods", r.stdout.strip() == "no", r.stdout + r.stderr)
dbspec = json.loads(kube("get", "pod", "shieldwaf-db-0", "-o", "json").stdout)["spec"]
check("the database pod has its own service account too", dbspec.get("serviceAccountName") == "shieldwaf-db", dbspec.get("serviceAccountName"))

print("== K: Kubernetes hardening", flush=True)
ns = json.loads(subprocess.run(["kubectl", "get", "ns", NS, "-o", "json"], capture_output=True, text=True).stdout)["metadata"]["labels"]
check("the namespace enforces the 'restricted' Pod Security level", ns.get("pod-security.kubernetes.io/enforce") == "restricted", ns)
full = json.loads(kube("get", "pod", pod, "-o", "json").stdout)["spec"]
cs = full["containers"]
check("every container drops all capabilities and forbids privilege escalation",
      all(c["securityContext"]["capabilities"]["drop"] == ["ALL"] and c["securityContext"]["allowPrivilegeEscalation"] is False for c in cs))
check("every container has a read-only root file system and CPU / memory requests and limits",
      all(c["securityContext"]["readOnlyRootFilesystem"] is True and c["resources"].get("limits", {}).get("memory") and c["resources"].get("requests", {}).get("cpu") for c in cs))
check("seccomp RuntimeDefault, non-root, no host network / PID / IPC", full["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault" and full["securityContext"]["runAsNonRoot"] is True
      and not full.get("hostNetwork") and not full.get("hostPID") and not full.get("hostIPC"))
keys = [t["topologyKey"] for t in full.get("topologySpreadConstraints", [])]
check("replicas are spread over nodes and zones", "kubernetes.io/hostname" in keys and "topology.kubernetes.io/zone" in keys, keys)
check("a PodDisruptionBudget protects the replicas during node maintenance", kube("get", "pdb", "-o", "name").stdout.strip() != "")
check("a default-deny NetworkPolicy exists", "shieldwaf-default-deny" in kube("get", "networkpolicy", "-o", "name").stdout)
import os
manifest = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "k8s", "namespace-guardrails.yaml"), encoding="utf-8").read()
manifest = manifest.replace("namespace: shieldwaf" + chr(10), f"namespace: {NS}" + chr(10))
r = subprocess.run(["kubectl", "apply", "--dry-run=server", "-f", "-"], input=manifest, capture_output=True, text=True)
check("the optional guard rails (LimitRange, ResourceQuota) are accepted by the cluster", r.returncode == 0 and "shieldwaf-quota" in r.stdout, r.stderr[-200:])

print()
bad = [n for n, ok in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} hardening checks passed")
if bad:
    print("FAILED:", *bad, sep="\n  ")
sys.exit(1 if bad else 0)
