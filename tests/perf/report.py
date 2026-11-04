"""Prints the results of tests/perf/perf.sh as a table (argument: the folder with the JSON files)."""
import json
import os
import sys

d = sys.argv[1]
print(f"{'case':32} {'req/s':>9} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'failed':>7}")
base = None
for f in sorted(os.listdir(d)):
    if not f.endswith(".json"):
        continue
    r = json.load(open(os.path.join(d, f)))
    name = f[:-5]
    if name == "v24_plain":
        base = r["rps"]
    print(f"{name:32} {r['rps']:9.0f} {r['p50']:8.2f} {r['p95']:8.2f} {r['p99']:8.2f} {r['failed']:7.2%}")
if base:
    print("\nrelative to v24_plain (req/s):")
    for f in sorted(os.listdir(d)):
        if f.endswith(".json") and f != "v24_plain.json":
            r = json.load(open(os.path.join(d, f)))
            print(f"  {f[:-5]:30} {100.0 * r['rps'] / base:6.1f} %")
