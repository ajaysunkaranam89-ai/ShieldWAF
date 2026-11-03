"""Small server-side SVG charts for the Dashboards page: Grafana-style panels, no JavaScript and no chart library (the panel's
Content-Security-Policy forbids inline scripts, and SVG drawn on the server needs none). All text that ends up in the SVG is escaped."""
import math
import time
from html import escape

PALETTE = {"green": "#73BF69", "yellow": "#F2CC0C", "orange": "#FF9830", "red": "#F2495C", "blue": "#5794F2", "purple": "#B877D9", "cyan": "#4ED1E0"}
W, LEFT, RIGHT, TOP, BOTTOM = 640, 46, 10, 10, 24


def human(v):
    """1234 -> 1.2K, 0.5 -> 0.5"""
    v = float(v)
    for lim, suf in ((1e9, "G"), (1e6, "M"), (1e3, "K")):
        if abs(v) >= lim:
            return f"{v / lim:.1f}".rstrip("0").rstrip(".") + suf
    return f"{v:.1f}".rstrip("0").rstrip(".") if v != int(v) else str(int(v))


def _nice_max(v):
    if v <= 0:
        return 1
    e = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * e:
            return m * e
    return 10 * e


def clock(ts, span):
    t = time.localtime(ts)
    return time.strftime("%H:%M" if span <= 2 * 86400 else "%d %b %H:%M", t)


def timeseries(starts, series, kind="area", stacked=False, h=210, span=3600, unit="", W=W):
    """starts: bucket start times; series: [{"name","color","values"}]. kind: "area" (lines with fill) or "bar" (columns)."""
    n = max(len(starts), 1)
    plot_w, plot_h = W - LEFT - RIGHT, h - TOP - BOTTOM
    cum = [0.0] * n
    layers = []
    for s in series:
        vals = [float(x or 0) for x in s["values"]]
        base = list(cum) if stacked else [0.0] * n
        top = [b + v for b, v in zip(base, vals)]
        if stacked:
            cum = top
        layers.append((s, vals, base, top))
    ymax = _nice_max(max([max(t) for _, _, _, t in layers] + [0]))
    x = lambda i: LEFT + (i + 0.5) * plot_w / n  # noqa: E731
    y = lambda v: TOP + plot_h - (v / ymax) * plot_h  # noqa: E731
    o = [f'<svg viewBox="0 0 {W} {h}" width="100%" role="img" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" class="chart">']
    for k in range(5):
        v = ymax * k / 4
        o.append(f'<line x1="{LEFT}" x2="{W - RIGHT}" y1="{y(v):.1f}" y2="{y(v):.1f}" stroke="#27325a" stroke-width="1"/>'
                 f'<text x="{LEFT - 6}" y="{y(v) + 4:.1f}" text-anchor="end" font-size="11" fill="#97a3d0">{escape(human(v))}{escape(unit)}</text>')
    for k in range(0, n, max(1, n // 6)):
        o.append(f'<text x="{x(k):.1f}" y="{h - 7}" text-anchor="middle" font-size="11" fill="#97a3d0">{escape(clock(starts[k], span))}</text>')
    bw = max(1.0, plot_w / n * 0.8)
    for s, vals, base, top in layers:
        c = s["color"]
        if kind == "bar":
            for i in range(n):
                if vals[i] > 0:
                    o.append(f'<rect x="{x(i) - bw / 2:.1f}" y="{y(top[i]):.1f}" width="{bw:.1f}" height="{max(0.5, y(base[i]) - y(top[i])):.1f}" fill="{c}"/>')
        else:
            pts = " ".join(f"{x(i):.1f},{y(top[i]):.1f}" for i in range(n))
            back = " ".join(f"{x(i):.1f},{y(base[i]):.1f}" for i in range(n - 1, -1, -1))
            o.append(f'<polygon points="{pts} {back}" fill="{c}" fill-opacity="0.22"/><polyline points="{pts}" fill="none" stroke="{c}" stroke-width="1.6" stroke-linejoin="round"/>')
    for i in range(n):          # invisible hover columns: the browser shows the <title> as a tooltip
        tip = clock(starts[i], span) + "".join(f"\n{s['name']}: {human(v[i])}{unit}" for s, v, _, _ in layers)
        o.append(f'<rect x="{x(i) - plot_w / n / 2:.1f}" y="{TOP}" width="{plot_w / n:.1f}" height="{plot_h}" fill="transparent"><title>{escape(tip)}</title></rect>')
    o.append("</svg>")
    return "".join(o)


def sparkline(values, color="#5794F2", w=120, h=34):
    vals = [float(v or 0) for v in values] or [0.0]
    mx = max(vals) or 1.0
    n = len(vals)
    pts = " ".join(f"{(i / max(n - 1, 1)) * (w - 2) + 1:.1f},{h - 2 - (v / mx) * (h - 6):.1f}" for i, v in enumerate(vals))
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" class="spark">'
            f'<polygon points="1,{h - 2} {pts} {w - 1},{h - 2}" fill="{color}" fill-opacity="0.2"/><polyline points="{pts}" fill="none" stroke="{color}" stroke-width="1.5"/></svg>')
