"""Default visitor-facing pages. Placeholders: {{SITE}} = the site's hostname."""

_CSS = """
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:Segoe UI,system-ui,sans-serif;color:#fff;
background:linear-gradient(-45deg,%(g)s);background-size:400%% 400%%;animation:bg 14s ease infinite}
@keyframes bg{0%%{background-position:0%% 50%%}50%%{background-position:100%% 50%%}100%%{background-position:0%% 50%%}}
.card{width:min(92vw,560px);padding:2.6rem 2.2rem;text-align:center;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.4);
border-radius:24px;backdrop-filter:blur(14px);box-shadow:0 20px 60px rgba(0,0,0,.35)}
.ic{font-size:5rem;display:inline-block;animation:%(anim)s;filter:drop-shadow(0 6px 10px rgba(0,0,0,.35))}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%%,100%%{transform:scale(1)}50%%{transform:scale(1.18)}}
h1{margin:.4rem 0 .6rem;font-size:2.1rem;text-shadow:0 3px 12px rgba(0,0,0,.35)}
p{margin:.3rem 0;font-size:1.1rem;opacity:.95;line-height:1.5}
.bar{margin:1.8rem auto 1rem;height:12px;width:80%%;background:rgba(255,255,255,.28);border-radius:99px;overflow:hidden}
.bar i{display:block;height:100%%;width:40%%;border-radius:99px;background:linear-gradient(90deg,%(b)s);animation:load 2.2s ease-in-out infinite}
@keyframes load{0%%{margin-left:-40%%}100%%{margin-left:100%%}}
.tag{display:inline-block;margin-top:1rem;padding:.4rem 1rem;border-radius:99px;background:rgba(0,0,0,.28);font-size:.9rem;letter-spacing:.04em}
"""

_TPL = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '%(refresh)s<title>%(title)s</title><style>%(css)s</style></head><body><div class="card"><div class="ic">%(icon)s</div>'
        '<h1>%(h1)s</h1>%(body)s<div class="bar"><i></i></div><span class="tag">%(tag)s</span></div></body></html>')

DEFAULT_MAINTENANCE = _TPL % {
    "refresh": "", "title": "{{SITE}} is under maintenance",
    "css": _CSS % {"g": "#ff6a00,#ee0979,#7f00ff,#00c6ff", "b": "#ffe53b,#ff2525,#00f5a0", "anim": "spin 6s linear infinite"},
    "icon": "&#9881;&#65039;", "h1": "We will be back soon!",
    "body": "<p>Our application is getting a <b>fresh upgrade</b>.</p><p>Thank you for your patience &#128156;</p>",
    "tag": "&#128736;&#65039; Scheduled maintenance &middot; please try again shortly",
}

DEFAULT_DOWN = _TPL % {
    "refresh": '<meta http-equiv="refresh" content="10">', "title": "{{SITE}} is getting back up",
    "css": _CSS % {"g": "#11998e,#38ef7d,#0575e6,#021b79", "b": "#f9d423,#ff4e50,#fc00ff", "anim": "pulse 2s ease-in-out infinite"},
    "icon": "&#128260;", "h1": "We are getting back up",
    "body": ("<p>The service is temporarily unavailable.</p><p>This page checks again <b>automatically</b>, "
             "and you will be taken to the app as soon as it is ready.</p>"),
    "tag": "&#128260; Auto-retry every 10 seconds",
}


def fill(html, host):
    return html.replace("{{SITE}}", host)
