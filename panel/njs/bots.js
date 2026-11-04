/* ShieldWAF bot protection (njs). Runs inside nginx; no extra service and no per-request network call.
   Variables set per site by the renderer: $bot_mode (detect|block|challenge), $bot_thr (score that counts as a bot), $bot_excl (path prefixes that are never
   judged, for example an API), $bot_allow (user-agent fragments that are never judged).
   Every request gets a score from header behaviour that real browsers show and scripts usually do not. The score is a hint, not a proof: it is combined with the
   OWASP rules, the rate limit and, in mode "challenge", the proof-of-work page that a script has to solve before it gets through.
   js_set $bot_score  -> the number (also written to the access log and sent to the application in X-Shield-Bot-Score)
   js_set $bot_action -> "" (pass) | "block" | "challenge" */

import challenge from 'challenge.js';

var SCANNERS = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wpscan|havij|zgrab|nuclei|jaeles|whatweb|w3af|netsparker|burpcollaborator|metasploit|hydra|ffuf|feroxbuster|dirsearch|nessus)/i;
var AUTOMATION = /(curl\/|wget\/|python-requests|python-urllib|aiohttp|httpx|go-http-client|java\/|apache-httpclient|okhttp|libwww-perl|lwp::|scrapy|node-fetch|axios\/|got \(|undici|headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver|casperjs|mechanize|http_request2|guzzle|ruby|powershell|postmanruntime|insomnia)/i;
var CRAWLER = /(bot\b|crawler|spider|scraper|fetcher|harvest|extractor)/i;

function h(r, name) { return r.headersIn[name] || ''; }

function score(r) {
  var ua = h(r, 'User-Agent'), pts = 0;
  if (!ua) return '6';                                          // no user agent at all
  if (SCANNERS.test(ua)) pts += 10;
  else if (AUTOMATION.test(ua)) pts += 4;
  else if (CRAWLER.test(ua)) pts += 3;
  var browser = /^Mozilla\//.test(ua);
  if (browser) {                                                // it says it is a browser: a browser also sends these
    if (!h(r, 'Accept')) pts += 2;
    if (!h(r, 'Accept-Language')) pts += 2;
    if (!h(r, 'Accept-Encoding')) pts += 1;
    if (r.httpVersion === '1.0') pts += 2;
    var cm = ua.match(/Chrome\/(\d+)/);
    if (r.variables.scheme === 'https' && cm && parseInt(cm[1], 10) >= 90 && !h(r, 'Sec-Fetch-Site') && !h(r, 'Sec-Ch-Ua')) pts += 2;
    if (/HeadlessChrome/.test(ua)) pts += 4;
  }
  if (h(r, 'X-Forwarded-For') && !/^[0-9a-fA-F:., ]+$/.test(h(r, 'X-Forwarded-For'))) pts += 3;   // a malformed forwarding header is crafted, not produced by a proxy
  return String(pts);
}

function action(r) {
  var uri = r.variables.uri || '';
  if (uri.indexOf('/__shield/') === 0) return '';
  var excl = (r.variables.bot_excl || '').split(' ');
  for (var i = 0; i < excl.length; i++) if (excl[i] && uri.indexOf(excl[i]) === 0) return '';
  var ua = (r.headersIn['User-Agent'] || '').toLowerCase(), allow = (r.variables.bot_allow || '').split(' ');
  for (var j = 0; j < allow.length; j++) if (allow[j] && ua.indexOf(allow[j].toLowerCase()) >= 0) return '';
  var thr = parseInt(r.variables.bot_thr || '6', 10), mode = r.variables.bot_mode || 'detect';
  if (parseInt(r.variables.bot_score, 10) < thr) return '';
  if (mode === 'detect') return '';
  if (mode === 'challenge' && challenge.valid(r)) return '';      // already solved the proof-of-work page: let it through
  return mode;
}

export default { score: score, action: action };
