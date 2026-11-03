/* ShieldWAF anti-bot challenge (njs). Runs inside nginx; no extra service.
   Variables set per site by the renderer: $chal_diff, $chal_ttl, $chal_scope (pages|all), $chal_excl (path prefixes).
   Flow: no valid cookie -> rewrite to /__shield/page (proof-of-work page) -> GET /__shield/verify -> signed cookie -> back to the URL.
   The cookie is an HMAC (key in /data/challenge.key) bound to client IP + User-Agent + host + expiry, so it cannot be forged or shared. */
import crypto from 'crypto';
import fs from 'fs';

var KEY = null, PAGE = null, POW = null;

function key() {
  if (KEY === null) {
    try { KEY = fs.readFileSync('/data/challenge.key', 'utf8').trim(); } catch (e) { KEY = ''; }
  }
  return KEY;
}

function mac(parts) { return crypto.createHmac('sha256', key()).update(parts.join('|')).digest('hex'); }

function same(a, b) {   // constant-time string compare
  if (a.length !== b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function ident(r) {
  return r.variables.remote_addr + '|' + (r.headersIn['User-Agent'] || '').slice(0, 200) + '|' + r.variables.host;
}

function getCookie(r, name) {
  var parts = (r.headersIn.Cookie || '').split(/;\s*/);
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].indexOf(name + '=') === 0) return parts[i].slice(name.length + 1);
  }
  return '';
}

/* js_set $chal_need: "1" when this request must solve the challenge first, else "0" */
function need(r) {
  var uri = r.variables.uri;
  if (uri.indexOf('/__shield/') === 0) return '0';
  var excl = (r.variables.chal_excl || '').split(' ');
  for (var i = 0; i < excl.length; i++) {
    if (excl[i] && uri.indexOf(excl[i]) === 0) return '0';
  }
  if (!key()) return '1';                                   // fail closed: no key, no free pass
  if ((r.variables.chal_scope || 'pages') === 'pages') {
    var acc = r.headersIn['Accept'] || '';
    if (r.variables.request_method !== 'GET' || acc.indexOf('text/html') < 0) return '0';   // only browser page loads
  }
  var ck = getCookie(r, '__shield_ok'), p = ck.split('.');
  if (p.length === 2) {
    var exp = parseInt(p[0], 10);
    if (exp > Date.now() / 1000 && same(p[1], mac(['ok', ident(r), p[0]]))) return '0';
  }
  return '1';
}

function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return '&#' + c.charCodeAt(0) + ';'; }); }

function page(r) {
  if (PAGE === null) {
    PAGE = fs.readFileSync('/panel/njs/challenge.html', 'utf8');
    POW = fs.readFileSync('/panel/njs/pow.js', 'utf8');
  }
  var diff = parseInt(r.variables.chal_diff, 10) || 4;
  var ts = Math.floor(Date.now() / 1000);
  var seed = ts + '.' + mac(['seed', r.variables.remote_addr, ts, diff]);
  var html = PAGE.split('/*POW*/').join(POW)
    .split('__SEED__').join(seed)
    .split('__DIFF__').join(String(diff))
    .split('__RET__').join(encodeURIComponent(r.variables.request_uri))
    .split('__HOST__').join(esc(r.variables.host));
  r.headersOut['Content-Type'] = 'text/html; charset=utf-8';
  r.headersOut['Cache-Control'] = 'no-store';
  r.headersOut['X-Shield-Challenge'] = '1';
  r.return(200, html);
}

function verify(r) {
  var diff = parseInt(r.variables.chal_diff, 10) || 4;
  var ttl = parseInt(r.variables.chal_ttl, 10) || 43200;
  var seed = String(r.args.seed || ''), nonce = String(r.args.nonce || '');
  var parts = seed.split('.');
  if (!key() || parts.length !== 2 || !/^\d{1,12}$/.test(parts[0]) || !/^\d{1,12}$/.test(nonce)) { r.return(400); return; }
  var ts = parseInt(parts[0], 10), now = Math.floor(Date.now() / 1000);
  if (now - ts > 300 || ts - now > 5) { r.return(410); return; }                                   // seed too old
  if (!same(parts[1], mac(['seed', r.variables.remote_addr, ts, diff]))) { r.return(403); return; }   // not issued to this IP
  var h = crypto.createHash('sha256').update(seed + ':' + nonce).digest('hex');
  if (h.indexOf('0'.repeat(diff)) !== 0) { r.return(403); return; }                                 // work not done
  var exp = now + ttl;
  var c = '__shield_ok=' + exp + '.' + mac(['ok', ident(r), String(exp)]) + '; Path=/; Max-Age=' + ttl + '; HttpOnly; SameSite=Lax';
  if (r.variables.scheme === 'https') c += '; Secure';
  r.headersOut['Set-Cookie'] = c;
  r.headersOut['Cache-Control'] = 'no-store';
  r.return(204);
}

export default { need, page, verify };
