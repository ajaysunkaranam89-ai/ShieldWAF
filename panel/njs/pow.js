/* ShieldWAF anti-bot challenge: browser-side proof of work (pure JS SHA-256, no secure context needed).
   Finds a nonce so that SHA-256(seed + ":" + nonce) starts with `diff` hex zeros, then asks the server to verify it. */
var ShieldPow = (function () {
  var K = new Uint32Array(64), H0 = new Uint32Array(8);
  (function init() {
    var primes = [], c = 2, i;
    while (primes.length < 64) {
      var ok = true;
      for (i = 0; i < primes.length; i++) { if (c % primes[i] === 0) { ok = false; break; } }
      if (ok) primes.push(c);
      c++;
    }
    for (i = 0; i < 64; i++) K[i] = Math.floor((Math.pow(primes[i], 1 / 3) % 1) * 4294967296);
    for (i = 0; i < 8; i++) H0[i] = Math.floor((Math.pow(primes[i], 1 / 2) % 1) * 4294967296);
  })();
  var W = new Int32Array(64), st = new Int32Array(8);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function block(buf, off) {
    var i, a, b, c, d, e, f, g, h, t1, t2, w15, w2;
    for (i = 0; i < 16; i++) {
      W[i] = (buf[off + 4 * i] << 24) | (buf[off + 4 * i + 1] << 16) | (buf[off + 4 * i + 2] << 8) | buf[off + 4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
      w15 = W[i - 15]; w2 = W[i - 2];
      W[i] = (W[i - 16] + (rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3)) + W[i - 7] + (rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10))) | 0;
    }
    a = st[0]; b = st[1]; c = st[2]; d = st[3]; e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0; i < 64; i++) {
      t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    st[0] = (st[0] + a) | 0; st[1] = (st[1] + b) | 0; st[2] = (st[2] + c) | 0; st[3] = (st[3] + d) | 0;
    st[4] = (st[4] + e) | 0; st[5] = (st[5] + f) | 0; st[6] = (st[6] + g) | 0; st[7] = (st[7] + h) | 0;
  }

  /* SHA-256 of an ASCII string; returns the 8 state words (signed ints) */
  function sha256(str) {
    var L = str.length, blocks = Math.ceil((L + 9) / 64), buf = new Uint8Array(blocks * 64), i;
    for (i = 0; i < L; i++) buf[i] = str.charCodeAt(i) & 255;
    buf[L] = 0x80;
    var bits = L * 8;
    buf[blocks * 64 - 4] = (bits >>> 24) & 255; buf[blocks * 64 - 3] = (bits >>> 16) & 255;
    buf[blocks * 64 - 2] = (bits >>> 8) & 255; buf[blocks * 64 - 1] = bits & 255;
    for (i = 0; i < 8; i++) st[i] = H0[i] | 0;
    for (i = 0; i < blocks; i++) block(buf, i * 64);
    return st;
  }

  function hex(str) {
    var s = sha256(str), out = "";
    for (var i = 0; i < 8; i++) out += ("00000000" + (s[i] >>> 0).toString(16)).slice(-8);
    return out;
  }

  /* leading zero hex digits check using only the first state word (diff <= 8) */
  function ok(str, diff) { return (sha256(str)[0] >>> (32 - 4 * diff)) === 0; }

  /* Solve asynchronously in small slices so the page stays responsive. cb(nonce) when found. */
  function solve(seed, diff, onProgress, cb) {
    var n = 0, t0 = Date.now();
    (function slice() {
      var end = Date.now() + 25;
      while (Date.now() < end) {
        for (var k = 0; k < 500; k++, n++) { if (ok(seed + ":" + n, diff)) { cb(n); return; } }
      }
      if (onProgress) onProgress(n, Date.now() - t0);
      setTimeout(slice, 0);
    })();
  }
  return { hex: hex, ok: ok, solve: solve };
})();
if (typeof module !== "undefined") module.exports = ShieldPow;
