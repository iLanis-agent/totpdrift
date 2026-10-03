(function (root) {
  // HOTP (RFC 4226), TOTP (RFC 6238), Base32 (RFC 4648) and the otpauth key URI (Google Authenticator wiki). HMAC comes from WebCrypto.
  var ALGS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
  var A32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32decode(s) {
    s = String(s).replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase(); var bits = 0, val = 0, out = [], i;
    for (i = 0; i < s.length; i++) { var k = A32.indexOf(s[i]); if (k < 0) return null; val = (val << 5) | k; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } }
    return new Uint8Array(out);
  }
  function b32encode(bytes, pad) {
    var out = '', bits = 0, val = 0, i;
    for (i = 0; i < bytes.length; i++) { val = (val << 8) | bytes[i]; bits += 8; while (bits >= 5) { out += A32[(val >>> (bits - 5)) & 31]; bits -= 5; val &= (1 << bits) - 1; } }
    if (bits > 0) out += A32[(val << (5 - bits)) & 31];
    if (pad !== false) while (out.length % 8) out += '=';
    return out;
  }
  function counterBytes(c) { var b = new Uint8Array(8), v = BigInt(c), i; for (i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; }
  async function hmac(alg, key, msg) {
    var k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: ALGS[alg] }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  }
  // RFC 4226 section 5.3 dynamic truncation, then mod 10^digits
  async function hotp(alg, key, counter, digits) {
    var h = await hmac(alg, key, counterBytes(counter)), o = h[h.length - 1] & 15;
    var bin = ((h[o] & 0x7f) * 16777216) + (h[o + 1] << 16) + (h[o + 2] << 8) + h[o + 3];
    var s = String(bin % Math.pow(10, digits)); while (s.length < digits) s = '0' + s; return s;
  }
  function step(ms, period, t0) { return Math.floor((Math.floor(ms / 1000) - (t0 || 0)) / period); }
  async function totp(o, ms) { return hotp(o.alg, o.key, step(ms, o.period, o.t0), o.digits); }
  // find which time step a typed code belongs to, searching +-maxSteps around `ms`. Returns offsets in steps (negative = older code).
  async function findOffset(o, code, ms, maxSteps) {
    var base = step(ms, o.period, o.t0), hits = [], d;
    for (d = 0; d <= maxSteps; d++) {
      var ds = d === 0 ? [0] : [-d, d];
      for (var q = 0; q < ds.length; q++) { var c = await hotp(o.alg, o.key, base + ds[q], o.digits); if (c === code) hits.push({ steps: ds[q], seconds: ds[q] * o.period }); }
    }
    return hits;
  }
  function parseUri(u) {
    var m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\?(.*)$/i.exec(String(u).trim()); if (!m) return null;
    var label = decodeURIComponent(m[1] && m[2]), params = {}, issuerFromLabel = '', account = label;
    m[3].split('&').forEach(function (kv) { var i = kv.indexOf('='); if (i > 0) params[kv.slice(0, i).toLowerCase()] = decodeURIComponent(kv.slice(i + 1).replace(/\+/g, ' ')); });
    var ci = label.indexOf(':'); if (ci >= 0) { issuerFromLabel = label.slice(0, ci); account = label.slice(ci + 1).replace(/^\s+/, ''); }
    if (!params.secret) return null;
    return { type: m[1].toLowerCase(), account: account, issuer: params.issuer || issuerFromLabel, secret: params.secret, alg: (params.algorithm || 'SHA1').toUpperCase(), digits: params.digits ? parseInt(params.digits, 10) : 6, period: params.period ? parseInt(params.period, 10) : 30, counter: params.counter };
  }
  function buildUri(o) {
    var label = (o.issuer ? encodeURIComponent(o.issuer) + ':' : '') + encodeURIComponent(o.account || 'account');
    var q = 'secret=' + String(o.secret).replace(/[\s=-]/g, '').toUpperCase() + (o.issuer ? '&issuer=' + encodeURIComponent(o.issuer) : '') + '&algorithm=' + o.alg + '&digits=' + o.digits + '&period=' + o.period;
    return 'otpauth://totp/' + label + '?' + q;
  }
  var api = { b32decode: b32decode, b32encode: b32encode, hotp: hotp, totp: totp, step: step, findOffset: findOffset, parseUri: parseUri, buildUri: buildUri, counterBytes: counterBytes, ALGS: ALGS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.TotpDrift = api;
})(typeof window !== 'undefined' ? window : this);
