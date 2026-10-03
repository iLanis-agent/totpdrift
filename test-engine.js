var T = require('./engine.js'), nodeCrypto = require('crypto'); var fails = 0, n = 0;
function eq(a, b, m) { n++; if (JSON.stringify(a) !== JSON.stringify(b)) { fails++; console.log('FAIL', m, JSON.stringify(a), JSON.stringify(b)); } }
function asc(s) { return new Uint8Array(Buffer.from(s, 'latin1')); }
(async function () {
  // RFC 4226 Appendix D (as quoted on the RFC Editor errata page): secret "12345678901234567890", counters 0 to 9
  var hv = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  for (var i = 0; i < 10; i++) eq(await T.hotp('SHA1', asc('12345678901234567890'), i, 6), hv[i], 'HOTP vector ' + i);
  // RFC 6238 Table 1. SHA256 and SHA512 use the longer seeds from verified erratum 2866: the RFC text prints a 20-byte seed for all three.
  var seeds = { SHA1: '12345678901234567890', SHA256: '12345678901234567890123456789012', SHA512: '1234567890123456789012345678901234567890123456789012345678901234' };
  var tbl = [[59, '94287082', '46119246', '90693936'], [1111111109, '07081804', '68084774', '25091201'], [1111111111, '14050471', '67062674', '99943326'], [1234567890, '89005924', '91819424', '93441116'], [2000000000, '69279037', '90698825', '38618901'], [20000000000, '65353130', '77737706', '47863826']];
  for (var r = 0; r < tbl.length; r++) for (var a = 0; a < 3; a++) { var alg = ['SHA1', 'SHA256', 'SHA512'][a]; eq(await T.totp({ alg: alg, key: asc(seeds[alg]), period: 30, digits: 8, t0: 0 }, tbl[r][0] * 1000), tbl[r][a + 1], 'RFC 6238 ' + alg + ' t=' + tbl[r][0]); }
  // T values from the table
  eq(T.step(59000, 30), 1, 'T at 59 s'); eq(T.step(1111111109 * 1000, 30).toString(16).toUpperCase(), '23523EC', 'T hex 1111111109'); eq(T.step(20000000000 * 1000, 30).toString(16).toUpperCase(), '27BC86AA', 'T hex 20000000000');
  // the 20-byte seed with SHA-256 does NOT give the table value (that is the erratum)
  n++; if (await T.hotp('SHA256', asc(seeds.SHA1), 1, 8) === '46119246') { fails++; console.log('FAIL erratum'); }
  // Oracle: node:crypto HMAC with an independent truncation, random keys, counters, algorithms and digit counts
  function ref(alg, key, c, d) { var b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(c)); var h = nodeCrypto.createHmac(alg.toLowerCase().replace('sha', 'sha'), key).update(b).digest(); var o = h[h.length - 1] & 15; var v = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) >>> 0; return String(v % Math.pow(10, d)).padStart(d, '0'); }
  var seed = 5; function rnd(m) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % m; }
  for (var t = 0; t < 300; t++) { var alg2 = ['SHA1', 'SHA256', 'SHA512'][rnd(3)], key = Buffer.alloc(1 + rnd(70)); for (var j = 0; j < key.length; j++) key[j] = rnd(256); var c = rnd(2000000000) * 3 + rnd(3), d = 6 + rnd(3);
    eq(await T.hotp(alg2, new Uint8Array(key), c, d), ref(alg2, key, c, d), 'node oracle ' + t); }
  eq(Array.from(T.counterBytes(1)), [0, 0, 0, 0, 0, 0, 0, 1], 'counter bytes'); eq(Array.from(T.counterBytes(0x0273EF07)), [0, 0, 0, 0, 0x02, 0x73, 0xEF, 0x07], 'counter bytes 2');
  // RFC 4648 section 10 Base32 vectors
  var b32 = [['', ''], ['f', 'MY======'], ['fo', 'MZXQ===='], ['foo', 'MZXW6==='], ['foob', 'MZXW6YQ='], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI======']];
  b32.forEach(function (v) { eq(T.b32encode(asc(v[0])), v[1], 'b32 encode ' + v[0]); eq(Buffer.from(T.b32decode(v[1])).toString('latin1'), v[0], 'b32 decode ' + v[0]); eq(Buffer.from(T.b32decode(v[1].replace(/=+$/, ''))).toString('latin1'), v[0], 'b32 decode unpadded ' + v[0]); });
  eq(Buffer.from(T.b32decode('mzxw 6ytb-oi')).toString('latin1'), 'foobar', 'lowercase, spaces and dashes'); eq(T.b32decode('MZXW1'), null, 'invalid char 1'); eq(T.b32decode('MZXW8'), null, 'invalid char 8');
  for (t = 0; t < 100; t++) { var bytes = new Uint8Array(rnd(40)); for (j = 0; j < bytes.length; j++) bytes[j] = rnd(256); eq(Array.from(T.b32decode(T.b32encode(bytes))), Array.from(bytes), 'b32 roundtrip ' + t); eq(Array.from(T.b32decode(T.b32encode(bytes, false))), Array.from(bytes), 'b32 roundtrip unpadded ' + t); }
  // drift finder: a code from k steps ago is found at offset -k
  var o = { alg: 'SHA1', key: asc('12345678901234567890'), period: 30, digits: 6, t0: 0 }, now = 1700000000000;
  for (var k = -5; k <= 5; k++) { var code = await T.hotp('SHA1', o.key, T.step(now, 30) + k, 6), hits = await T.findOffset(o, code, now, 10); n++; if (!hits.some(function (h) { return h.steps === k; })) { fails++; console.log('FAIL drift', k); } }
  eq((await T.findOffset(o, await T.hotp('SHA1', o.key, T.step(now, 30) - 2, 6), now, 1)), [], 'outside the window finds nothing');
  eq((await T.findOffset(o, await T.hotp('SHA1', o.key, T.step(now, 30) - 2, 6), now, 2)).map(function (h) { return h.seconds; }), [-60], 'minus 60 seconds');
  // landing page example: RFC 6238 SHA1 seed at 1111111109 s; the code 90 s earlier is 31404137
  var rf = { alg: 'SHA1', key: asc('12345678901234567890'), period: 30, digits: 8, t0: 0 }; eq(await T.findOffset(rf, '31404137', 1111111109000, 40), [{ steps: -3, seconds: -90 }], 'landing example: 3 steps old'); eq(await T.findOffset(rf, '07081804', 1111111109000, 40), [{ steps: 0, seconds: 0 }], 'landing example: current');
  // otpauth URIs from the Key URI Format page
  var u1 = T.parseUri('otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'); eq([u1.type, u1.issuer, u1.account, u1.secret, u1.alg, u1.digits, u1.period], ['totp', 'Example', 'alice@google.com', 'JBSWY3DPEHPK3PXP', 'SHA1', 6, 30], 'uri 1 defaults');
  var u2 = T.parseUri('otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30'); eq([u2.issuer, u2.account, u2.period], ['ACME Co', 'john.doe@email.com', 30], 'uri 2');
  eq(T.parseUri('otpauth://totp/x:y?issuer=a'), null, 'no secret'); eq(T.parseUri('https://example.com'), null, 'not a uri'); eq(T.parseUri('otpauth://totp/Big%20Corporation%3A%20alice?secret=ABC&digits=8&period=60&algorithm=sha256').account, 'alice', 'encoded colon');
  var built = T.buildUri({ issuer: 'ACME Co', account: 'john.doe@email.com', secret: 'hxdm vjec', alg: 'SHA256', digits: 8, period: 60 }); var back = T.parseUri(built); eq([back.issuer, back.account, back.secret, back.alg, back.digits, back.period], ['ACME Co', 'john.doe@email.com', 'HXDMVJEC', 'SHA256', 8, 60], 'build then parse');
  console.log(n + ' checks, ' + fails + ' failures'); process.exit(fails ? 1 : 0);
})();
