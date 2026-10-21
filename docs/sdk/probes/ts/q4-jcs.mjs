// Q4: JSON.stringify numbers vs RFC 8785 Appendix B / 3.2.2 samples, and key sorting by UTF-16 code units.
const dv = new DataView(new ArrayBuffer(8)), js = (h) => (dv.setBigUint64(0, BigInt('0x' + h)), JSON.stringify(dv.getFloat64(0)));
const B = ('0000000000000000=0 8000000000000000=0 0000000000000001=5e-324 8000000000000001=-5e-324 7fefffffffffffff=1.7976931348623157e+308 '
  + 'ffefffffffffffff=-1.7976931348623157e+308 4340000000000000=9007199254740992 c340000000000000=-9007199254740992 4430000000000000=295147905179352830000 '
  + '44b52d02c7e14af5=9.999999999999997e+22 44b52d02c7e14af6=1e+23 44b52d02c7e14af7=1.0000000000000001e+23 444b1ae4d6e2ef4e=999999999999999700000 '
  + '444b1ae4d6e2ef4f=999999999999999900000 444b1ae4d6e2ef50=1e+21 3eb0c6f7a0b5ed8c=9.999999999999997e-7 3eb0c6f7a0b5ed8d=0.000001 41b3de4355555553=333333333.3333332 '
  + '41b3de4355555554=333333333.33333325 41b3de4355555555=333333333.3333333 41b3de4355555556=333333333.3333334 41b3de4355555557=333333333.33333343 '
  + 'becbf647612f3696=-0.0000033333333333333333 43143ff3c1cb0959=1424953923781206.2').split(' ').map((r) => r.split('='));
console.log('Appendix B rows:', B.length, '| mismatches:', B.filter(([h, j]) => js(h) !== j).map(([h, j]) => [h, j, js(h)]));
console.log('1e21 1e-7 -0 4.5 0.000001 1E30 ->', [1e21, 1e-7, -0, 4.5, 0.000001, 1e30].map((n) => JSON.stringify(n)).join(' '));
console.log('NaN Infinity -Infinity ->', [NaN, Infinity, -Infinity].map((n) => JSON.stringify(n)).join(' '), '| lone surrogate ->', JSON.stringify('\ud800'));
const canon = (v) => Array.isArray(v) ? `[${v.map(canon)}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k]))}}` : JSON.stringify(v);
const s = '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}';
console.log('3.2.2 sample canonical form equals the RFC 3.2.3 text:', canon(JSON.parse(s)) === '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
const o = JSON.parse('{"\\u20ac":"Euro","\\r":"CR","\\ufb33":"Dalet","1":"One","\\ud83d\\ude00":"Emoji","\\u0080":"Control","\\u00f6":"o-umlaut"}');
const order = (cmp) => Object.keys(o).sort(cmp).map((k) => o[k]).join(' ');
console.log('RFC 3.2.3 expected  : CR One Control o-umlaut Euro Emoji Dalet\nObject.keys order   :', Object.keys(o).map((k) => o[k]).join(' '));
console.log('default sort()      :', order());
console.log('localeCompare       :', order((a, b) => a.localeCompare(b)));
console.log('code point order    :', order((a, b) => a.codePointAt(0) - b.codePointAt(0)));
