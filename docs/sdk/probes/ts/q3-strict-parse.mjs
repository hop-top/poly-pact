// Q3: JSON.parse and TextDecoder leniency against the strict-input rules of spec 7.1.
const t = (l, f) => { try { console.log(l.padEnd(26), f()); } catch (e) { console.log(l.padEnd(26), 'THROWS', e.name + ':', e.message.replaceAll('\ufeff', '<U+FEFF>')); } };
t('duplicate keys', () => JSON.stringify(JSON.parse('{"a":1,"a":2}')));
t('duplicate keys + reviver', () => { const seen = []; JSON.parse('{"a":1,"a":2}', (k, v) => (seen.push(k + '=' + v), v)); return seen; });
t('1e999', () => JSON.parse('1e999'));
t('lone surrogate escape', () => { const s = JSON.parse('"\\ud800"'); return { length: s.length, wellFormed: s.isWellFormed() }; });
t('lone surrogate in key', () => Object.keys(JSON.parse('{"\\udc00":1}')).map((k) => k.isWellFormed()));
t('BOM char in JSON.parse', () => JSON.parse('﻿{}'));
t('2^53+1 and 2^64', () => JSON.parse('[9007199254740993,18446744073709551616]'));
t('reviver context.source', () => { const o = []; JSON.parse('[9007199254740993,1e999,1.0]', (k, v, c) => (k && o.push([String(v), c.source]), v)); return o; });
const dec = (b, o) => () => 'code points: ' + Array.from(new TextDecoder('utf-8', o).decode(Uint8Array.from(b)), (c) => c.codePointAt(0).toString(16)).join(' ');
const bad = { 'ff byte': [0x7b, 0xff, 0x7d], 'overlong c0 80': [0xc0, 0x80], 'surrogate ed a0 80': [0xed, 0xa0, 0x80],
  'truncated e2 82': [0xe2, 0x82], 'above 10ffff f4 90 80 80': [0xf4, 0x90, 0x80, 0x80], 'noncharacter ef bf be': [0xef, 0xbf, 0xbe] };
for (const [l, b] of Object.entries(bad)) { t('fatal: ' + l, dec(b, { fatal: true })); }
t('non-fatal: ff byte', dec(bad['ff byte'], {}));
t('fatal: BOM ef bb bf 7b 7d', dec([0xef, 0xbb, 0xbf, 0x7b, 0x7d], { fatal: true }));
t('fatal+ignoreBOM: same', dec([0xef, 0xbb, 0xbf, 0x7b, 0x7d], { fatal: true, ignoreBOM: true }));
t('fatal: valid 4-byte f0 9f 98 80', dec([0xf0, 0x9f, 0x98, 0x80], { fatal: true }));
