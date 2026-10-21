// Q5: ajv/dist/2020 strict compile of spec/v1.0/schemas/pact.schema.json, with and without ajv-formats (run with cwd = the install dir).
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
const req = createRequire(process.cwd() + '/'), Ajv = req('ajv/dist/2020').default, formats = req('ajv-formats').default;
const load = (rel) => readFileSync(new URL('../../../../spec/' + rel, import.meta.url), 'utf8');
const text = load('schemas/pact.schema.json'), schema = JSON.parse(text);
console.log('$ref targets not starting with "#/":', [...text.matchAll(/"\$ref":\s*"([^"]*)"/g)].map((m) => m[1]).filter((r) => !r.startsWith('#/')));
const problem = { type: 'https://example.test/p', title: 't', status: 400, code: 'c', request_id: 'r' }, none = () => {};
const ack = { request_id: 'r1', status: 'ACCEPTED', artifact_id: 'a1', received_at: 1 }, uri = (a) => a.addFormat('uri', (v) => URL.canParse(v));
const c = JSON.parse(Buffer.from(load('fixtures/parse/appendix-c-wrong-version.jws').split('.')[1], 'base64url'));
const docs = { ack, 'ack status OK': { ...ack, status: 'OK' }, 'ack received_at 2^53': { ...ack, received_at: 2 ** 53 }, problem,
  'problem type "not a uri"': { ...problem, type: 'not a uri' }, 'Appendix C payload (0.2)': c, 'same, pact_version 0.1': { ...c, pact_version: '0.1' } };
for (const [label, opts, setup] of [['no ajv-formats', {}, none], ['validateFormats:false', { validateFormats: false }, none], ['addFormat uri=URL.canParse', {}, uri], ['ajv-formats', {}, formats]]) {
  try {
    const ajv = new Ajv({ strict: true, allErrors: true, ...opts });
    setup(ajv);
    const validate = ajv.compile(schema), o = ajv.opts;
    console.log(label + ': compiled;', [o.strictSchema, o.strictNumbers, o.strictTypes, o.strictTuples, o.strictRequired].join(), '|', Object.entries(docs).map(([k, d]) => `${k}=${validate(d)}`).join(' | '));
  } catch (e) { console.log(label + ': compile error:', e.message); }
}
