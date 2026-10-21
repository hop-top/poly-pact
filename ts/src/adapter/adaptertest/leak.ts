/**
 * The credential scan of draft 19 (Go hop.top/pact-go/adapter/adaptertest,
 * leak.go).
 *
 * @module
 */
import { RawJSON } from '../../core/values.ts';

/**
 * The patterns of credential material in text that must not carry any.
 * Receipts, outcome reports and logs must not contain the headers
 * authorization, proxy-authorization, cookie, set-cookie, pact-presentation
 * and pact-admission, any private JWK parameter, or native tokens and
 * passwords.
 *
 * The patterns are deliberately narrow, so that a legitimate message such as
 * "basic authentication failed" does not match: an authorization value needs
 * a long token after the scheme, a header name needs to be a JSON member
 * name, and a key=value secret needs a name that only credentials have.
 */
const CREDENTIAL_PATTERNS: readonly {
  readonly name: string;
  readonly re: RegExp;
  /** Receives a match and reports one that is not a credential after all. */
  readonly placeholder?: (m: RegExpExecArray) => boolean;
}[] = [
  { name: 'authorization value', re: /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{16,}=*/gi },
  {
    name: 'compact JWS or JWT',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  {
    name: 'credential header as a member name',
    re: /"(?:authorization|proxy-authorization|cookie|set-cookie|pact-presentation|pact-admission)"\s*:/gi,
  },
  { name: 'private JWK parameter as a member name', re: /"(?:d|p|q|dp|dq|qi|k)"\s*:/g },
  {
    name: 'credential assignment',
    re: /\b(?:access_token|refresh_token|id_token|api_?key|password|passwd|secret|session(?:_?id)?|sid)=([^\s&;"']{6,})/gi,
    placeholder: isPlaceholder,
  },
];

const MASKS = new Set([
  '',
  'redacted',
  'removed',
  'hidden',
  'masked',
  'filtered',
  'omitted',
  'elided',
]);

// Whether the value of an assignment is a mask such as [redacted], REDACTED,
// ***** or xxxxxx rather than a credential.
function isPlaceholder(m: RegExpExecArray): boolean {
  const v = (m[1] ?? '').replace(/^[[\]<>(){}*_\-.x]+|[[\]<>(){}*_\-.x]+$/g, '').toLowerCase();
  return MASKS.has(v);
}

/**
 * A description of every credential in `text`: each secret that occurs
 * literally and the first match of each pattern that is not a placeholder.
 */
export function findCredentials(text: string, secrets: readonly string[]): string[] {
  const found: string[] = [];
  for (const s of secrets) {
    if (s !== '' && text.includes(s)) found.push(`secret ${JSON.stringify(s)}`);
  }
  for (const p of CREDENTIAL_PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      if (p.placeholder?.(m)) continue;
      found.push(`${p.name} ${JSON.stringify(m[0])}`);
      break;
    }
  }
  return found;
}

/**
 * The JSON text of a returned value, for the scan and for messages: raw
 * values as their text, `bigint` as digits, a value with no JSON form as a
 * description. It never throws.
 */
export function jsonText(v: unknown): string {
  try {
    const out = JSON.stringify(v, (_k, x: unknown) => {
      if (x instanceof RawJSON) return JSON.parse(x.text) as unknown;
      if (typeof x === 'bigint') return x.toString();
      return x;
    });
    return out ?? String(v);
  } catch (err) {
    return `<unencodable ${typeName(v)}: ${(err as Error).message}>`;
  }
}

/** The constructor name of `v`, or its `typeof`, for messages. */
export function typeName(v: unknown): string {
  if (v === null) return 'null';
  if (typeof v !== 'object') return typeof v;
  const name = (Object.getPrototypeOf(v) as { constructor?: { name?: string } } | null)?.constructor
    ?.name;
  return name === undefined || name === '' ? 'object' : name;
}

/**
 * The text of an error and of everything its `cause` chain wraps, as Go's
 * `Error()` of a wrapping error includes the wrapped text.
 */
export function errorText(err: unknown): string {
  const parts: string[] = [];
  const seen = new Set<unknown>();
  for (let e: unknown = err; e !== undefined && e !== null && !seen.has(e); ) {
    seen.add(e);
    parts.push(e instanceof Error ? e.message : String(e));
    e = e instanceof Error ? e.cause : undefined;
  }
  return parts.join(': ');
}
