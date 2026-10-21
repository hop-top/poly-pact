// Pieces of spec/v1.0/draft.md the ported go/core/jws draft tests read
// (draft_test.go): a section between two headings, the first fenced block
// of a language after a marker, Appendix C and the B.5 example.

import assert from 'node:assert/strict';

/** The draft text from the heading start up to the heading end. */
export function section(draft: string, start: string, end: string): string {
  const i = draft.indexOf(start);
  assert.ok(i >= 0, `draft has no ${JSON.stringify(start)}`);
  const j = draft.indexOf(end, i);
  assert.ok(j >= 0, `draft has no ${JSON.stringify(end)} after ${JSON.stringify(start)}`);
  return draft.slice(i, j);
}

/** The body of the first fenced block of lang after marker. */
export function fenced(text: string, marker: string, lang: string): string {
  const i = text.indexOf(marker);
  assert.ok(i >= 0, `no ${JSON.stringify(marker)}`);
  const open = `\`\`\`${lang}\n`;
  const j = text.indexOf(open, i);
  assert.ok(j >= 0, `no ${lang} block after ${JSON.stringify(marker)}`);
  const body = text.slice(j + open.length);
  const k = body.indexOf('\n```');
  assert.ok(k >= 0, `unterminated ${lang} block after ${JSON.stringify(marker)}`);
  return body.slice(0, k);
}

export function appendixC(draft: string): string {
  return section(draft, '## Appendix C.', '## Appendix D.');
}

/** The exact compact evidence JWS of Appendix C. */
export function appendixCCompact(draft: string): string {
  return fenced(appendixC(draft), 'Exact compact evidence JWS:', 'text').trim();
}

/** The runtime evidence example of Appendix B.5, the payload of the Appendix C JWS. */
export function appendixB5(draft: string): string {
  return fenced(draft, '### B.5 Runtime evidence', 'json');
}

/**
 * The text after the heading line `heading` (such as `### 17.1 Required
 * adapter capabilities`) up to the next heading of level 1 to 3, as the Go
 * adapter tests' draftSection reads it.
 */
export function headingSection(draft: string, heading: string): string {
  const start = draft.indexOf(`\n${heading}\n`);
  assert.ok(start >= 0, `draft has no heading ${JSON.stringify(heading)}`);
  const rest = draft.slice(start + 1 + heading.length);
  const end = /^#{1,3} /m.exec(rest);
  return end === null ? rest : rest.slice(0, end.index);
}
