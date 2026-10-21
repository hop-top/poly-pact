// ParityCopy: a scratch copy of the spec tree and the steps of a case of
// the shared manifest case table applied to it, undone after each case, so
// one copy serves every case (tools/spec/README.md, Manifest parity cases;
// a port of the Copy class of scripts/paritycases.py). Not a test file (the
// test glob is *.test.ts).

import {
  copyFileSync,
  cpSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { compareCodePoints } from '../../src/runner/manifest/rules.ts';
import { CaseError, isObj, type Json, type Obj, type Step, transform } from './paritycases.ts';

const SELECTOR = /^\{([a-z][a-z-]*)(?:#([1-9][0-9]*))?\}$/;
const INDEX = /^(0|[1-9][0-9]*)$/;
const GROUP_ROW = /^\| ([^|]+?) \|.*\| (planned|partial|landed) \|$/;

/**
 * A scratch copy of the spec tree (spec/v1.0/fixtures, symbolic links kept as
 * links, spec/v1.0/spec-map.md and spec/v1.0/draft.md), and the steps of a mutation
 * applied to it.
 * {@link restore} undoes every change of the last {@link apply}.
 */
export class ParityCopy {
  /** The spec directory of the copy. */
  readonly spec: string;
  readonly fixtures: string;
  readonly mapPath: string;
  readonly #manifestPath: string;
  // The state of each changed path before its first change: its bytes, or
  // null when it did not exist. Directories created by a step, in order.
  readonly #saved = new Map<string, Uint8Array | null>();
  readonly #dirs: string[] = [];
  #doc: Json | undefined;
  #text: string | null = null;
  #dirty = false;

  constructor(specSource: string, root: string) {
    this.spec = join(root, 'spec');
    this.fixtures = join(this.spec, 'fixtures');
    this.mapPath = join(this.spec, 'spec-map.md');
    this.#manifestPath = join(this.fixtures, 'manifest.json');
    cpSync(join(specSource, 'fixtures'), this.fixtures, {
      recursive: true,
      verbatimSymlinks: true,
    });
    for (const name of ['spec-map.md', 'draft.md']) {
      copyFileSync(join(specSource, name), join(this.spec, name));
    }
  }

  /** Applies the steps of mutation, in order, then writes the manifest. */
  apply(mutation: readonly Step[]): void {
    this.#doc = undefined;
    this.#text = null;
    this.#dirty = false;
    for (const step of mutation) this.#step(step);
    if (this.#text !== null) this.#writeFile(this.#manifestPath, this.#text);
    else if (this.#dirty) this.#writeFile(this.#manifestPath, this.#dump());
  }

  /** Undoes every change since the last restore. */
  restore(): void {
    for (const [path, data] of [...this.#saved].reverse()) {
      // A symbolic link a step put in place of a file goes first, so the
      // bytes land in the file and not in the link's target.
      rmSync(path, { force: true, recursive: true });
      if (data !== null) writeFileSync(path, data);
    }
    for (const d of this.#dirs.reverse()) rmSync(d, { force: true, recursive: true });
    this.#saved.clear();
    this.#dirs.length = 0;
  }

  get #root(): Json {
    if (this.#doc === undefined) this.#doc = JSON.parse(readFileSync(this.#manifestPath, 'utf8'));
    return this.#doc as Json;
  }

  #dump(): string {
    return `${JSON.stringify(this.#root, null, 2)}\n`;
  }

  #save(path: string): void {
    if (this.#saved.has(path)) return;
    let data: Uint8Array | null = null;
    if (lstatSync(path, { throwIfNoEntry: false }) !== undefined) data = readFileSync(path);
    this.#saved.set(path, data);
  }

  #writeFile(path: string, text: string): void {
    this.#save(path);
    writeFileSync(path, text);
  }

  #step(step: Step): void {
    const s = step as Obj;
    switch (step.op) {
      case 'add':
        this.#manifestStep(step.op);
        this.#add(this.#tokens(s.path as string), structuredClone(s.value as Json));
        return;
      case 'remove':
        this.#manifestStep(step.op);
        this.#remove(this.#tokens(s.path as string));
        return;
      case 'replace': {
        this.#manifestStep(step.op);
        const tokens = this.#tokens(s.path as string);
        this.#get(tokens);
        const value = structuredClone(s.value as Json);
        if (tokens.length === 0) {
          this.#doc = value;
          return;
        }
        const into = this.#get(tokens.slice(0, -1));
        const last = tokens[tokens.length - 1] as string;
        if (Array.isArray(into)) into[Number(last)] = value;
        else (into as Obj)[last] = value;
        return;
      }
      case 'move': {
        this.#manifestStep(step.op);
        const source = this.#tokens(s.from as string);
        const target = this.#tokens(s.path as string);
        this.#add(target, this.#remove(source));
        return;
      }
      case 'copy': {
        this.#manifestStep(step.op);
        const source = this.#tokens(s.from as string);
        const target = this.#tokens(s.path as string);
        let value = structuredClone(this.#get(source));
        if (s.apply !== undefined) {
          if (typeof value !== 'string') throw new CaseError(`${s.from} is not a string`);
          value = transform(value, s.apply as Json[]);
        }
        this.#add(target, value);
        return;
      }
      case 'insert-entry': {
        this.#manifestStep(step.op);
        const like =
          s.like === undefined ? {} : structuredClone(this.#get(this.#tokens(s.like as string)));
        if (!isObj(like)) throw new CaseError(`${s.like} is not an entry`);
        for (const [name, v] of Object.entries(s.set as Obj)) {
          like[name] = isObj(v) ? this.#string(v) : v;
        }
        const entries = this.#get(['entries']);
        const id = like.id;
        if (!Array.isArray(entries) || typeof id !== 'string') {
          throw new CaseError('insert-entry needs an entries array and an id');
        }
        let at = entries.findIndex(
          (e) => isObj(e) && compareCodePoints(typeof e.id === 'string' ? e.id : '', id) > 0,
        );
        if (at < 0) at = entries.length;
        entries.splice(at, 0, like);
        return;
      }
      case 'text':
        if (this.#text === null) this.#text = this.#dump();
        this.#text = transform(this.#text, s.apply as Json[]);
        return;
      case 'write':
        this.#create(this.#path(s.file as Json), s.text as string);
        return;
      case 'copy-file':
        this.#create(
          this.#path(s.file as Json),
          readFileSync(this.#path(s.source as Json), 'utf8'),
        );
        return;
      case 'delete': {
        const full = this.#path(s.file as Json);
        this.#save(full);
        rmSync(full);
        return;
      }
      case 'symlink': {
        const full = this.#path(s.file as Json);
        if (lstatSync(full, { throwIfNoEntry: false }) !== undefined) {
          throw new CaseError(`${this.#string(s.file as Json)} exists already`);
        }
        this.#save(full);
        symlinkSync(s.target as string, full);
        return;
      }
      case 'map-group':
        this.#mapGroup(s);
        return;
      case 'map-line': {
        const lines = this.#mapLines();
        const n = lines.filter((l) => l === s.line).length;
        if (n !== 1)
          throw new CaseError(`spec-map.md has no single line ${JSON.stringify(s.line)}`);
        lines[lines.indexOf(s.line as string)] = s.text as string;
        this.#writeFile(this.mapPath, lines.join('\n'));
        return;
      }
    }
    throw new CaseError(`${step.op} is not a step`);
  }

  #manifestStep(op: string): void {
    if (this.#text !== null) throw new CaseError(`the ${op} step comes after a text step`);
    this.#dirty = true;
  }

  // JSON pointers (RFC 6901) into the manifest, with entry selectors.
  #tokens(pointer: string): string[] {
    const out: string[] = [];
    for (const raw of pointer.split('/').slice(1)) {
      const sel = SELECTOR.exec(raw);
      if (sel) {
        if (out.length !== 1 || out[0] !== 'entries') {
          throw new CaseError(`${pointer}: an entry selector must follow /entries`);
        }
        out.push(String(this.#select(sel[1] as string, Number(sel[2] ?? 1))));
      } else {
        out.push(raw.replaceAll('~1', '/').replaceAll('~0', '~'));
      }
    }
    return out;
  }

  #select(kind: string, n: number): number {
    const root = this.#root;
    const entries = isObj(root) ? root.entries : undefined;
    if (!Array.isArray(entries)) throw new CaseError('the manifest has no entries array');
    const found = entries.flatMap((e, i) => (isObj(e) && e.kind === kind ? [i] : []));
    if (found.length < n) throw new CaseError(`the manifest has fewer than ${n} ${kind} entries`);
    return found[n - 1] as number;
  }

  #get(tokens: readonly string[]): Json {
    let v: Json = this.#root;
    for (const t of tokens) {
      if (isObj(v) && Object.hasOwn(v, t)) v = v[t] as Json;
      else if (Array.isArray(v) && INDEX.test(t) && Number(t) < v.length) v = v[Number(t)] as Json;
      else throw new CaseError(`the manifest has no /${tokens.join('/')}`);
    }
    return v;
  }

  #add(tokens: readonly string[], value: Json): void {
    if (tokens.length === 0) {
      this.#doc = value;
      return;
    }
    const into = this.#get(tokens.slice(0, -1));
    const last = tokens[tokens.length - 1] as string;
    if (isObj(into)) into[last] = value;
    else if (Array.isArray(into) && last === '-') into.push(value);
    else if (Array.isArray(into) && INDEX.test(last) && Number(last) <= into.length) {
      into.splice(Number(last), 0, value);
    } else throw new CaseError(`cannot add at /${tokens.join('/')}`);
  }

  #remove(tokens: readonly string[]): Json {
    if (tokens.length === 0) throw new CaseError('cannot remove the whole manifest');
    const value = this.#get(tokens);
    const into = this.#get(tokens.slice(0, -1));
    const last = tokens[tokens.length - 1] as string;
    if (Array.isArray(into)) into.splice(Number(last), 1);
    else delete (into as Obj)[last];
    return value;
  }

  #string(expr: Json): string {
    if (typeof expr === 'string') return expr;
    const e = expr as Obj;
    const v = this.#get(this.#tokens(e.from as string));
    if (typeof v !== 'string') throw new CaseError(`${e.from} is not a string`);
    return transform(v, (e.apply ?? []) as Json[]);
  }

  // Files under spec/v1.0/fixtures.
  #path(expr: Json): string {
    return join(this.fixtures, ...this.#string(expr).split('/'));
  }

  #create(full: string, text: string): void {
    if (lstatSync(full, { throwIfNoEntry: false }) !== undefined) {
      throw new CaseError(`${relative(this.fixtures, full)} exists already`);
    }
    const made = mkdirSync(dirname(full), { recursive: true });
    if (made !== undefined) this.#dirs.push(made);
    this.#writeFile(full, text);
  }

  // spec/v1.0/spec-map.md.
  #mapLines(): string[] {
    return readFileSync(this.mapPath, 'utf8').split('\n');
  }

  // Changes the first row of the Fixture groups table that the step
  // selects: gives it set_status, or drops it.
  #mapGroup(s: Obj): void {
    const group = s.group === undefined ? null : this.#string(s.group as Json);
    const lines = this.#mapLines();
    let section: string | null = null;
    for (const [i, line] of lines.entries()) {
      if (line.startsWith('## ')) {
        section = line.slice(3).trim();
        continue;
      }
      const row = section === 'Fixture groups' ? GROUP_ROW.exec(line) : null;
      if (!row) continue;
      const name = (row[1] as string).replace(/^[` ]+|[` ]+$/g, '');
      const status = row[2] as string;
      if ((group !== null && group !== name) || (s.status ?? status) !== status) continue;
      if (s.drop === true) lines.splice(i, 1);
      else lines[i] = `${line.slice(0, -`${status} |`.length)}${s.set_status as string} |`;
      this.#writeFile(this.mapPath, lines.join('\n'));
      return;
    }
    throw new CaseError('no row of the Fixture groups table fits the mutation');
  }
}
