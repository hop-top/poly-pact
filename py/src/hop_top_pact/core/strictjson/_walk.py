"""The walker: a port of go/core/strictjson/walk.go and of the token rules of
encoding/json's Decoder (Token, More, InputOffset) it runs on."""

from __future__ import annotations

import json.decoder
import re
from collections.abc import Mapping
from typing import Any, Final, cast

from hop_top_pact.core.strictjson._errors import (
    MAX_SAFE_INTEGER,
    Limits,
    StrictJSONError,
    StrictJSONErrorKind,
)
from hop_top_pact.core.strictjson._target import (
    BOOL,
    FLOAT,
    FREE,
    INT,
    MAP,
    RAW,
    SLICE,
    STRING,
    STRUCT,
    Struct,
    Target,
    build,
    struct_of,
)

_WS = re.compile(r"[ \t\n\r]*")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?")
_STRING_BODY = re.compile(
    r'"[^"\\\x00-\x1f]*(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})[^"\\\x00-\x1f]*)*'
)
_ESCAPE_PREFIX = re.compile(r"\\(?:u[0-9a-fA-F]{0,3})?\Z")
_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|.)", re.S)
_NON_FINITE: Final = ("NaN", "Infinity", "-Infinity", "+Infinity")
_LITERALS: Final = {"t": ("true", True), "f": ("false", False), "n": ("null", None)}
_scanstring = json.decoder.scanstring  # type: ignore[attr-defined]

# The token states of Go's json.Decoder.
(
    _TOP,
    _ARRAY_START,
    _ARRAY_VALUE,
    _ARRAY_COMMA,
    _OBJECT_START,
    _OBJECT_KEY,
    _OBJECT_COLON,
    _OBJECT_VALUE,
    _OBJECT_COMMA,
) = range(9)
_VALUE_STATES: Final = frozenset((_TOP, _ARRAY_START, _ARRAY_VALUE, _OBJECT_VALUE))

# Token kinds.
_OPEN_OBJECT, _OPEN_ARRAY, _CLOSE, _KEY, _STR, _NUM, _LIT = range(7)


class _Stop(Exception):
    """A token could not be read. clean: the input ended where a token would begin."""

    def __init__(self, detail: str, eof: bool = False, clean: bool = False) -> None:
        super().__init__(detail)
        self.detail, self.eof, self.clean = detail, eof, clean


class _Frame:
    __slots__ = ("elem", "fields", "is_object", "out", "struct", "target")

    def __init__(self, is_object: bool, target: Target | None) -> None:
        self.is_object = is_object
        self.target = target  # None: free-form (or a container that does not fit)
        self.struct: Struct | None = None
        self.fields: Mapping[str, Target] | None = None
        self.elem = FREE
        self.out: Any = {} if is_object else []
        if target is None:
            return
        if target.kind == STRUCT and target.cls is not None:
            self.struct = struct_of(target.cls)
            self.fields = self.struct.fields
        elif target.elem is not None:
            self.elem = target.elem


def run(data: bytes, limits: Limits | None, target: Target) -> Any:
    max_bytes, max_depth = (limits or Limits())._resolved()
    data = bytes(data)
    if len(data) > max_bytes:
        raise StrictJSONError(
            StrictJSONErrorKind.SIZE, offset=max_bytes, detail=f"limit is {max_bytes} bytes"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise StrictJSONError(StrictJSONErrorKind.INVALID_UTF8, offset=e.start) from None
    return _Walker(text, len(text) == len(data), max_depth).run(target)


class _Walker:
    """Reads the text once with Go's json.Decoder token rules, in step with the target."""

    def __init__(self, text: str, ascii: bool, max_depth: int) -> None:
        self.s = text
        self.n = len(text)
        self.ascii = ascii
        self.max_depth = max_depth
        self.pos = 0  # the decoder's input offset, in characters
        self.state = _TOP
        self.states: list[int] = []
        self.path: list[str] = []
        self.depth = 0
        self.surrogate: tuple[int, str] | None = None  # first unpaired escape: offset, detail
        self.mismatch: str | None = None  # first value that does not fit its target
        self.end = 0  # where the top-level value ends

    # -- reporting --

    def offset(self, pos: int) -> int:
        return pos if self.ascii else len(self.s[:pos].encode("utf-8"))

    def pointer(self) -> str:
        return "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in self.path)

    def fail(self, kind: StrictJSONErrorKind, detail: str = "") -> StrictJSONError:
        return StrictJSONError(kind, self.pointer(), self.offset(self.pos), detail)

    def token_error(self, e: _Stop) -> StrictJSONError:
        if e.eof:
            return self.fail(StrictJSONErrorKind.SYNTAX, "unexpected end of input")
        # A failed token leaves the offset at the start of the bad text.
        at = _WS.match(self.s, self.pos).end()  # type: ignore[union-attr]
        for lit in _NON_FINITE:
            if self.s.startswith(lit, at):
                return self.fail(StrictJSONErrorKind.NON_FINITE, f"{lit} is not a JSON number")
        return self.fail(StrictJSONErrorKind.SYNTAX, e.detail)

    def does_not_fit(self, what: str, t: Target) -> None:
        if self.mismatch is None:
            self.mismatch = f"{what} at {self.pointer() or '/'} does not fit {t.name()}"

    # -- tokens, as json.Decoder.Token reads them --

    def peek(self) -> str:
        i = self.pos
        if i < self.n and self.s[i] not in " \t\n\r":
            return self.s[i]
        i = _WS.match(self.s, i).end()  # type: ignore[union-attr]
        if i >= self.n:
            return ""  # the offset stays before the white space, as in Go
        self.pos = i
        return self.s[i]

    def more(self) -> bool:
        c = self.peek()
        return c != "" and c != "]" and c != "}"

    def bad(self, c: str, context: str) -> _Stop:
        return _Stop(f"invalid character {c!r} {context}")

    def token(self) -> tuple[int, Any]:
        while True:
            c = self.peek()
            if not c:
                raise _Stop("unexpected end of input", eof=True, clean=True)
            st = self.state
            if c == "{" or c == "[":
                if st not in _VALUE_STATES:
                    raise self.bad(c, "looking for beginning of value")
                self.pos += 1
                self.states.append(st)
                self.state = _OBJECT_START if c == "{" else _ARRAY_START
                return (_OPEN_OBJECT if c == "{" else _OPEN_ARRAY), None
            if c == "]" or c == "}":
                ok = (_ARRAY_START, _ARRAY_COMMA) if c == "]" else (_OBJECT_START, _OBJECT_COMMA)
                if st not in ok:
                    raise self.bad(c, "looking for beginning of value")
                self.pos += 1
                self.state = self.states.pop()
                self.value_end()
                return _CLOSE, None
            if c == ":":
                if st != _OBJECT_COLON:
                    raise self.bad(c, "looking for beginning of value")
                self.pos += 1
                self.state = _OBJECT_VALUE
                continue
            if c == ",":
                if st == _ARRAY_COMMA:
                    self.state = _ARRAY_VALUE
                elif st == _OBJECT_COMMA:
                    self.state = _OBJECT_KEY
                else:
                    raise self.bad(c, "looking for beginning of value")
                self.pos += 1
                continue
            if c == '"' and st in (_OBJECT_START, _OBJECT_KEY):
                key = self.read_string()
                self.state = _OBJECT_COLON
                return _KEY, key
            if st not in _VALUE_STATES:
                raise self.bad(c, "after object key" if st == _OBJECT_COLON else "after value")
            tok = self.read_scalar(c)
            self.value_end()
            return tok

    def value_end(self) -> None:
        if self.state in (_ARRAY_START, _ARRAY_VALUE):
            self.state = _ARRAY_COMMA
        elif self.state == _OBJECT_VALUE:
            self.state = _OBJECT_COMMA

    def read_scalar(self, c: str) -> tuple[int, Any]:
        if c == '"':
            return _STR, self.read_string()
        s, pos = self.s, self.pos
        if c == "-" or "0" <= c <= "9":
            m = _NUMBER.match(s, pos)
            if m is None:
                raise _Stop("invalid number", eof=pos + 1 >= self.n)
            end = m.end()
            if end < self.n:
                nxt = s[end]
                if nxt == "." and m.group(1) is None and m.group(2) is None:
                    raise _Stop("invalid number", eof=end + 1 >= self.n)
                if (nxt == "e" or nxt == "E") and m.group(2) is None:
                    j = end + 1
                    if j < self.n and s[j] in "+-":
                        j += 1
                    raise _Stop("invalid number", eof=j >= self.n)
            self.pos = end
            return _NUM, m
        lit = _LITERALS.get(c)
        if lit is not None:
            word, value = lit
            if s.startswith(word, pos):
                self.pos = pos + len(word)
                return _LIT, value
            raise _Stop(f"invalid literal, want {word}", eof=word.startswith(s[pos:]))
        raise self.bad(c, "looking for beginning of value")

    def read_string(self) -> str:
        s, start = self.s, self.pos
        m = _STRING_BODY.match(s, start)
        end = m.end() if m else start
        if m is None or end >= self.n or s[end] != '"':
            eof = end >= self.n or _ESCAPE_PREFIX.match(s, end) is not None
            raise _Stop("invalid string", eof=eof)
        end += 1
        if s.find("\\", start, end) < 0:
            value = s[start + 1 : end - 1]
        else:
            if self.surrogate is None and s.find("\\u", start, end) >= 0:
                self.check_surrogates(start, end)
            value, _ = _scanstring(s, start + 1, True)
        self.pos = end
        return value

    def check_surrogates(self, start: int, end: int) -> None:
        """Note the first \\uD800-\\uDFFF escape that is not a high surrogate followed at
        once by a low surrogate; Go reports it after the walk."""
        it = _ESCAPE.finditer(self.s, start, end)
        for m in it:
            h = m.group(1)
            if h is None:
                continue
            c = int(h, 16)
            if 0xDC00 <= c <= 0xDFFF:
                self.surrogate = (
                    m.start(),
                    f"low surrogate \\u{c:04x} without a high surrogate before it",
                )
                return
            if 0xD800 <= c <= 0xDBFF:
                lo = next(it, None)
                if (
                    lo is None
                    or lo.start() != m.end()
                    or lo.group(1) is None
                    or not 0xDC00 <= int(lo.group(1), 16) <= 0xDFFF
                ):
                    self.surrogate = (
                        m.start(),
                        f"high surrogate \\u{c:04x} without a low surrogate after it",
                    )
                    return

    # -- values --

    def scalar(self, kind: int, v: Any, t: Target) -> Any:
        if kind == _NUM:
            return self.number(v, t)
        if kind == _LIT:
            if v is None:
                if not t.nullable:
                    raise self.fail(StrictJSONErrorKind.NULL, f"target {t.name()} cannot hold null")
                return None
            if t.kind != BOOL and t.kind != RAW:
                self.does_not_fit("boolean", t)
            return v
        if t.kind != STRING and t.kind != RAW:
            self.does_not_fit("string", t)
        return v

    def number(self, m: re.Match[str], t: Target) -> Any:
        lit = m.group(0)
        if m.group(1) is not None or m.group(2) is not None:
            if t.kind == INT:
                raise self.fail(StrictJSONErrorKind.INTEGER, f"{lit} is not an integer")
            f = float(lit)
            if f == _INF or f == -_INF:
                raise self.fail(StrictJSONErrorKind.NON_FINITE, f"{lit} does not fit binary64")
            value: Any = f
        else:
            # The length check comes first: int() of a long literal is slow,
            # and refuses one over the digit limit with ValueError.
            if len(lit) - (lit[0] == "-") > 16 or abs(i := int(lit)) > MAX_SAFE_INTEGER:
                raise self.fail(
                    StrictJSONErrorKind.INTEGER, f"{lit} is outside ±{MAX_SAFE_INTEGER}"
                )
            if t.kind == INT and i < 0:
                raise self.fail(StrictJSONErrorKind.INTEGER, f"{lit} is negative")
            value = float(i) if t.kind == FLOAT else i
        if t.kind != INT and t.kind != FLOAT and t.kind != RAW:
            self.does_not_fit("number", t)
        return value

    def open(self, kind: int, t: Target) -> _Frame:
        self.depth += 1
        if self.depth > self.max_depth:
            raise self.fail(
                StrictJSONErrorKind.DEPTH,
                f"depth {self.depth} exceeds the limit of {self.max_depth}",
            )
        is_object = kind == _OPEN_OBJECT
        fits = (STRUCT, MAP, RAW) if is_object else (SLICE, RAW)
        if t.kind not in fits:
            self.does_not_fit("object" if is_object else "array", t)
            return _Frame(is_object, None)
        return _Frame(is_object, None if t.kind == RAW else t)

    def close(self, f: _Frame) -> Any:
        self.depth -= 1
        if not f.is_object:
            return tuple(f.out)
        built = f.target is not None and f.target.cls is not None and f.struct is not None
        if built and self.mismatch is None and self.surrogate is None:
            # A failed decode raises below, so a value that does not fit is never built.
            return build(cast(type, cast(Target, f.target).cls), f.out)
        return f.out

    def run(self, top: Target) -> Any:
        stack: list[_Frame] = []
        target = top
        while True:
            # A value for target.
            try:
                kind, v = self.token()
            except _Stop as e:
                raise self.token_error(e) from None
            if kind in (_OPEN_OBJECT, _OPEN_ARRAY):
                stack.append(self.open(kind, target))
                have = False
                value: Any = None
            else:
                value, have = self.scalar(kind, v, target), True
            # The containers: store the value, then read the next member or close.
            while stack:
                f = stack[-1]
                if have:
                    if f.is_object:
                        f.out[self.path.pop()] = value
                    else:
                        f.out.append(value)
                        self.path.pop()
                    have = False
                if self.more():
                    target = self.member(f)
                    break
                try:
                    self.token()  # the closing brace or bracket
                except _Stop as e:
                    raise self.token_error(e) from None
                value, have = self.close(stack.pop()), True
            if not stack:
                break
        self.end = self.pos
        self.trailing()
        if self.surrogate is not None:
            at, detail = self.surrogate
            raise StrictJSONError(StrictJSONErrorKind.LONE_SURROGATE, "", self.offset(at), detail)
        if self.mismatch is not None:
            raise StrictJSONError(
                StrictJSONErrorKind.TYPE, "", self.offset(self.end), self.mismatch
            )
        return value

    def member(self, f: _Frame) -> Target:
        """Read the next member name of an object (or open the next array element) and
        return the target of its value."""
        if not f.is_object:
            self.path.append(str(len(f.out)))
            return f.elem
        try:
            kind, key = self.token()
        except _Stop as e:
            raise self.token_error(e) from None
        if kind != _KEY:
            raise self.fail(StrictJSONErrorKind.SYNTAX, "object member name is not a string")
        self.path.append(key)
        if key in f.out:
            raise self.fail(StrictJSONErrorKind.DUPLICATE_KEY, json.dumps(key))
        if f.fields is not None:
            t = f.fields.get(key)
            if t is None:
                name = f.target.name() if f.target is not None else "the target"
                raise self.fail(
                    StrictJSONErrorKind.UNKNOWN_FIELD,
                    f"{json.dumps(key)} is not a field of {name}",
                )
            return t
        return f.elem

    def trailing(self) -> None:
        try:
            self.token()
        except _Stop as e:
            if e.clean:
                return
        raise self.fail(StrictJSONErrorKind.TRAILING_DATA)


_INF: Final = float("inf")
