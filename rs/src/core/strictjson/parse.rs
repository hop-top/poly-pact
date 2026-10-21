//! The strict reader: RFC 8259 syntax, read once into a tree, with the
//! document-level rules (duplicate names, depth, numbers, surrogates,
//! trailing data). Type-level rules are applied by `de`.

use std::collections::HashSet;

use super::{Error, Kind, Limits, MAX_SAFE_INTEGER};

/// A number as read: an integer literal (no fraction, no exponent) within
/// ±(2^53-1), or a finite binary64 value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Number {
    Int(i64),
    Float(f64),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum V {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Node>),
    /// Members in document order; names are unique.
    Object(Vec<(String, Node)>),
}

/// A value and the byte offset at which it starts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Node {
    pub(crate) off: usize,
    pub(crate) v: V,
}

/// A document that passed the reader. `surrogate` holds the first unpaired
/// surrogate escape, which is reported only after the type-level checks, as
/// the Go reference does.
pub(crate) struct Document {
    pub(crate) root: Node,
    pub(crate) surrogate: Option<Error>,
}

impl Document {
    pub(crate) fn read(data: &[u8], lim: Limits) -> Result<Document, Error> {
        if data.len() > lim.max_bytes {
            return Err(Error::new(Kind::Size, lim.max_bytes, format!("limit is {} bytes", lim.max_bytes)));
        }
        let text = std::str::from_utf8(data).map_err(|e| Error::new(Kind::InvalidUtf8, e.valid_up_to(), ""))?;
        let mut r = Reader {
            s: text.as_bytes(),
            text,
            i: 0,
            depth: 0,
            max_depth: lim.max_depth,
            path: Vec::new(),
            surrogate: None,
        };
        r.ws();
        let root = r.value()?;
        r.ws();
        if r.i < r.s.len() {
            return Err(r.fail(Kind::TrailingData, ""));
        }
        Ok(Document { root, surrogate: r.surrogate })
    }
}

struct Reader<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
    depth: usize,
    max_depth: usize,
    path: Vec<String>,
    surrogate: Option<Error>,
}

/// The JSON Pointer (RFC 6901) of a path.
pub(crate) fn pointer<S: AsRef<str>>(path: &[S]) -> String {
    let mut p = String::new();
    for seg in path {
        p.push('/');
        p.push_str(&seg.as_ref().replace('~', "~0").replace('/', "~1"));
    }
    p
}

impl Reader<'_> {
    fn fail(&self, kind: Kind, detail: impl Into<String>) -> Error {
        Error { kind, path: pointer(&self.path), offset: self.i, detail: detail.into() }
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.s.get(self.i) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn syntax(&self, what: &str) -> Error {
        match self.peek() {
            None => self.fail(Kind::Syntax, "unexpected end of input"),
            Some(c) if c.is_ascii_graphic() => {
                self.fail(Kind::Syntax, format!("invalid character {:?} {what}", c as char))
            }
            Some(c) => self.fail(Kind::Syntax, format!("invalid character 0x{c:02x} {what}")),
        }
    }

    fn value(&mut self) -> Result<Node, Error> {
        let off = self.i;
        let v = match self.peek() {
            Some(b'{') => self.object()?,
            Some(b'[') => self.array()?,
            Some(b'"') => V::String(self.string()?),
            Some(b't') => self.literal("true", V::Bool(true))?,
            Some(b'f') => self.literal("false", V::Bool(false))?,
            Some(b'n') => self.literal("null", V::Null)?,
            Some(b'-' | b'0'..=b'9') => {
                if self.s[self.i..].starts_with(b"-Infinity") {
                    return Err(self.fail(Kind::NonFinite, "-Infinity is not a JSON number"));
                }
                V::Number(self.number()?)
            }
            _ => {
                for lit in ["NaN", "Infinity", "+Infinity"] {
                    if self.s[self.i..].starts_with(lit.as_bytes()) {
                        return Err(self.fail(Kind::NonFinite, format!("{lit} is not a JSON number")));
                    }
                }
                return Err(self.syntax("looking for beginning of value"));
            }
        };
        Ok(Node { off, v })
    }

    fn literal(&mut self, word: &str, v: V) -> Result<V, Error> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.syntax(&format!("in literal {word}")))
        }
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(self.fail(Kind::Depth, format!("depth {} exceeds the limit of {}", self.depth, self.max_depth)));
        }
        Ok(())
    }

    fn object(&mut self) -> Result<V, Error> {
        self.enter()?;
        self.i += 1;
        let mut members: Vec<(String, Node)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(V::Object(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.syntax("looking for beginning of object key string"));
            }
            let key = self.string()?;
            self.path.push(key.clone());
            if !seen.insert(key.clone()) {
                return Err(self.fail(Kind::DuplicateKey, format!("{key:?}")));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.syntax("after object key"));
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            self.path.pop();
            members.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(V::Object(members));
                }
                _ => return Err(self.syntax("after object key:value pair")),
            }
        }
    }

    fn array(&mut self) -> Result<V, Error> {
        self.enter()?;
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(V::Array(items));
        }
        loop {
            self.ws();
            self.path.push(items.len().to_string());
            let v = self.value()?;
            self.path.pop();
            items.push(v);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(V::Array(items));
                }
                _ => return Err(self.syntax("after array element")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while let Some(b'0'..=b'9') = self.peek() {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Number, Error> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if let Some(b'0'..=b'9') = self.peek() {
                    return Err(self.syntax("after top-level value"));
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.syntax("in numeric literal")),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.i += 1;
            if self.digits() == 0 {
                return Err(self.syntax("after decimal point in numeric literal"));
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            float = true;
            self.i += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(self.syntax("in exponent of numeric literal"));
            }
        }
        let lit = &self.text[start..self.i];
        if float {
            return match lit.parse::<f64>() {
                Ok(f) if f.is_finite() => Ok(Number::Float(f)),
                _ => Err(Error { offset: start, ..self.fail(Kind::NonFinite, format!("{lit} does not fit binary64")) }),
            };
        }
        match lit.parse::<i64>() {
            Ok(n) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) => Ok(Number::Int(n)),
            _ => Err(Error {
                offset: start,
                ..self.fail(Kind::Integer, format!("{lit} is outside ±{MAX_SAFE_INTEGER}"))
            }),
        }
    }

    fn hex4(&self, at: usize) -> Option<u16> {
        let h = self.s.get(at..at + 4)?;
        let mut r: u16 = 0;
        for &c in h {
            let d = (c as char).to_digit(16)? as u16;
            r = r << 4 | d;
        }
        Some(r)
    }

    fn lone(&mut self, at: usize, detail: String) {
        if self.surrogate.is_none() {
            self.surrogate = Some(Error { kind: Kind::LoneSurrogate, path: pointer(&self.path), offset: at, detail });
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        self.i += 1;
        let mut out = String::new();
        let mut run = self.i;
        loop {
            let Some(c) = self.peek() else {
                return Err(self.fail(Kind::Syntax, "unexpected end of input in string literal"));
            };
            match c {
                b'"' => {
                    out.push_str(&self.text[run..self.i]);
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.text[run..self.i]);
                    self.escape(&mut out)?;
                    run = self.i;
                }
                0x00..=0x1f => return Err(self.syntax("in string literal")),
                _ => self.i += 1,
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), Error> {
        let at = self.i;
        self.i += 1;
        let c = self.peek();
        self.i += 1;
        let ch = match c {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let Some(u) = self.hex4(self.i) else {
                    return Err(self.fail(Kind::Syntax, "invalid \\u escape in string literal"));
                };
                self.i += 4;
                match u {
                    0xDC00..=0xDFFF => {
                        self.lone(at, format!("low surrogate \\u{u:04x} without a high surrogate before it"));
                        '\u{fffd}'
                    }
                    0xD800..=0xDBFF => {
                        let low =
                            if self.s.get(self.i..self.i + 2) == Some(b"\\u") { self.hex4(self.i + 2) } else { None };
                        match low {
                            Some(l @ 0xDC00..=0xDFFF) => {
                                self.i += 6;
                                let cp = 0x10000 + ((u32::from(u) - 0xD800) << 10) + (u32::from(l) - 0xDC00);
                                char::from_u32(cp).unwrap_or('\u{fffd}')
                            }
                            _ => {
                                self.lone(at, format!("high surrogate \\u{u:04x} without a low surrogate after it"));
                                '\u{fffd}'
                            }
                        }
                    }
                    _ => char::from_u32(u32::from(u)).unwrap_or('\u{fffd}'),
                }
            }
            _ => {
                self.i -= 1;
                return Err(self.syntax("in string escape code"));
            }
        };
        out.push(ch);
        Ok(())
    }
}
