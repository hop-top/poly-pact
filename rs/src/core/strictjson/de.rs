//! The type-level rules: a serde `Deserializer` over the tree the reader
//! built. It reports unknown fields, `null` for a target that cannot hold it,
//! and negative or non-integer numbers for an integer target, with the JSON
//! Pointer of the member.

use std::fmt;

use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Unexpected, Visitor};

use super::parse::{Node, Number, V, pointer};
use super::{Error, Kind};

/// An error on its way out: the path is collected in reverse while the
/// deserializer unwinds, and the offset is the one of the innermost value.
#[derive(Debug)]
pub(crate) struct DeError {
    kind: Kind,
    detail: String,
    rev_path: Vec<String>,
    offset: Option<usize>,
}

impl DeError {
    fn new(kind: Kind, detail: impl Into<String>) -> DeError {
        DeError { kind, detail: detail.into(), rev_path: Vec::new(), offset: None }
    }

    fn at(mut self, seg: impl Into<String>, off: usize) -> DeError {
        self.rev_path.push(seg.into());
        if self.offset.is_none() {
            self.offset = Some(off);
        }
        self
    }

    pub(crate) fn finish(self) -> Error {
        let path: Vec<&String> = self.rev_path.iter().rev().collect();
        Error { kind: self.kind, path: pointer(&path), offset: self.offset.unwrap_or(0), detail: self.detail }
    }
}

impl fmt::Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for DeError {}

impl de::Error for DeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        DeError::new(Kind::Type, msg.to_string())
    }

    fn invalid_type(unexp: Unexpected<'_>, exp: &dyn de::Expected) -> Self {
        if let Unexpected::Unit = unexp {
            return DeError::new(Kind::Null, format!("target {exp} cannot hold null"));
        }
        DeError::new(Kind::Type, format!("invalid type: {unexp}, expected {exp}"))
    }

    fn unknown_field(field: &str, expected: &'static [&'static str]) -> Self {
        DeError::new(Kind::UnknownField, format!("{field:?} is not a field; fields: {}", expected.join(", ")))
    }

    fn duplicate_field(field: &'static str) -> Self {
        DeError::new(Kind::DuplicateKey, format!("{field:?}"))
    }
}

pub(crate) struct NodeDe<'a> {
    node: &'a Node,
}

impl<'a> NodeDe<'a> {
    pub(crate) fn root(node: &'a Node) -> NodeDe<'a> {
        NodeDe { node }
    }

    fn here(&self, e: DeError) -> DeError {
        DeError { offset: e.offset.or(Some(self.node.off)), ..e }
    }

    fn integer<V2: Visitor<'a>>(self, visitor: V2) -> Result<V2::Value, DeError> {
        match &self.node.v {
            V::Number(Number::Int(n)) if *n < 0 => {
                Err(self.here(DeError::new(Kind::Integer, format!("{n} is negative"))))
            }
            V::Number(Number::Int(n)) => visitor.visit_u64(*n as u64),
            V::Number(Number::Float(f)) => {
                Err(self.here(DeError::new(Kind::Integer, format!("{f} is not an integer"))))
            }
            _ => self.deserialize_any_inner(visitor),
        }
    }

    fn deserialize_any_inner<V2: Visitor<'a>>(self, visitor: V2) -> Result<V2::Value, DeError> {
        let off = self.node.off;
        let r = match &self.node.v {
            V::Null => visitor.visit_unit(),
            V::Bool(b) => visitor.visit_bool(*b),
            V::Number(Number::Int(n)) if *n >= 0 => visitor.visit_u64(*n as u64),
            V::Number(Number::Int(n)) => visitor.visit_i64(*n),
            V::Number(Number::Float(f)) => visitor.visit_f64(*f),
            V::String(s) => visitor.visit_borrowed_str(s),
            V::Array(items) => visitor.visit_seq(Seq { items: items.iter(), index: 0 }),
            V::Object(members) => visitor.visit_map(Map { members: members.iter(), pending: None }),
        };
        r.map_err(|e| DeError { offset: e.offset.or(Some(off)), ..e })
    }
}

macro_rules! integer_targets {
    ($($m:ident)*) => {$(
        fn $m<V2: Visitor<'de>>(self, visitor: V2) -> Result<V2::Value, DeError> {
            self.integer(visitor)
        }
    )*};
}

impl<'de> de::Deserializer<'de> for NodeDe<'de> {
    type Error = DeError;

    fn deserialize_any<V2: Visitor<'de>>(self, visitor: V2) -> Result<V2::Value, DeError> {
        self.deserialize_any_inner(visitor)
    }

    integer_targets!(deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64 deserialize_i128
        deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64 deserialize_u128);

    fn deserialize_option<V2: Visitor<'de>>(self, visitor: V2) -> Result<V2::Value, DeError> {
        match self.node.v {
            V::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_newtype_struct<V2: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V2,
    ) -> Result<V2::Value, DeError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V2: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V2,
    ) -> Result<V2::Value, DeError> {
        match &self.node.v {
            V::String(s) => visitor.visit_enum(s.as_str().into_deserializer()).map_err(|e: DeError| self.here(e)),
            _ => Err(self.here(DeError::new(Kind::Type, "an enum is a JSON string"))),
        }
    }

    fn deserialize_ignored_any<V2: Visitor<'de>>(self, visitor: V2) -> Result<V2::Value, DeError> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool f32 f64 char str string bytes byte_buf unit unit_struct seq tuple
        tuple_struct map struct identifier
    }
}

struct Seq<'a> {
    items: std::slice::Iter<'a, Node>,
    index: usize,
}

impl<'de> SeqAccess<'de> for Seq<'de> {
    type Error = DeError;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, DeError> {
        let Some(node) = self.items.next() else { return Ok(None) };
        let i = self.index;
        self.index += 1;
        seed.deserialize(NodeDe { node }).map(Some).map_err(|e| e.at(i.to_string(), node.off))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len())
    }
}

struct Map<'a> {
    members: std::slice::Iter<'a, (String, Node)>,
    pending: Option<&'a (String, Node)>,
}

impl<'de> MapAccess<'de> for Map<'de> {
    type Error = DeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, DeError> {
        let Some(m) = self.members.next() else { return Ok(None) };
        self.pending = Some(m);
        let key: de::value::BorrowedStrDeserializer<'de, DeError> = de::value::BorrowedStrDeserializer::new(&m.0);
        seed.deserialize(key).map(Some).map_err(|e| e.at(m.0.clone(), m.1.off))
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, DeError> {
        let Some(m) = self.pending.take() else {
            return Err(DeError::new(Kind::Type, "value requested before its key"));
        };
        seed.deserialize(NodeDe { node: &m.1 }).map_err(|e| e.at(m.0.clone(), m.1.off))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.members.len())
    }
}
