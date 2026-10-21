//! Rust SDK of the PACT protocol (Purpose-bound Access Control & Trust): the
//! wire types, strict JSON, RFC 8785 canonical JSON, digests, the ES256 JWS
//! profile with JWKs and RFC 7638 thumbprints, the time rules, and schema
//! validation.
//!
//! The modules follow the `core` packages of the Go reference
//! implementation, `hop.top/pact-go`, and pass the same language-neutral
//! vectors:
//!
//! - [`core`]: the wire objects and limits;
//! - [`core::strictjson`], [`core::jcs`], [`core::digest`]: strict decoding,
//!   canonical JSON and the object, artifact and bytes digests;
//! - [`core::jws`]: signing and verification of compact JWS, key sets and
//!   resolvers;
//! - [`core::clock`]: validity windows, lifetimes and replay retention;
//! - [`core::schema`]: validation against the PACT JSON Schema.
#![forbid(unsafe_code)]

pub mod core;

/// The examples of README.md, run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
