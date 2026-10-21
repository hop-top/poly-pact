# mTLS adapter cases

These are the cases of the mTLS adapter of the integration profile
[`profiles/mtls`](../../../profiles/mtls/profile.md). They run after the
common cases, with the case file format, the outcomes and the checks of
[`../README.md`](../README.md). The profile does not support workloads shared
by several agents, so a harness runs the `dedicated` cases. Section 10 of the
profile says which case group each file belongs to, which behaviour is tested
outside these files, and which common cases the adapter replaces.

The cases do not use `request.tls_peer`: a certificate built from those
members has no signature that an X.509 verifier could check. They state real
certificates in the native state instead, as `mtls/1` below, and the harness
mints them. Every key is derived from a seed, so a case can state the
thumbprint of a key without holding the key.

## Model `mtls/1`

```
{
  "model": "mtls/1",
  "listener": {"role", "tenant_id", "environment_id"},
  "status_bound_seconds": <seconds>,
  "authorities": [{"ref", "subject_cn", "key_seed", "issuer", "not_before", "not_after"}],
  "pinned_cas": [{"ca_id", "authority", "san_kind"}],
  "terminators": ["<identifier>", ...],                    // optional
  "peers": [{"ref", "issuer", "serial", "subject_cn", "uris", "dns_names",
             "not_before", "not_after", "ext_key_usage", "key_usage",
             "is_ca", "key_seed", "chain", "ocsp_servers"}],
  "snapshots": [{"ca_id", "number", "this_update", "next_update",
                 "revoked": [{"serial", "reason", "revoked_at"}]}],
  "connection": {"tls_version", "resumed", "cleartext"},  // optional
  "forwarded": [[["<key>", "<value>"], ...], ...],         // optional
  "enrollments": [...],                                    // optional
  "unavailable_sources": [...]                             // optional
}
```

Times are Unix seconds.

- `listener`: the listener that accepted the connection. `role` is `direct`
  or `terminated` (profile MTLS-22), and the realm is the listener's, never a
  value of a certificate (MTLS-6).
- `status_bound_seconds`: the status bound `S` of MTLS-14.
- `authorities`: every certificate authority of the case, pinned or not. An
  authority is a CA certificate with `cA` true and the key usages
  `digitalSignature`, `keyCertSign` and `cRLSign`; its subject is the common
  name `subject_cn` alone. It is self-signed, or issued by the authority that
  `issuer` names. Two authorities may have the same subject text.
- `pinned_cas`: the pinned CA set (MTLS-2): the `ca-id` of each entry, the
  authority whose certificate is the trust anchor, and the `san-kind` (`uri` or
  `dns`) that the authority uses to name workloads. An authority that no entry
  names is not pinned.
- `terminators`: the terminator allowlist of a terminated listener, as
  identifiers of MTLS-6 (MTLS-23).
- `peers`: end-entity certificates. `issuer` names the authority that signs
  it, `serial` is its serial number, and its subject is the common name
  `subject_cn` alone. `uris` and `dns_names` are the entries of its subject
  alternative name extension, URIs first, each written as the octets given;
  with both empty the certificate has no such extension. `ext_key_usage` lists
  `client_auth`, `server_auth` or `any` (anyExtendedKeyUsage); `null` means no
  extended key usage extension. `key_usage` lists `digital_signature`,
  `key_encipherment`, `key_agreement`, `cert_sign` or `crl_sign`; `null` means
  no key usage extension. `is_ca` true asserts `cA` in a basic constraints
  extension; absent or false, a peer has no basic constraints extension.
  `chain` lists the authorities whose certificates the peer sends after its
  own, in that order; absent, it sends none. `ocsp_servers` are the OCSP
  locations of its authority information access extension.
- `snapshots`: the certificate revocation list held for a pinned CA: a v2 CRL
  signed with that CA's key, with that issuer, `thisUpdate`, `nextUpdate`, the
  CRL number and the CA's key identifier as authority key identifier. Each
  entry of `revoked` lists a serial with its revocation time `revoked_at` and
  its RFC 5280 reason (`unspecified`, which the list states by having no
  reason code, `keyCompromise`, `certificateHold`, ...). A pinned CA without
  a snapshot has no usable status (MTLS-15).
- `connection`: the TLS connection the request arrived on. `tls_version` is
  `1.3` (the default) or `1.2`; `resumed` true says that the TLS stack reports
  the session as resumed; `cleartext` true says the request arrived without
  TLS.
- `forwarded`: the elements of an `x-forwarded-client-cert` header in the text
  form of MTLS-24, each a list of key and value pairs in order. A value
  `@cert:<ref>` stands for the PEM certificate of that peer, and
  `@certs:<ref>,<ref>` for the PEM certificates of both, concatenated; either
  is written with every octet that is not unreserved (RFC 3986, section 2.3)
  percent-encoded in upper-case hexadecimal. A value that contains `,`, `;`,
  `=` or `"` is written in double quotes, with `\"` for a double quote. Pairs
  are joined by `;`, elements by `,`. Absent, the request has no such header.
- `enrollments`, `unavailable_sources`: as in `common/1`.

### Keys

The private key of an authority or a peer is the P-256 key whose scalar is
the SHA-256 digest of the UTF-8 octets of `key_seed`, read as a big-endian
integer. Two certificates with the same seed have the same key. A case that
states a key thumbprint, as the attribute `cnf` of an authenticated principal,
states the RFC 7638 thumbprint of the public key of that seed.

### Credentials

`request.native_state_ref` names the TLS peer of the connection: a peer, or an
authority, whose own certificate is then presented with its key. The
harness's credential hook gives the request the TLS state of a completed
handshake with that peer, holding the peer's certificate and those of its
`chain`, at the TLS version and with the resumption flag of `connection`; with
`cleartext` it gives the request no TLS state. When the state has `forwarded`,
the hook also sets the `x-forwarded-client-cert` header. On a terminated
listener the TLS peer is the terminator, and the forwarded header carries the
certificate of the end client. A request without `native_state_ref` has no
client certificate.

## Common cases

The common cases state their native state in `common/1`. An mTLS harness
realizes it with one certificate authority per case, pinned with the `ca-id`
`common` and the `san-kind` `uri`, and an empty snapshot whose `thisUpdate` is
one second before the case's `now`. Each identity of the state is a peer
certificate of that authority whose URI name is the identity's `workload` when
that is an absolute URI, and `urn:pact:common:<ref>` otherwise. The other
functions use the deployment-supplied sources that `common/1` describes. Eight
common `authenticate_native` cases expect a principal or a denial reason that a
certificate cannot carry and are replaced (profile section 10; adapters README,
"Replaced common cases").
