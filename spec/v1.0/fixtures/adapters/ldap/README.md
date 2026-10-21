# LDAP adapter cases

These are the cases of the LDAP adapter of the integration profile
[`profiles/ldap`](../../../profiles/ldap/profile.md). They run after the
common cases, with the case file format, the outcomes and the checks of
[`../README.md`](../README.md). The profile does not support workloads shared
by several agents, so a harness runs the `dedicated` cases. Section 10 of the
profile says which closure item each file implements; the IDs `LDAP-01` to
`LDAP-11` are those of the profile.

The common cases state their native state in the `common/1` model. An LDAP
harness realizes the identities of `common/1` as accounts of one OpenLDAP
realm, whose login name is the identity's `ref` and whose password is its
`secret`; the other members are deployment-supplied sources, as for every
adapter. The principal an LDAP account authenticates as is
`ldap:{realm_id}:{unique_id}` (profile LR-2), which cannot be the identifier a
common `authenticate_native` case expects; the profile lists the replaced
common cases. The cases in this directory state their native state in the
model `ldap/1` below.

## Model `ldap/1`

```
{
  "model": "ldap/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "login_realm": "<realm_id>",
  "directories": [{
    "name",
    "seed": "assets/<file>.ldif",
    "changes": ["assets/<file>.ldif", ...],             // optional
    "unreachable": true,                                // optional
    "tls_fails": true,                                  // optional
    "in_chain": false,                                  // optional
    "hidden": [{"base", "attributes": [...]} | {"base", "entries": true}]  // optional
  }],
  "realms": [{
    "realm_id", "kind", "directory",
    "unique_id_text": "rfc4122-octet-order",            // activedirectory only
    "user_bases": [...], "group_bases": [...],
    "account_class", "group_class", "login_attribute",
    "lookup": {"dn", "password"},
    "denied_principals": [...],
    "sentinel": {"account", "group", "parent_group"},   // parent_group optional
    "direct_groups": true | false,
    "nested": "none" | "ad-chain"
  }],
  "credentials": [{"ref", "user_id", "password"}],      // optional
  "enrollments": [...],                                 // optional
  "permissions": [{"principal", "action", "resource"}], // optional
  "execution": {"running_identity"},                    // optional
  "reporting": {"issuer", "audience", "kid"}            // optional
}
```

- `gateway`: as in `common/1`. Every directory realm belongs to the PACT realm
  of the gateway (profile LR-1).
- `login_realm`: the realm whose directory `authenticate_native` searches.
  Claim reads go to the realm the principal identifier names.
- `directories`: the directory servers.
  - `seed` is an LDIF file (RFC 2849) of content records, relative to this
    directory, that the server holds at the start of the case. Each entry
    states its unique id: `entryUUID` for OpenLDAP, which a harness loads with
    the Relax Rules control or with `slapadd`, and `objectGUID`, 16 octets in
    base64, for Active Directory. `memberOf` is never stated: the server
    derives it from the `member` values of the groups of the seed, as the
    OpenLDAP memberof overlay and Active Directory do (profile LR-16).
  - `changes` are LDIF files of change records applied in order after the
    seed, such as a removed member or a deleted entry.
  - `unreachable`: no connection to the server can be opened.
    `tls_fails`: the TLS negotiation of every connection fails.
  - `in_chain`: whether the server evaluates the matching rule
    `1.2.840.113556.1.4.1941` (LDAP_MATCHING_RULE_IN_CHAIN). Absent, an
    Active Directory server does and an OpenLDAP server does not. A server
    that does not evaluates such a filter item as Undefined, so the entry is
    not returned and no error is reported (RFC 4511, section 4.5.1.7).
  - `hidden`: what the directory's access control withholds from the lookup
    account under `base`, without an error: the listed `attributes` of each
    entry, or, with `entries`, the entries themselves (RFC 4511, sections
    4.5.1.8 and 4.5.2; profile LR-14).
- `realms`: the realm records of profile Appendix A. `kind` is `openldap` or
  `activedirectory`; `directory` names the server. The unique id attribute
  follows from `kind` (profile LR-2). `unique_id_text` says how the 16 octets
  of `objectGUID` become the identifier text: `rfc4122-octet-order` writes
  them in the order received as the hyphenated hexadecimal form of RFC 4122.
  The profile leaves the order to a probe (Appendix H, P3); a deployment
  states the order it established, and these cases state this one.
  `lookup` is the lookup account and its password. `sentinel` gives the
  unique ids of the sentinel account, its group and, for `ad-chain`, the
  parent group (profile LR-14). `direct_groups` false is an OpenLDAP
  database without the memberof overlay (profile LR-16).
- `credentials`: what a client holds. The credential hook attaches the
  identity `ref` names as the `Authorization` header `Basic` followed by the
  Base64 encoding of the UTF-8 octets of user-id, a colon, and password
  (RFC 7617, section 2). The profile does not fix how the request carries the
  name and the password; the adapter of this repository reads them from the
  Basic scheme.
- `enrollments`, `reporting`: as in `common/1`.
- `permissions`: the application's native permissions, whose source id is
  `inventory-permissions`: each entry allows one principal one action on one
  resource; every other request is denied.
- `execution`: the identity under which the application would run the
  operation, as the deployment's executor source reports it, for the check
  `execution-identity-v1` (draft 17.5). The executor the mapping declares for
  route R1 is the authenticated account itself.

The installed operation mapping is that of the profile's reference route R1,
revision `pact-ldap-1`: `GET /api/v1/warehouses/{warehouse_id}/stock` maps to
the action `stock.read` and the resource `warehouse:{warehouse_id}`.

## Hooks

Besides `execute`, an LDAP harness fires the hook `directory` each time the
adapter opens a connection to a directory server. A case with
`must_not_call: ["directory"]` requires that the adapter answered without
sending anything to the directory (profile LR-6, LR-17).

## Integration tier

The seed, the change files, and the cases run against a real OpenLDAP 2.6
server as well. The server loads the memberof and ppolicy overlays and lets
the lookup accounts read every entry under the suffix `dc=northstar,dc=example`
except `userPassword`. Before each case the harness restores the seed with
the Relax Rules control and then applies the case's changes. Cases whose
directory is Active Directory, or that state `tls_fails`, `in_chain` or
`hidden`, need a server behavior a single OpenLDAP instance does not have and
run in the unit tier only; `unreachable` is a closed port.
