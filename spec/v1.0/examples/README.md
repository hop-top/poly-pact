# PACT examples

Informative examples for PACT Protocol v1.0. Names, identifiers, routes, policies, and thresholds are fictional. Excerpts are partial illustrations, not signed wire fixtures or tested implementations.

## Use cases

Worked behavioral examples. `U` numbers are preserved from the original series.
[U13](example_U13.md) follows the registration model in [Section 16.3](../draft.md#163-candidate-artifacts-and-evaluation): private staging, one signed manifest, and a new manifest for any later change.

| # | File | Use case |
|---|---|---|
| U01 | [example_U01.md](example_U01.md) | Finance assistant reads invoices |
| U05 | [example_U05.md](example_U05.md) | Valid profile, insufficient resource permissions |
| U06 | [example_U06.md](example_U06.md) | Purchase requires supervisor approval |
| U07 | [example_U07.md](example_U07.md) | Authorized person grants an exceptional pass |
| U09 | [example_U09.md](example_U09.md) | Reliable agent earns reduced scrutiny |
| U13 | [example_U13.md](example_U13.md) | Gateway learns a better admission policy |

## Integrations

Integration samples for native authentication and authorization mechanisms. `I` numbers are preserved from the original series.

| # | File | System or mechanism |
|---|---|---|
| I01 | [example_I01.md](example_I01.md) | HTTP Basic authentication; [profile](../profiles/basic/profile.md) |
| I02 | [example_I02.md](example_I02.md) | Microsoft 365 with Entra ID, OIDC, and OAuth; [profile](../profiles/oauth/profile.md) (inbound token), [profile](../profiles/graph/profile.md) (Graph, delegated) |
| I03 | [example_I03.md](example_I03.md) | OAuth-protected API; [profile](../profiles/oauth/profile.md) |
| I04 | [example_I04.md](example_I04.md) | File access under the user's own permissions; [profile](../profiles/files/profile.md) (local NTFS; SMB and Unix not claimed) |
| I05 | [example_I05.md](example_I05.md) | SAML enterprise SSO; [profile](../profiles/saml/profile.md) |
| I06 | [example_I06.md](example_I06.md) | LDAP-backed authentication and groups; [profile](../profiles/ldap/profile.md) (OpenLDAP 2.6, Active Directory) |
| I07 | [example_I07.md](example_I07.md) | Client certificates and mutual TLS; [profile](../profiles/mtls/profile.md) |
| I08 | [example_I08.md](example_I08.md) | App-only service identity without a signed-in user; [profile](../profiles/graph/profile.md) (Graph, application) |
| I09 | [example_I09.md](example_I09.md) | AWS IAM roles, temporary credentials, and policy boundaries; [profile](../profiles/aws/profile.md) |
| I10 | [example_I10.md](example_I10.md) | Kubernetes service accounts and namespace RBAC; [profile](../profiles/k8s/profile.md) |
| I11 | [example_I11.md](example_I11.md) | Attribute-based access control (ABAC); [profile](../profiles/abac/profile.md) (Open Policy Agent) |
| I12 | [example_I12.md](example_I12.md) | Relationship-based access control (ReBAC); [profile](../profiles/rebac/profile.md) (OpenFGA) |
| I13 | [example_I13.md](example_I13.md) | Database privileges and row-level security; [profile](../profiles/db/profile.md) (PostgreSQL 16) |
| I14 | [example_I14.md](example_I14.md) | Privileged access management and just-in-time activation; [profile](../profiles/oauth/profile.md) (inbound token) |

The [multi-operation profile](../profiles/multi-operation.md) carries the task, budget, retry, and side-effect rules that span exchanges. Its section 13 works [I02](example_I02.md) (mailbox pages), [I03](example_I03.md) (record reads under a refreshed token), [I08](example_I08.md) (pages of a scheduled run), and [I14](example_I14.md) (the virtual machine restart) row by row, and points to [U01](example_U01.md), [U06](example_U06.md), and [U07](example_U07.md). Those examples cite its rules `MO-n` and its cases `TASK-01` to `TASK-09`, which are tests of a Go package of the source repository, not fixture cases.

## Outcome mapping index

Every example cites the baseline native outcome mapping in [Section 14.5](../draft.md#145-baseline-native-outcome-mapping) in its reputation or outcomes section, or the closest equivalent. The index below lists the examples that exercise each row. The PACT admission decision row carries zero weight in every example, and no example treats admission as task success.

| 14.5 row | Examples |
|---|---|
| PACT admission decision | All 20 examples |
| Native authorization allow | [U01](example_U01.md), [U06](example_U06.md), [U07](example_U07.md), [I01](example_I01.md), [I02](example_I02.md), [I03](example_I03.md), [I04](example_I04.md), [I05](example_I05.md), [I06](example_I06.md), [I07](example_I07.md), [I08](example_I08.md), [I09](example_I09.md), [I10](example_I10.md), [I11](example_I11.md), [I12](example_I12.md), [I13](example_I13.md), [I14](example_I14.md) |
| Native denial | [U01](example_U01.md), [U05](example_U05.md), [U07](example_U07.md), [I01](example_I01.md), [I02](example_I02.md), [I03](example_I03.md), [I04](example_I04.md), [I05](example_I05.md), [I06](example_I06.md), [I07](example_I07.md), [I08](example_I08.md), [I09](example_I09.md), [I10](example_I10.md), [I11](example_I11.md), [I12](example_I12.md), [I13](example_I13.md), [I14](example_I14.md) |
| Pre-authentication or transport failure | [I01](example_I01.md), [I03](example_I03.md), [I05](example_I05.md), [I06](example_I06.md), [I07](example_I07.md), [I09](example_I09.md) |
| Execution completed with data returned | [U01](example_U01.md), [U06](example_U06.md), [U07](example_U07.md), [U09](example_U09.md), [U13](example_U13.md), [I01](example_I01.md), [I02](example_I02.md), [I03](example_I03.md), [I04](example_I04.md), [I05](example_I05.md), [I06](example_I06.md), [I07](example_I07.md), [I08](example_I08.md), [I09](example_I09.md), [I10](example_I10.md), [I11](example_I11.md), [I12](example_I12.md), [I13](example_I13.md) |
| Execution completed, zero rows or filtered result | [I13](example_I13.md) |
| Asynchronous request accepted | [I14](example_I14.md) |
| Asynchronous completion observed | [I14](example_I14.md) |
| Ambiguous timeout | [I14](example_I14.md) |
| Execution visibility unavailable | No example |
| Independent assessment | [U01](example_U01.md), [U05](example_U05.md), [U06](example_U06.md), [U07](example_U07.md), [U09](example_U09.md), [U13](example_U13.md), [I01](example_I01.md), [I02](example_I02.md), [I03](example_I03.md), [I04](example_I04.md), [I05](example_I05.md), [I06](example_I06.md), [I08](example_I08.md), [I10](example_I10.md), [I11](example_I11.md), [I13](example_I13.md), [I14](example_I14.md) |
| Confirmed incident | [U05](example_U05.md), [U13](example_U13.md) |
| No row: an approval or activation wait produces no event | [U06](example_U06.md), [U07](example_U07.md), [I14](example_I14.md) |

[I02](example_I02.md) and [I08](example_I08.md) report each page of a paged read as its own operation, so each completed page is its own execution report. [U06](example_U06.md), [U07](example_U07.md), and [I14](example_I14.md) show that a wait for approval or activation is no event.
