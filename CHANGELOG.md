# Changelog

Each release's section is copied into its GitHub release notes. If you compare a
report against one made with an earlier version, read "Verdicts that may change"
first: a different verdict can come from the tool, not from your tenant.

## v0.9.2 (2026-11-11) · knowledge base 2026.11.11b

### Verdicts that may change

- **New Tier-0 permissions and roles.** 31 permissions and 21 roles were added
  after a full re-sync with azure-tiering. Apps that showed "no known path" because
  a permission was missing from the knowledge base can now show a path. The ones
  most likely to matter: `UserAuthMethod-TAP.ReadWrite.All`,
  `UserAuthMethod-Phone.ReadWrite.All` and `DelegatedAdminRelationship.ReadWrite.All`
  (direct), and Conditional Access Administrator and Tenant Governance Administrator
  (direct).
- **Lockout is now its own verdict.** `Policy.ReadWrite.ConditionalAccess`,
  `User.DeleteRestore.All`, `User.EnableDisableAccount.All`,
  `SignInIdentifier.ReadWrite.All`, Conditional Access Administrator and Security
  Administrator can lock every account out of the tenant (a ransom vector) but don't
  confer Global Admin's privileges. They show as "Lockout" and are counted apart from
  "can reach Global Admin". An app that can backdoor a lockout-only app inherits the
  lockout, not Global Admin.
- **Self-escalating permissions are direct in every mode.**
  `AppRoleAssignment.ReadWrite.All`, `Policy.ReadWrite.PermissionGrant` and
  `PrivilegedAssignmentSchedule.ReadWrite.EntraAppRole` can grant themselves a
  Global-Admin-capable permission with nothing else in the tenant. The single-app
  check previously said "conditional" for these.
- **Lowered to conditional, matching azure-tiering:** Application Administrator,
  Cloud Application Administrator, Hybrid Identity Administrator, Intune
  Administrator, `UserAuthMethod-HardwareOATH.ReadWrite.All`,
  `UserAuthMethod-QR.ReadWrite.All`. Whole-tenant mode still shows Global Admin when
  the export proves the chain (for example, an Application Administrator and a
  privileged app to backdoor).
- **Directory Synchronization Accounts no longer counts as able to plant app
  credentials**, so it no longer produces "confirmed via chain" paths.
- **Partner Tier1 Support and Hybrid Identity Administrator now count as able to
  plant app credentials**, matching their published attack paths.
- **Corrected explanations:** Groups, User, Helpdesk, Exchange and SharePoint
  Administrator. A password reset alone doesn't get past MFA, and Groups
  Administrator can't touch role-assignable groups.

### Safety

- Names and IDs from an export are escaped once, everywhere they're rendered. A
  crafted export could previously run script through an app ID or tenant ID.
- The page's Content Security Policy allows only the page's own scripts (by hash),
  so injected markup can't run even if escaping fails. Exported reports allow no
  script at all; print them with Ctrl+P (⌘P).
- An export without `tenantId` now says the cross-tenant credential checks did not
  run, instead of reporting 0.

### Releases and verification

- Releases are built by CI and carry `SHA256SUMS` plus a signed build-provenance
  attestation: `gh attestation verify blast-radius-local.html --repo pslorenz/blast-radius`.
- CI runs engine, hostile-input and headless-browser tests on every change.
- The knowledge base is checked against azure-tiering snapshots
  (`scripts/sync_azure_tiering.py`).

### Fixes

- Unescaped and double-escaped text in results and reports (for example a
  credential named `Bob's key` showed as `Bob&#39;s key`).
- The partner fixture test depended on the wall clock and started failing on
  2026-11-01.

## v0.9.1 · knowledge base 2026.10.22b

- PIM-eligible role-assignable groups modeled as a gated path.
- App registration owners exported; service-principal owners treated as backdoor
  edges.
- Windows PowerShell 5.1 credential dates (`/Date(ms)/`) parsed; they previously
  disabled every time-based flag.
- Delegated grants (`oauth2PermissionGrants`) read from the export.
- Credentials on Microsoft first-party service principals get their own flag.
- Unverified incident details removed from knowledge-base entries.

## v0.9.0 · knowledge base 2026.10.22

- Cross-tenant credential detection (the ConnectWise/SkyKick persistence pattern),
  with a reviewed allowlist.
- PIM-eligible Global Admin as a distinct, gated verdict.
- Ownership paths (human and service-principal owners).
- Credential source (app registration or service principal) and a "changed since"
  filter.
