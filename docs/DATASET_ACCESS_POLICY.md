# DATASET_ACCESS_POLICY.md — access, copying, distribution, handling

Date: 2026-10-14. Repository access, dataset licensing, and runtime
access are three separate controls; none implies the others.

## 1. Verified starting facts (not assumptions)

- Repository visibility, verified 2026-10-14 via GitHub API: PUBLIC.
  Default branch: main. Working branch for this session:
  arena/41073ddc-drobon-dataset.
- A public repository means every committed byte is already expertly
  retrievable. A proprietary license does not make public bytes
  secret; it only sets the legal terms for their use.
- No LICENSE file exists yet (see PROPRIETARY_LICENSE_DRAFT.md,
  status DRAFT). Until the owner finalizes it, all original content
  is project-internal by default, and release stays NO-GO.

## 2. Access tiers (policy)

- Repository read (public today): see the bytes; grants no use rights
  beyond what the (pending) license states.
- Contributor write: owner-designated collaborators only, least
  privilege, reviewed commits (suite green + diff audit).
- Raw dataset distribution: forbidden without a written owner
  agreement naming scope, term, and redistribution limits.
- Customer product access (future): subscription to detection
  outcomes through the app, never a raw corpus download. The dataset
  stays server-side; customers receive findings, not the catalog.

## 3. Handling rules (enforced where machine-checkable)

- No credentials, tokens, keys, or private data in the repo — ever.
  Enforced by the suite leak scan (strict repo-wide + audited
  fixtures) and GitHub push protection (already blocked one push:
  Slack-shaped fixture, resolved by rewording, no bypass used).
- No bulk export endpoints, no corpus dumps in the repo, no dataset
  bytes bundled into the Main App build. Production corpus storage
  stays separate from this working repository at release time.
- Third-party records: no download, mirror, transform, or
  redistribution without source-specific rights + owner decision +
  open gates (all absent; importers exit 1).

## 4. Honest limits of each control

- Private repository: reduces exposure but fixes neither ownership
  gaps nor license non-compliance, and does not revoke copies made
  while public.
- Proprietary license: sets legal terms; does not encrypt, hide, or
  watermark bytes, and claims no rights over third-party content.
- Encryption/access control: protects stored/transmitted copies; is
  not a substitute for legal ownership or license compliance.
- Audit logging/backups/revocation and deployment authentication are
  release-time requirements for the separate hosting workstream —
  designed here, implemented there, never in this pump.

## 5. Changes requiring owner sign-off

Visibility flip (public/private), collaborator grants, any LICENSE
install or text change, any raw-data distribution agreement, and any
release tag. Each is recorded with decider + date; unsigned intent
changes nothing.
