# DAST — Consolidated Owner-Decision Packet

**Date:** 2026-10-19
**Status:** REQUEST FOR DECISION — nothing in this packet is approved, and nothing here has been enabled.
**Related files:** `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md`, `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`,
`docs/OWNER_DECISIONS.json` (unchanged; closed key set preserved).

This packet consolidates every DAST capability that cannot be implemented without an owner decision.
It replaces the need to read three separate proposals to find out what is waiting. A proposal is not
an approval; the rules behind these items remain disabled and no placeholder rule, stub field or
simulated correlation exists in the repository.

## Why a decision is needed at all

The DAST evaluator has a closed vocabulary of seven check types. Each type receives **one header
value** (or the body) and answers a single boolean. Three classes of security question cannot be
expressed in that shape without either guessing or changing the contract:

1. questions about the **whole header list** (duplicate headers, policy intersection);
2. questions that need **more than one header** (CORS origin + credentials, report-only + enforcing);
3. questions that need a **request/response pair** (was the reflection actually reflected by this
   request? did the credentialed request succeed?).

## OD-1 — `DPK-DAST-050` (protocol-relative `Location`)

| Field | Content |
|---|---|
| Current state | Enabled, `response-header-matches` on `Location` with `^//`. |
| Defect | Fires on same-host scheme-relative redirects (`//app.example/home`), which are legitimate. Every true positive it produces is already reported by `DPK-DAST-056` (host comparison). |
| Why it cannot be fixed in place | A permanent asset id is being changed. Retirement and rewrite both alter published identity; the rule cannot express "different host" in a single-header check. |
| Decision requested | Choose one: (a) retire `DPK-DAST-050` with a documented tombstone, (b) rewrite it as `response-header-host-differs` semantics under a new id (leaves (a) unavoidable for the old id), or (c) accept the false positives and document them. |
| Compatibility | (a)/(b) change a published id; no schema change either way. |
| Tests required | A tombstone test if retired; a same-host negative and cross-host positive if rewritten. |

## OD-2 — Header-list check type (duplicate `Content-Security-Policy`)

| Field | Content |
|---|---|
| Current state | `response-header-matches` tests each header value independently (`some`). |
| Security question blocked | A response may carry CSP more than once; browsers enforce the **intersection**. A wildcard in one header is reported even when another header restricts the same directive. Pinned as limitation E3 in `scripts/test-csp-semantics.mjs`. |
| Proposed change | Add one check type, `response-header-set-matches`, whose input is the ordered value list and whose semantics are documented per rule. Minimum fields: `header`, `valuePattern`, `combine: "all" \| "any"`. |
| Compatibility | Additive; existing types unchanged; `validate-packs` gains one case in the closed vocabulary. Rules that adopt it would change behaviour, so they must be listed explicitly. |
| Tests required | Duplicate-header positive/negative, empty-list, mixed-case name, determinism row. |

## OD-3 — Multi-header correlation

| Field | Content |
|---|---|
| Current state | No check type receives two headers. |
| Questions blocked | `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`; `Content-Security-Policy-Report-Only` alongside an enforcing policy (072 currently reports the report-only header even when enforcement exists); `Cache-Control: public/immutable` on a response that also sets cookies; `X-Frame-Options` versus `frame-ancestors` disagreement. |
| Proposed change | Either (i) a `response-headers-together` check with an explicit list of predicates, or (ii) a rule-level `requires` clause that suppresses a rule when another header satisfies a condition. Option (ii) is smaller but still changes the rule schema. |
| Compatibility | Schema addition; existing rules unaffected until migrated. |
| Tests required | Each pair positive/negative, one-supplied/one-missing, repeated headers, and a regression row showing the single-header rules still behave. |

## OD-4 — Request/response pair analysis

| Field | Content |
|---|---|
| Current state | The scanner observes one response; no request is modelled. |
| Questions blocked | Reflected-input confirmation, authenticated exposure, preflight-versus-actual-request behaviour, redirect chains. |
| Proposed change | New evaluation mode with a paired fixture (`request`, `response`) and a documented evidence model. This is a product-scope decision, not only a schema decision, because it turns a passive scanner into one that issues requests. |
| Compatibility | New mode; no existing case changes. |
| Tests required | Full pair fixtures, a policy test proving no active probe escapes the fixture harness, determinism, and privacy review of stored requests. |

## OD-5 — Cookie-model check type (prefix enforcement)

| Field | Content |
|---|---|
| Current state | `cookie-missing-flag` answers one flag question about stored cookies. |
| Questions blocked | `__Host-` / `__Secure-` prefix enforcement, `Domain` scope widening, expiry sanity. |
| Proposed change | A `cookie-attributes` check type that receives the parsed model and a small predicate set (prefix, domain scope, lifetime). |
| Compatibility | Additive check type; the Set-Cookie model already exists in `scripts/lib/set-cookie.mjs`. |
| Tests required | Prefix positives/negatives, discarded-header, refused-cookie, duplicate-attribute rows. |

## What is already implemented without a decision

The four new rules in `DAST Batch 16` and both semantic models need no approval: they use existing
check types, existing assets and existing evaluation machinery. The limitations in OD-2/OD-3 are
pinned by tests rather than hidden, so the current behaviour is documented while the decision is
open.
