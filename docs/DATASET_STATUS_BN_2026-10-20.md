> **আপডেট (২০২৬-১০-২১):** এই রিপোর্টটি ২০২৬-১০-২০ তারিখের স্ন্যাপশট। এর পর মেইন অ্যাপে (`9360dd1`)
> ডেটাসেট সংযোগ বাস্তবে চালু হয়েছে — ৯টি ক্যাটাগরি `DATASET_PATH` থেকে লোড হয় (১০০ / ৯৫০ / ৯৭ / ২৬৩ /
> ১৩১০ / ৬৮ / ৬ / ৩ / ২) এবং SCA ম্যাচিং আসল অ্যাডভাইজরি ফেরত দেয় (`fast-jwt@6.2.4` → ৬টি)।
> অর্থাৎ নিচের "অ্যাপে ব্যবহার ০%" সংখ্যাটি **এখন আর সত্য নয়**। নতুন ও যাচাই করা অবস্থা:
> `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md` এবং `docs/CAPABILITY_COVERAGE_MATRIX.md`।
> লাইসেন্স, প্রোডাকশন ডেটা (০/১,০০,০০০) ও রিলিজ NO-GO — এই তিনটি অপরিবর্তিত।

# Drobon-Dataset — বর্তমান অবস্থা, কত % কাজ হয়েছে এবং কী বাকি (বাংলা রিপোর্ট)

**তারিখ:** ২০২৬-১০-২০ (Asia/Dhaka)
**যাচাই করা রিপোজিটরি:** `mdraselislam0101-design/Drobon-Dataset` (branch `arena/9155a3b1-drobon-dataset`)
**মেইন অ্যাপ (read-only):** `mdraselislam0101-design/Drobon` @ `c32c797` (সর্বশেষ push ২০২৬-১০-১৪)
**পদ্ধতি:** প্রতিটি সংখ্যা ফাইল থেকে গোনা হয়েছে (রিপোর্ট থেকে কপি নয়)। কোনো ফাইল, rule, record বা entry এই রিপোর্টের জন্য বানানো হয়নি। কোনো অ্যাপ ফাইল পড়া/বদলানো হয়নি — শুধু GitHub API দিয়ে pinned revision দেখা হয়েছে।

> **এক লাইনে:** ডেটাসেটের নিজের ইঞ্জিনিয়ারিং প্রায় শেষ (~৮০%), কিন্তু **যে দুটি জিনিস ডেটাসেটকে আসলে মূল্যবান করে — (১) আসল CVE/অ্যাডভাইজরি ডেটা এবং (২) মেইন অ্যাপে সেটির ব্যবহার — দুটিই এখনো ০%**। তাই "পেইড টুলের মতো" প্রশ্নটির সৎ উত্তর: ডকুমেন্টেড ক্যাপাবিলিটি হিসেবে ~৫৩–৬৪%, আর প্রোডাকশন রিলিজ **NO-GO**।

---

## ১. এখন বাস্তবে কী আছে (আজ ফাইল থেকে গোনা)

| অ্যাসেট | সংখ্যা | যাচাই |
|---|---|---|
| SAST rules | **৯৫০** | `packs/sast/v1/rules/*.json` |
| Secrets rules | **৯৭** | `packs/secrets/v1/rules/*.json` |
| DAST rules | **২৬৩** | `packs/dast/v1/rules/*.json` |
| **মোট pack rules** | **১,৩১০** | ৯৫০ + ৯৭ + ২৬৩ |
| Detection patterns | **১,৩১০** | ১:১ rule-এর সাথে, ০ orphan |
| Concept records | **১,৩১০** | ১:১ |
| Remediation entries | **১,৩১০** | প্রতি rule-এ অন্তত একটি, ০ orphan |
| CWE reference | **৬৮** | প্রতিটি rule-এর CWE resolve হয় |
| Evaluation cases | **১,৬১০** (১,৫৯৯ assessed, ১১ UNASSESSED) | `data/eval-cases/` |
| Provider interop vectors | **১৬** | `interop/provider-vectors.json` |
| Lessons / assessment templates / engagement aids | **৬ / ৩ / ২** | audience datasets |
| আসল অ্যাডভাইজরি ফাইল (production-eligible নয়) | **১০০ ফাইল → ৭৮ GHSA id → ৮৪ identity item** | seed, `verifiedProduction = 0` |
| প্যাক-লেভেল টেস্ট | প্রতি rule-এ ≥১ positive + ≥১ negative, সব executed | `npm test` exit 0 |

**আজকের টেস্ট রান:** `npm test` → **৬৯৫ passed, ০ failed** (determinism সহ, tree digest `15fd850e…`)।
**Evaluation:** TP ১,৩৩৬ · FN ০ · FP ১ · recall ১.০০ · precision **০.৯৯৯৩** (সিন্থেটিক কর্পাসে)।
**Independent eval coverage:** ১,৩১০/১,৩১০ rules অন্তত একটি case-এ আছে (১০০%); এর মধ্যে **১,৩০২ rules** positive detection-এ এবং **৫৯৮ rules** negative control-এ। SAST namespace-এ (gate-এর হিসাব অনুযায়ী): ৮৯০/৯৫০ positive, ২০৪ negative, ৭৯৭ case।

এই সংখ্যা মানে "ভাবলেই হয়" নয় — এগুলো **authored synthetic** কেস। আসল দুনিয়ার কোনো ভুলনারেবিলিটিতে rule কতটা কাজ করে, তার প্রমাণ এখানে নেই; সেটা প্রোডাকশন ডেটার কাজ।

---

## ২. কত % হয়েছে — এক সংখ্যা দিলে মিথ্যা হবে, তাই পাঁচটি আলাদা হিসাব

| প্রশ্ন | উত্তর | ভিত্তি |
|---|---|---|
| (ক) ডেটাসেটের নিজের কাজ (অনুমোদিত সীমার ভেতরে) | **~৮১%** | ৪২/৫২ dataset-dependent requirement-এ technical implementation সম্পূর্ণ (FULL+PARTIAL+IMPLEMENTED_NOT_VERIFIED); verified coverage ৩৮.৯৭/৫২ = **৭৪.৯%** |
| (খ) মেইন অ্যাপে এগুলোর বাস্তব ব্যবহার | **০%** | ৫টি loader-এর একটিও অ্যাপে নেই (SAST/secrets/DAST pack, remediation merge, audience) |
| (গ) আসল ভুলনারেবিলিটি ইন্টেলিজেন্স (SCA) | **০.০৮%** | ৮৪ identity item vs ১০০,০০০ লক্ষ্য; **production-verified ০** |
| (ঘ) পেইড টুলের সাথে ডকুমেন্টেড ক্যাপাবিলিটি তুলনা | **৫২.৬% GHAS · ৫৭.৫% Snyk · ৫৩.৩% Semgrep · ৬৩.৬% Burp** | ২২-মাত্রার fixed benchmark (গুণগত মান নয়, শুধু "কী আছে") |
| (ঙ) প্রোডাকশন রিলিজ | **NO-GO** | ১৭টি রিলিজ গেটের ১৩টি PASS, ৪টি owner/legal গেটে ব্লকড; `LICENSE` ফাইল নেই |

কেন (ক) আর (খ) এত আলাদা: ডেটাসেটে ১,৩১০টি rule তৈরি, টেস্টেড ও ভ্যালিডেটেড — কিন্তু অ্যাপে সেগুলো পড়ার কোনো কোড নেই। ফল: আজ অ্যাপে SAST ~৫০–৫১, secrets ~৭, DAST ৮টি hard-coded rule চলে; বাকি **১,৩১০টি rule dead weight**, কারণ অ্যাপে pack loader নেই (GAP-005…009)। এই কারণেই ব্যবহারকারী হিসেবে আপনি এখনো কোনো নতুন detection দেখছেন না।

---

## ৩. কী বাকি — তিন ভাগে ভাগ করা (এটাই মূল উত্তর)

### ৩.১ Owner/legal সিদ্ধান্ত (engineering দিয়ে সমাধান হয় না) — P0

| # | বাকি কাজ | কেন আটকে | প্রভাব |
|---|---|---|---|
| A1 | `LICENSE` নির্বাচন + প্রতি সোর্সের redistribution অনুমোদন (BLK-001/002, GAP-002) | শুধু owner/legal ঠিক করতে পারেন | লাইসেন্স ছাড়া ডেটাসেট redistribute/বিক্রি/হোস্ট করা যাবে না — পুরো প্রোডাক্ট আটকে |
| A2 | প্রোডাকশন ingestion অনুমোদন (BLK-003, GAP-001) | "production-data lock" এখনো চালু | ০/১০০,০০০ অ্যাডভাইজরি; আসল CVE মিলবে না |
| A3 | Refresh cadence + approval expiry (BLK-004, GAP-004) | owner নীতি | ডেটা পুরোনো হয়ে যাওয়ার ঝুঁকি |
| A4 | Severity/exception সিদ্ধান্ত: ১৫টি `csharp-flag` rule HIGH রাখা হবে কি না, `DPK-DAST-050` (OD-1), legacy duplicate pair (D-13), userinfo ৮-char floor ratification (GAP-026), ১১টি UNASSESSED case-এর scoring policy (GAP-038) | owner decision | মান/নীতিগত, টেকনিক্যাল নয় |

### ৩.২ মেইন অ্যাপ রিপোতে কাজ (এখানেই সবচেয়ে বড় দৃশ্যমান লাফ) — P1

| # | বাকি কাজ | আজকের অবস্থা | লাফ |
|---|---|---|---|
| B1 | SAST pack loader (GAP-005) | loader নেই | ৫০ → **~১,০০০** rule |
| B2 | Secrets pack loader (GAP-006) | loader নেই | ৬ → **~১০৩** |
| B3 | DAST pack loader (GAP-007) | loader নেই | ৮ → **~২৭১** |
| B4 | Remediation merge-loader (GAP-008) | অ্যাপ নিজের guidance দেখায় | **১,৩১০** entry live |
| B5 | Audience loaders: lessons/templates/engagements (GAP-009) | অ্যাপের নিজের ৪-লেসন catalog | ৬+৩+২ asset live |
| B6 | SCA provider বাস্তবায়ন + contract (provider seam `assess(coordinates)`) | `providerId: 'none'`, `NO_DATA_LOADED` → সব ফলাফল `NOT_ASSESSED` | আসল dependency finding |
| B7 | CVSS/OWASP/prioritization field + exploitability engine (GAP-010/011) | অ্যাপে score field-ই নেই | পেইড টুলের মতো report |
| B8 | Ecosystem বাড়ানো (npm/pypi-এর বাইরে), ৫টি `gha` rule-এর catalog subfamily + ~১৫০ subformat tag (GAP-014/023) | অ্যাপ contract-এ আটকে | reachability বৃদ্ধি |
| B9 | Git/CI integration ও account lifecycle (GAP-017/018) | অ্যাপে অনুপস্থিত | পেইড টুলের CI/PR gate সমতুল্য |

### ৩.৩ ডেটাসেটের অবশিষ্ট ইঞ্জিনিয়ারিং (owner গেট ছাড়াই করা যায়, তবে evidence-gated) — P1/P2

| # | বাকি কাজ | পরিমাণ | মন্তব্য |
|---|---|---|---|
| C1 | DAST ৫০০ লক্ষ্য পূরণ | ২৬৩ → ৫০০ (**+২৩৭**, ৫২.৬% সম্পন্ন) | ৭টি closed check type-এর ভেতরেই করতে হবে; padding নিষিদ্ধ |
| C2 | SAST ১,০০০ পরিকল্পনা লক্ষ্য | ৯৫০ → ১,০০০ (**+৫০**, ৯৫% সম্পন্ন) | প্রতিটি rule-এ আসল evidence লাগবে |
| C3 | Evaluation depth | ৬০টি SAST rule-এর positive case নেই, ৭৪৬টির negative control নেই (gate-এর হিসাব) | 별도 SAST eval টাস্ক, DAST ব্যাচ নয় |
| C4 | Cross-rule overlap পরিষ্কার | ৪৪টি positive line অন্য rule-ও মেলে; ১৫টি negative-test দ্বন্দ্ব (GAP-033) | ডুপ্লিকেট finding কমাবে |
| C5 | Legacy duplicate pair + token-prefix residual | D-13 inactive; ৯১+১১ rule-এ prefix-boundary residual (GAP-034) | owner decision + triage |
| C6 | Generator leak-guard-এর PEM regex সংকীর্ণ (DSA/PGP/ENCRYPTED label বাদ) | এক লাইনের ফিক্স, কিন্তু reviewed exception path দরকার | নিরাপত্তা গার্ডের ডিজাইন সিদ্ধান্ত |
| C7 | ডক-ড্রিফট | `CAPABILITY_COVERAGE_MATRIX`-এ পুরোনো "১,১৬৩" সংখ্যা ছিল → এই রিপোর্টের সাথে **১,৩১০**-এ ঠিক করা হয়েছে | বাকি হিস্টোরিক্যাল রিপোর্ট ইচ্ছাকৃতভাবে অপরিবর্তিত |
| C8 | অ্যাডভাইজরি breadth | ৮৪ → ১০০,০০০ | A2 ছাড়া সম্ভব নয় (importer তৈরি ও টেস্টেড, live dry-run ব্লকড) |

---

## ৪. "পেইড টুলের মতো" হতে ঠিক কী কী লাগবে

পেইড টুলের সাথে তুলনা করলে গ্যাপ দুই ধরনের — কিছু ঘোষণা করা যায়, কিছু **কখনোই** পূরণ হবে না (ডিজাইনগত সীমা)।

**পূরণযোগ্য (কিন্তু এখনো নেই):**
1. আসল অ্যাডভাইজরি ডেটাবেস (GHAS-এর GitHub Advisory DB / Snyk vuln DB সমতুল্য) — ১০০k+ record, প্রতিদিন/সাপ্তাহিক refresh।
2. ম্যানেজড feed operations + লাইসেন্স/redistribution অধিকার (Snyk/GHAS-এ vendored, Drobon-এ আলাদা রিপো)।
3. SBOM/PR-gate/dependency-review পলিসি ইঞ্জিন, IDE ইন্টিগ্রেশন, license-compliance report।
4. CVSS v3.1/v4 vector, OWASP mapping, prioritization (KEV/EPSS) — অ্যাপে field যোগ করতে হবে (contract change)।
5. SCA reachability (GHAS/Snyk-এর উন্নত ফিচার) — নতুন engine, সবচেয়ে ব্যয়বহুল কাজ।
6. Container/IaC runtime scanner (আজকে শুধু rule হিসেবে data আছে, engine নেই)।

**ডিজাইনগতভাবে বন্ধ (ইচ্ছাকৃত, এবং এটাই Drobon-এর অবস্থান):**
- DAST active scanning / crawl / fuzzing (Burp-এর মূল শক্তি) — Drobon passive-only।
- Secret liveness/active validation (GHAS/Snyk যাচাই করে) — Drobon কখনো live credential স্পর্শ করে না।
- Exploit payload / PoC library / attack chaining — সম্পূর্ণ নিষিদ্ধ।
- Dependency license inference — অ্যাপের নীতি অনুযায়ী বাদ।

অর্থাৎ **১০০% পেইড-টুল প্যারিটি লক্ষ্যই নয়**। বাস্তবসম্মত লক্ষ্য: passive + evidence-first ভিত্তিতে ~৭৫–৮৫% ডকুমেন্টেড ক্যাপাবিলিটি, যা Drobon-এর honesty নীতির সাথে সঙ্গতিপূর্ণ।

---

## ৫. সাজানো রোডম্যাপ (ক্রমটা গুরুত্বপূর্ণ — উল্টো করলে কাজ বৃথা)

| ধাপ | কাজ | কে | মোটামুটি সময়* | তারপর কী খুলবে |
|---|---|---|---|---|
| ১ | `LICENSE` + প্রতি সোর্সের terms সিদ্ধান্ত | owner/legal | দিন | redistribution ও publication সম্ভব |
| ২ | প্রোডাকশন ingestion অনুমোদন → importer dry-run → ১০k, তারপর ১০০k ingest | owner + engineering | ১–২ সপ্তাহ (importer ও ১০k rehearsal আগেই টেস্টেড) | আসল dependency vulnerability finding |
| ৩ | অ্যাপে ৫টি loader (B1–B5) | মেইন অ্যাপ রিপো | ১–২ সপ্তাহ | ১,৩১০ rule + ১,৩১০ remediation live — সবচেয়ে বড় দৃশ্যমান উন্নতি |
| ৪ | DAST +২৩৭, SAST +৫০, evaluation depth, overlap পরিষ্কার | ডেটাসেট | ৩–৬ সপ্তাহ, evidence-gated | rule সংখ্যা ও নির্ভরযোগ্যতা |
| ৫ | CVSS/OWASP/prio + exploitability + reachability | অ্যাপ + owner contract | ৪–৮ সপ্তাহ | পেইড টুলের তুলনায় ~৭৫–৮৫% ডকুমেন্টেড প্যারিটি |

\* সময় = মাত্রা বোঝানোর জন্য অনুমান, কোনো প্রতিশ্রুতি নয়। ধাপ ১–২ ছাড়া ধাপ ৩-এর কোনো ব্যবসায়িক মূল্য নেই, আর ধাপ ৩ ছাড়া ধাপ ৪ শুধু ফাইল বাড়ায়।

---

## ৬. সততা: এই রিপোর্ট কী প্রমাণ করে না

1. **অ্যাপ টেস্ট রান করা হয়নি** — এই স্যান্ডবক্সে অ্যাপ checkout নেই। অ্যাপের তথ্য pinned revision `c32c797` + GitHub API থেকে; "loader নেই" একটি absence দাবি, runtime পর্যবেক্ষণ নয়।
2. **evaluation সংখ্যা synthetic** — recall ১.০০ / precision ০.৯৯৯৩ authored corpus-এর উপর, বাস্তব জগতের detection ক্ষমতার প্রমাণ নয়।
3. **প্রোডাকশন অ্যাডভাইজরি ০** — importer তৈরি, মক-টেস্টেড ও ১০k rehearsal পাস, কিন্তু live dry-run হয়নি (lock)।
4. **কোনো % averaging করা হয়নি** — ভিন্ন denominator মিশিয়ে একক "overall score" বানানো এই রিপোর নিজের methodology নিষিদ্ধ করে; তাই উপরের পাঁচটি আলাদা হিসাব।
5. **EVAL-SAST-008 এখনো FAIL** — একটি আসল false positive (DPK-SAST-283), ইচ্ছাকৃতভাবে দৃশ্যমান রাখা হয়েছে; ১১টি UNASSESSED case স্কোরের বাইরে।

---

## ৭. নিজে যাচাই করার কমান্ড

```bash
npm test                     # সব gate: 695 passed, 0 failed
node scripts/inventory.mjs --check
node scripts/eval-coverage-report.mjs        # 1310/1310 rules
node scripts/run-eval.mjs                    # TP 1336 / FN 0 / FP 1
node scripts/validate-packs.mjs packs
node scripts/validate-capability-coverage.mjs
node scripts/test-doc-drift.mjs
```

সংশ্লিষ্ট মেশিন-রিডেবল প্রমাণ: `docs/CURRENT_INVENTORY.json`, `docs/CAPABILITY_COVERAGE_MATRIX.json`, `docs/RELEASE_READINESS_MATRIX.json`, `docs/BLOCKER_REGISTER.json`, `DROBON_REMAINING_WORK.csv`, `DROBON_PAID_TOOL_BENCHMARK.csv`।
