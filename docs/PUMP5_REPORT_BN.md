# Pump 5 — যাচাই ও নথিভুক্তকরণ প্রতিবেদন (বাংলা)

তারিখ: ২০২৬-১০-১৫ · শাখা: `arena/7224fbda-drobon-dataset` · Main App (শুধু পড়া): `c32c797`

**সামগ্রিক অবস্থা: PARTIAL।** এই পাম্পে কোনো gate বন্ধ হয়নি। কোনো commit, push, PR, merge বা release করা হয়নি। সব খোলা সিদ্ধান্ত `docs/OWNER_ACTION_REQUIRED.md` §6-এ আছে।

> **সংশোধন (Pump 7, ২০২৬-১০-১৫):** এই প্রতিবেদনের নিচের কিছু অবস্থা এখন পুরোনো। PEP 440 D1–D4 Pump 6-এ ঠিক হয়েছে এবং D5 Pump 7-এ ঠিক হয়েছে (`docs/FORMAT.md`)। Secrets veto-র rule-স্তরের regression Pump 6-এ যোগ হয়েছে এবং Pump 7-এ নিশ্চিত হয়েছে (`scripts/test-packs.mjs`)। Generator-এর denylist এখন case-insensitive (Pump 7)। নিচের মূল বিবরণ ইতিহাসের জন্য অপরিবর্তিত রাখা হয়েছে। বর্তমান খোলা সিদ্ধান্ত `docs/OWNER_ACTION_REQUIRED.md` §7-এ আছে।

## ১. একনজরে ফলাফল

| কাজ | অবস্থা | প্রমাণ |
|---|---|---|
| Reachability (কারণ-কোড সহ) এবং app catalog-এর লাইভ যাচাই | DONE | 53/53 id মিলেছে; `docs/PACKS.md` Pump 5 |
| চার UserType-এর audit | DONE (সামগ্রিক PARTIAL) | সব type-এর content আছে; কোনো type-এর live app consumer নেই। `docs/AUDIENCES.md` §6 |
| Secrets: Pump 4-এর ভুল দাবি সংশোধন | DONE | DPK-SEC-003 `${` দাবি ভুল ছিল; `docs/PACKS.md` |
| Secrets: false positive ও gap নথিভুক্ত | DONE | ৭টি gap, ৩টি false positive, ২টি covered (বিস্তারিত নিচে) |
| Secrets: denylist veto-র পরীক্ষা | **BLOCKED / OPEN GAP** | veto mutant ৩টির মধ্যে ২টি ধরা পড়েনি; সমাধানে owner-এর সিদ্ধান্ত লাগবে |
| SCA: PEP 440 ও npm-এর deviation নথিভুক্ত | DONE (নথি) | `docs/FORMAT.md` |
| SCA: engine পরিবর্তন | **BLOCKED** | owner approval ছাড়া engine বদলানো হয়নি |
| CWE-470 নাম যাচাই (MITRE) | DONE | MITRE 4.20-এ নাম হুবহু মিলেছে |
| CWE-470 group ও CROSS_CWE বিশ্লেষণ | DONE (সীমিত) | MITRE-এর relationships অংশ পড়া হয়নি → PARTIAL |
| Records, retired ID, generator invariant | DONE | ৪০ legacy pattern = ৪০ record-less; retired ২১; generator 0/3584 বদলায় |
| language id সংখ্যা (১০৯ নয়, ১০৮) | DONE | base commit-এর সাথে তুলনা করে derivation লেখা হয়েছে |
| চূড়ান্ত verification (`npm test`) | DONE | exit 0, ৬টি suite PASS |
| Mutation test | PARTIAL | DAST ৪টি mutant (১টি gap ঠিক করা হয়েছে); secrets veto-তে ২টি বাকি |

## ২. প্রধান সংখ্যা

- SAST নিয়ম ৭৪৩টি: FULL ৫০০; PARTIAL ২৫; NONE ২১৭; universal ১ (DPK-SAST-004)। যোগফল ৭৪৩।
- NONE ২১৭ = NO_APP_FAMILY ১২৭ + CAT_UNSUPPORTED ৫৫ + ALIAS_OR_BROADEN ২২ + UNIVERSAL_TAG ১০ + CAT_SYNTAX_ONLY ৩।
- Language id: **১০৮** (১০৯ নয়)। base commit-এ rule-এর language ১০৮ ছিল (`hcl` সহ); pattern target ১০৯ ছিল, অতিরিক্ত একটি `http` (DAST target)। বর্তমানে: ১০৮ − `hcl` (terraform-এ মেশানো) + `bash` (২৫টি shell rule)।
- Catalog-এর সাথে মিল ৪১; catalog-এ নেই ৬৭।
- Pattern ৮৮৮, record ৮৪৮, retired reservation ২১ (সব নথিভুক্ত, কোনো file নেই)।
- Test: tests ৫৪৫ (আগে ৫১৬), pack-tests ৩৬৫০ (আগে ৩৬৪৮), asset-tests ৬৯৯৪ (অপরিবর্তিত), audience ২৭০৫, consistency ১৮২, rehearsal ৭৮।

## ৩. পাওয়া গুরুত্বপূর্ণ সমস্যা

### (ক) PEP 440 — তিনটি MUST-স্তরের deviation (KNOWN DEFECT)

PEP 440-এর "Exclusive ordered comparison" অংশে এগুলো বাধ্যতামূলক (MUST):

- **D1** — `>V` কোনো post-release অনুমতি দেবে না (V নিজে post না হলে)। Engine `pypi 1.7.0.post1` কে `>1.7`-এর সাথে মেলায় (true) — spec-এর নিজের উদাহরণের বিপরীত।
- **D2** — `<V` কোনো pre-release অনুমতি দেবে না। Engine `2.0.0a1` কে `<2.0`-এর সাথে মেলায় (true)। Pump 4-এ এটিকে "policy" ধরা হয়েছিল; এখন MUST হিসেবে সংশোধন।
- **D3** — bound-এ local version অনুমোদিত নয়। Engine `<1.7+local` গ্রহণ করে।

এগুলো pin করা হয়েছে (`KNOWN DEFECT`), যাতে যেকোনো পরিবর্তন test-এ ধরা পড়ে। engine বদলানো হয়নি — এটি SCA contract, Main App-এর সাথে মিল রাখতে হবে। **সিদ্ধান্ত owner-এর।**

### (খ) npm prerelease ও PyPI pre-release default — POLICY-PENDING

- npm README "Prerelease Tags": prerelease শুধু তখনই মেলে যখন একই `major.minor.patch`-এর prerelease comparator থাকে। Engine এটি মানে না। এটি npm-এর নীতি, semver.org-এর MUST নয়, তাই POLICY।
- PEP 440 "Handling of pre-releases": default-এ pre-release বাদ থাকে — এটি **SHOULD**, অর্থাৎ নীতি।

### (গ) Secrets — Pump 4-এর ভুল সংশোধন

Pump 4 বলেছিল DPK-SEC-003 `${` দিয়ে placeholder veto করে। **এটি ভুল।** ওই rule-এর character class `$`, `{`, `<`, `>` মেলায় না, তাই quoted `${...}` বা `<...>` placeholder-এ সে কখনো match করে না। `${` entry শুধু সেই লাইনগুলোকে বাদ দেয় যেখানে অন্য কোথাও `${` আছে — এটি over-veto।

### (ঘ) Secrets — false positive ও gap

- False positive (veto হয়নি): `password = "<password>"`, `password = "${DB_PASSWORD}"`, `your-password-here` — DPK-SEC-007-এর pattern `<`, `$`, `{` মেলায়। এটি pattern-এর সীমা, denylist-এর ভুল নয়। `${`/`<` যোগ করলে আসল মান-ও veto হতে পারে — owner সিদ্ধান্ত।
- Gap (কোনো rule মেলে না): JDBC `password=`; JDBC `;password=`; ADO `Password=`; unquoted `DB_PASSWORD=`; `export DB_PASSWORD=`; unquoted YAML `password:`; symbol-সহ URI password।
- Covered: URI alphanumeric password, empty-user redis URI, `mongodb+srv` (DPK-SEC-063); quoted `password = "…"` (DPK-SEC-007)।
- Veto-তে বাদ: `changeme`, `EXAMPLE`।

### (ঙ) Secrets veto — পরীক্ষা নেই (OPEN GAP, BLOCKED)

- Denylist veto-র কোনো regression test নেই। ৮৮টি denylist rule-এর কোনো negative test-এর ফলাফল veto-র উপর নির্ভর করে না।
- দুটি veto test যোগ করে দেখা গেছে সেগুলো ৩টি mutant ধরতে পারত। কিন্তু generator rule-এর test-কে pattern-এ mirror করে, এবং `test-assets` সেগুলো pattern-এর regex দিয়ে যাচাই করে (denylist ছাড়া)। ফলে `got true, want false` ব্যর্থতা আসে। তাই test দুটি ফেরত নেওয়া হয়েছে; rule ও pattern মূল অবস্থায় (byte-identical)।
- সমাধানের বিকল্প (owner-এর সিদ্ধান্ত): (ক) `test-assets` ruleRef example-এ rule-এর denylist প্রয়োগ করবে; অথবা (খ) generator veto-only negative mirror করবে না।

## ৪. DAST mutation test

| Mutant | ফলাফল |
|---|---|
| redirect host তুলনা বন্ধ | ধরা পড়েছে (১০ FAIL) |
| status boundary `>399` → `>=399` | ধরা পড়েছে (২ FAIL) |
| comma split (শুধু `;`) | ধরা পড়েছে (৪ FAIL) |
| uppercase `HTTP` URL-এ host check বাদ | প্রথমে **ধরা পড়েনি** → ২টি row যোগ করা হয়েছে → এখন ধরা পড়ে |

## ৫. CWE-470 ও CROSS_CWE

- CWE-470 নাম MITRE থেকে হুবহু নিশ্চিত: "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')"।
- DPK-SAST-747..753 (৭টি rule): প্রতিটির আলাদা pattern (DPK-PAT-0898..0904); কোনো group বা CROSS_CWE-তে নেই; sink-এর নাম অন্য কোনো rule-এ নেই। পরিবর্তন দরকার নেই।
- CROSS_CWE পুনরুৎপাদন: ৩১ group / ৮৬ rule; CROSS_CWE ১৩ / ২৮; TRUE_DUPLICATE ০। সবই অপরিবর্তিত, owner review খোলা।
- **সীমাবদ্ধতা (PARTIAL):** MITRE-এর relationships অংশ পড়া হয়নি, তাই CWE hierarchy-তে mapping যাচাই হয়নি।

## ৬. Generator ও record invariant

- Generator পুনরায় চালালে (disposable copy) ৩৫৮৪টি file-এর একটিও বদলায় না।
- Quarantine: secrets class-এ অবৈধ `confidence` দিলে generator exit 1 করে, "৪৩টি cell quarantined" দেখায়, এবং কোনো file লেখে না।
- ৪০টি record-less pattern ঠিক সেই ৪০টি legacy entry, যেগুলো manifest-এ আছে।

## ৭. সীমাবদ্ধতা ও সতর্কতা

- Mutation ও probe-এর কাজ `/tmp`-এ disposable copy-তে হয়েছে; সেগুলো repo-তে সংরক্ষিত নয়।
- Main App শুধু পড়া হয়েছে; এর কোনো file বদলানো হয়নি।
- কাজের মাঝে একটি scripted edit `scripts/test-packs.mjs`-কে ভেঙেছিল; সেটি সংশোধন করে পুনরায় যাচাই করা হয়েছে।
- Engine (`satisfiesRange`) ও কোনো rule-এর logic বদলানো হয়নি। Schema পরিবর্তন হয়নি।
- Pump 4-এর uncommitted পরিবর্তন (যেমন `shell → bash` generator mapping) এখনও working tree-তে আছে; base commit-এ নেই।

## ৮. Owner-এর সিদ্ধান্ত লাগবে (সংক্ষেপে)

১. PEP 440 D1–D3 ঠিক করার অনুমোদন, না বর্তমান আচরণ provider contract হিসেবে নথিভুক্ত।
২. npm prerelease নীতি।
৩. PyPI pre-release default।
৪. Secrets veto-র পরীক্ষা-পদ্ধতি (ক/খ)।
৫. DPK-SEC-007-এর denylist-এ `${`/`<`।
৬. নতুন secrets rule (নতুন file)।
৭. Hyphenated language id-র schema।
৮. DPK-SAST-018-এর `python` tag।
৯. ২৫টি `shell` rule-এর `bash` tag নিশ্চিত করা।
১০. CROSS_CWE ১৩টি group।
১১. ৪০টি legacy pattern-এর record।

বিস্তারিত: `docs/PACKS.md` (Pump 5), `docs/FORMAT.md`, `docs/AUDIENCES.md` §6, `docs/OWNER_ACTION_REQUIRED.md` §6।
