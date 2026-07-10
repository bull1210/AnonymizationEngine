# Anonymization Engine — A Plain-Language Guide

*For readers with no background in data privacy, machine learning, or software infrastructure. Every technical term is explained the first time it appears.*

---

## 1. What is this software, in one paragraph?

Imagine a company with thousands of documents — contracts, medical records, emails, invoices. These documents contain private details: people's names, phone numbers, credit card numbers, home addresses. The company wants to use these documents for useful things (like teaching an AI assistant, or building a smart search tool), but it must not expose anyone's private information. This software is the machine that takes each document and **carefully replaces every piece of private information with a safe substitute**, producing a clean copy that can be used without risking anyone's privacy.

Think of it like a skilled editor with a black marker — except instead of just blacking things out, it can also swap real names for consistent fake names, so the documents still make sense afterwards.

---

## 2. The big picture: where this fits

This engine is one part of a larger system that runs entirely inside the company's own computers (nothing is ever sent over the internet — this is what "on-premise" and "fully offline" mean). The full assembly line looks like this:

```
┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐    ┌──────────────┐
│  Documents    │ →  │  Detection        │ →  │  THIS ENGINE         │ →  │  Clean       │
│  (originals)  │    │  (finds private   │    │  (replaces private   │    │  documents   │
│               │    │   information)    │    │   information)       │    │  (safe copy) │
└──────────────┘    └──────────────────┘    └─────────────────────┘    └──────────────┘
```

**Important division of labor:** a separate system (the "detection pipeline") has already read every document and marked exactly where the private information is — like a proofreader who highlighted every sensitive word before handing the pages to us. This engine does **not** search for private information itself. It only performs the replacements at the exact positions it was told about. This separation matters: if the engine second-guessed the highlighter, the two could disagree and mistakes would slip through.

---

## 3. Words you will see, translated

| Term | What it actually means |
|---|---|
| **Entity** | Any piece of private or sensitive information found in text — a person's name, a phone number, a diagnosis, an address. |
| **Entity type** | The category of that information: PERSON, PHONE, ADDRESS, CREDIT_CARD, MEDICATION, and so on. |
| **Finding** | One highlighted spot in a document: "characters 120 to 135 contain a PERSON name, and we're 97% sure." |
| **Span / offsets** | The exact start and end positions (counted in characters) of a finding within the document's text. |
| **Confidence** | How sure the detector is, from 0 to 1. A confidence of 0.97 means "almost certainly private info"; 0.3 means "probably not." |
| **Masking** | Replacing private information so it can never be recovered. Like shredding — one-way, permanent. |
| **Pseudonymization** | Replacing private information with a consistent fake stand-in (a "pseudonym"). "Priya Sharma" might become "User_91a4b" everywhere she appears. |
| **Anonymization** | The umbrella term for both of the above — making data safe by removing the link to real people. |
| **Downstream target** | Where the cleaned documents are going next. The destination determines *how* we clean them (see section 4). |
| **LLM / AI training** | Teaching a large language model (an AI like a chatbot) by feeding it huge amounts of text. The AI can accidentally memorize text it was trained on — which is why training data must be scrubbed extra thoroughly. |
| **RAG (Retrieval-Augmented Generation)** | A technique where an AI answers questions by first *searching* a library of documents and reading the relevant ones. The documents stay in a searchable index; the AI just consults them. |
| **Kafka** | A message conveyor belt between systems. The detector drops "this file is ready" messages onto the belt; our workers pick them up. |
| **Postgres** | A database — an organized, reliable filing cabinet for structured records (receipts, audit logs, lookup tables). |
| **Worker** | One copy of the engine's processing program. Many workers run at once to get through documents faster, like multiple cashiers at a supermarket. |
| **Tenant** | One customer or organization using the platform. Each tenant's data and secret keys are kept strictly separate. |
| **HIPAA Safe Harbor** | A US healthcare privacy rule listing 18 kinds of identifying information (names, dates, ZIP codes…) that must be removed or generalized for health data to count as de-identified. |
| **KMS / Vault (HashiCorp)** | A secure safe for storing secret keys, kept separate from the software's normal settings so keys can't leak. |
| **HMAC** | A mathematical recipe that turns any text plus a secret key into a fixed scrambled code. Same input + same key = same code, every time. Without the key, you can't reverse it or reproduce it. |
| **FPE (Format-Preserving Encryption)** | Encryption that keeps the *shape* of the data: a 16-digit card number becomes a different 16-digit number, not gibberish. |
| **Salt** | A secret random value mixed into the scrambling recipe so that outsiders can't guess-and-check their way back to the original. |
| **Idempotent** | Safe to run twice. If the same document is processed again by accident, the result is identical and nothing breaks. |
| **Dry run** | A rehearsal: the engine shows what it *would* change without actually saving the cleaned files. |

---

## 4. The two modes — and why they must be different

The engine has two cleaning styles. The choice depends on where the documents are going.

### Mode 1: Training mode — the shredder

**Used when:** the documents will be fed into an AI model for training.

**The danger:** AI models can memorize their training text word-for-word. If a real name or card number goes in, someone might later coax the AI into reciting it. So the replacement must be **irreversible** — no key, no lookup table, no way back. Ever.

**What it does:**

- **Names, organizations, locations** become numbered placeholders like `<NAME_1>`, `<ORG_2>`. The numbering restarts in every document. Inside one document, the same person always gets the same number — so a story about "`<NAME_1>` called `<NAME_2>`, and later `<NAME_1>` apologized" still reads sensibly. But `<NAME_1>` in document A and `<NAME_1>` in document B are completely unrelated people. This is deliberate: nothing may link identities *across* documents.
- **Things without personal identity** (a medication name, a diagnosis) become plain type labels like `<MEDICATION>` — no number needed, since "which specific one" is the sensitive part.
- **Dates** are blurred: either reduced to just the year, or shifted by a random number of days (up to a year). The shift is the same for all dates *within* one document, so "admitted, then discharged 3 days later" keeps its 3-day gap — useful for analysis — while the true dates are hidden.
- **ZIP/postal codes** keep only their first 3 digits (a broad region, not a street). **Ages over 89** become "90+" — because very old ages are rare enough to identify someone.

**The golden rule of this mode:** the engine keeps *no record* that could ever recover the originals. Even the audit receipt (section 7) records only *where* replacements happened and *what type* they were — never the original words.

### Mode 2: RAG mode — the consistent alias

**Used when:** the documents will live in a searchable library that an AI consults to answer questions.

**The different need:** here, the documents aren't absorbed into an AI's memory — they sit in an index and get retrieved. For search to work well, relationships must survive: if "Priya Sharma" appears in 40 documents, all 40 must refer to her by the *same* fake name, or a question like "what contracts is this person involved in?" falls apart.

**What it does:**

- Every entity gets a stable pseudonym like `User_91a4b` or `Org_7c3f2`, computed by the HMAC recipe: the entity's name + the tenant's secret key → always the same code. Beautifully, this needs **no shared list**: a hundred workers processing different files in parallel all compute the identical pseudonym independently, because they all use the same recipe and key.
- **Before scrambling, names are tidied up** ("canonicalization") so trivially different spellings link correctly: "Dr. Priya Sharma", "SHARMA, Priya", and "priya sharma" all reduce to the same standard form, and therefore get the same pseudonym. But the engine is deliberately cautious: "P. Sharma" is *not* automatically assumed to be the same person — guessing wrongly would fabricate a connection between two real people, which is worse than missing a connection.
- **Structured numbers** (credit cards, phone numbers, national IDs) are encrypted in a format-preserving way: a valid-looking fake card number replaces the real one, same length, same dash positions, and even a corrected final "check digit" so that software that validates card numbers still accepts it.
- **Optionally reversible:** if a customer explicitly turns this on, an encrypted lookup ("re-identification vault") stores the pseudonym-to-original mapping behind a locked, logged, emergency-access door — for cases like a legal request to find who "User_91a4b" really is. By default this vault does not exist at all.

### Why the two modes must never share machinery

Training mode's entire security guarantee is "there is no way back." RAG mode's entire usefulness is "the same entity always maps to the same code." If training data used RAG-style stable pseudonyms, the codes would link a person's information across every document in the training set — and if the secret key ever leaked, everything could be unscrambled. The two guarantees are opposites; mixing them destroys both. That's why the design forbids any shared pseudonym mechanism between modes.

---

## 5. How the engine avoids corrupting documents

A subtle but critical mechanic: replacements change text length. `Priya Sharma` (12 characters) becoming `<NAME_1>` (8 characters) shifts every character after it. If the engine replaced things left-to-right, every later position marker would be wrong.

**The trick: work backwards.** The engine sorts all findings and replaces from the *end of the document toward the beginning*. Changing text near the end never moves text near the start, so every position marker stays valid until it's used. Simple, and it eliminates a whole class of corruption bugs.

The engine also resolves messy overlaps first: if an ADDRESS contains a PERSON's name inside it ("c/o Priya Sharma, 42 Lake Road…"), the engine masks the whole outer address as one unit rather than leaving fragments.

---

## 6. The rulebook (policy)

Which replacement style applies to which entity type is not hard-coded — it lives in a single configuration file (`masking_policy.yaml`) that administrators can review and customize per customer or per job. Two safety defaults are built in:

1. **When unsure, mask.** Findings at or above a confidence threshold (default 50%) get masked. Masking something harmless by mistake is annoying; leaving something private exposed is a breach. The engine always errs toward masking.
2. **Unknown types are removed entirely.** If the detector reports a category the rulebook doesn't recognize, the engine doesn't guess — it deletes that span. This is called "failing closed": when in doubt, the safe action, not the convenient one.

---

## 7. Trust, but verify

Three mechanisms make sure the engine actually did its job:

**The receipt.** Every processed file produces a `TransformReceipt` — an itemized audit record of every replacement: where it was, what type, which rule was applied. In training mode the receipt deliberately omits the original text (otherwise the receipt itself would be a privacy leak).

**The verification pass.** After cleaning, the cleaned text is sent *back through the detector* — the same system that found the private information in the first place. If the detector still finds anything sensitive in the supposedly-clean output, the document is stamped `LEAK_DETECTED`, quarantined, and never delivered. The rate of such leaks is the number-one quality measure of the whole system.

**The dry run.** Before a real job, customers can request a rehearsal that produces a side-by-side "redline" view (original vs. cleaned, differences highlighted, like tracked changes in Word) so a human can approve the rules before anything is finalized.

---

## 8. A worked example

**Original document text:**

> Dr. Priya Sharma (phone 98401-23456) was admitted on 12 March 2024 and discharged on 15 March 2024. Prescribed Metformin. Card on file: 4111 1111 1111 1111.

**Training mode output** (going to AI training — shredder):

> <NAME_1> (phone <PHONE>) was admitted on <DATE_1> and discharged on <DATE_2>. Prescribed <MEDICATION>. Card on file: <CREDIT_CARD>.

*(With date-shifting enabled, the dates might instead read "9 June 2024" and "12 June 2024" — false dates, real 3-day gap.)*

**RAG mode output** (going to searchable library — consistent alias):

> User_91a4b (phone 73958-61204) was admitted on 12 March 2024 and discharged on 15 March 2024. Prescribed Metformin*. Card on file: 5217 8348 9010 3374.

Every other document mentioning Priya Sharma will also say `User_91a4b`. The phone and card numbers are fake but correctly formatted. *(Whether medications/dates are also replaced in RAG mode depends on the customer's rulebook.)*

---

## 9. What keeps the secrets secret

- Secret keys (the HMAC salt, the encryption keys, the vault key) live in a dedicated secure key store — never in settings files. Each tenant has their own keys; each purpose has its *own separate* key.
- Changing the tenant's secret key changes every pseudonym — so key rotation requires re-processing the whole document collection. This is documented and planned for, not a surprise.
- All logs and metrics are written so that they never contain original sensitive values.
- The system watches for one rare mathematical accident: two different names producing the same shortened code (a "collision"). If detected, the engine lengthens the code for that entity and logs it — two different people are never silently merged into one pseudonym.

---

## 10. Frequently asked questions

**Can cleaned training data be un-cleaned?** No. Training mode keeps no keys, no lookup tables, no original text anywhere. There is nothing to reverse with.

**If I run the same file twice, do I get two different results?** No. Processing is repeatable ("idempotent") — same file, same job, same rules → byte-identical output.

**What happens if the engine isn't sure something is private?** It masks it. Over-masking is the designed-in safe direction.

**Who can look up who "User_91a4b" really is?** Nobody, unless the customer explicitly enabled the reversible vault — and even then, only authorized roles, through an emergency-access door that records who asked and why.

**Does any data leave the company's machines?** No. The entire system runs offline, on-premise.
