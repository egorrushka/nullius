# Canonical encoding

This document is the normative statement of what a canonical `.ccert` byte
string is. It exists so that a second implementation can write a reader
that agrees with this one byte for byte — accepts exactly what this one
accepts, refuses exactly what it refuses — because content addressing is
only as meaningful as the agreement on which bytes address which document.

The reader in `verifier/src/json.rs` is the authority; this document
describes it. Where the two ever disagree the code is right and the
document is the bug, the same way the Rust verifier is the truth and the
Python producer mirrors it. Each rule below is stated with the exact
substring the reader emits when the rule is broken, so the rule is
checkable rather than merely asserted, and so a divergent implementation
can be caught against a fixed message rather than a paraphrase.

## The model: refuse, never re-encode

Canonicality is enforced by refusing non-canonical input, not by
normalising it. There is deliberately no mode that re-encodes a document
and compares — that would require a writer inside the verifier, and a
value is hashed from the bytes it was parsed from precisely so that a
disagreement between a writer and a reader cannot hide. A reader that
repaired its input would be an oracle mapping many spellings onto one, and
the oracle is the thing this format exists to remove. `ccert-v0.md`,
under "Canonical form, and why there is no re-encoding mode", gives the
longer argument; this document gives the rules it rests on.

A consequence worth stating plainly: a canonical document has exactly one
byte string. Two readers that both follow the rules below cannot disagree
about whether a given file is canonical, nor about what it says.

## Bytes and framing

- **UTF-8, and no byte-order mark.** The input is UTF-8. A leading BOM is
  refused rather than stripped, because stripping it would be a
  re-encoding. Refusal substring: `byte order mark is not allowed`.
- **One optional trailing newline, and nothing after it.** The document is
  a single value; after it, at most one `\n` may appear, and nothing else.
  Any other trailing byte is refused. Refusal substring: `trailing bytes
  after the document`. The single trailing newline is *not* part of the
  hashed encoding (see Content addressing), so a file with it and a file
  without it have the same digest and are the same document.
- **No whitespace between tokens.** Canonical form has no insignificant
  space: not between a key and its colon, a colon and its value, a comma
  and the next element, nor anywhere else. Where a value is expected, the
  refusal substring is `whitespace at offset`; where an object key is
  expected, whitespace instead trips the key parser and the substring
  names the expected quote (`expected \`"\``). Both are the same rule seen
  from two positions.

## Tokens and types

- **Only six types.** object, array, string, `true`, `false`, `null`. An
  unexpected byte where a value is expected is refused: `unexpected byte`.
- **No JSON numbers, anywhere.** Every quantity is a decimal string, so
  that a number has exactly one spelling. A bare JSON number — including
  one with a leading zero — is refused: `numbers are not allowed in
  canonical form`. The rule that a decimal string itself has one spelling
  (no leading zeros, no `+`, no `-0`, no exponent) is a semantic rule on
  the value, enforced by the claim that reads it, not by the reader; this
  document governs the byte grammar, and the byte grammar forbids the
  number token outright.

## Strings and escaping

Escaping is minimal: a character that can appear literally must appear
literally, or it would have two spellings.

- **Only the necessary escapes.** `\"`, `\\`, `\n`, `\t`, `\r`, `\b`,
  `\f`, and `\uXXXX` solely for control characters below `0x20`. Any other
  escape is refused: `unknown escape`.
- **No `\/`.** The solidus is a legal character and is written as itself;
  the escaped form is refused: ``\/` is not minimal escaping`` (the
  substring begins at the backtick-slash).
- **No `\u` for a character that can be literal.** A `\uXXXX` naming a code
  point at or above `0x20` is refused, because that character has a literal
  spelling: `non-minimal escape \u`.
- **No raw control bytes in a string.** A byte below `0x20` appearing
  literally inside a string is refused: `raw control byte at offset`. Such
  a byte must be written with the `\u` or short escape that is its only
  canonical spelling.

## Object keys

- **A closed character set.** A key matches `[A-Za-z0-9._:-]+`. The set is
  deliberately free of characters that escaping could spell two ways, so
  the sort below is a sort on the obvious bytes. A key with a byte outside
  the set is refused: `uses a byte outside [A-Za-z0-9._:-]`. An empty key
  is refused: `empty object key at offset`.
- **Sorted, and unique, by bytes.** Within an object, keys appear in
  ascending byte order with no repeats. Unsorted keys mean one document
  with two encodings; duplicate keys mean two readers can disagree about
  which value wins. Both are the same refusal: `keys out of order or
  repeated at offset`.
- **A closed set of keys at every level.** The bundle, a claim, its
  evidence reference, the subject and its field, each evidence payload,
  and every object nested inside a payload — a chain step, a factor entry,
  a point, a curve, a field — admit only the keys defined for them. A key
  that is not read by anything is refused rather than ignored: `unknown
  field`. This is where the format refuses a sentence addressed to a human
  reader with no verifier behind it; the fuller reasoning is in
  `security-model.md`, under the guarantee that no field reaches a policy
  or a reader unchecked.

## Content addressing

A content address is the string `sha256:` followed by exactly 64 lowercase
hexadecimal digits — 71 characters in total. A string of any other shape
is not an address.

Two digests are taken, both plain SHA-256 of a span of the canonical
bytes, with no prefix, tag, or domain separator:

- **The bundle digest** is `SHA-256` of the whole canonical encoding with
  the single optional trailing newline removed. It is the document's name.
- **An evidence-pool key** is `SHA-256` of the exact byte span of the entry
  it keys. Every key in the pool must equal the digest of its own value, or
  the pool has been altered: `evidence does not hash to its key`.

**There is no domain separation, and none is needed.** The two digests live
in disjoint namespaces — one names a file, the other keys an entry inside
that file's evidence pool — and are never compared against each other, so a
value that happened to hash alike in both places would create no ambiguity
about what any document says. Adding a domain tag would change every
published digest to defend against a collision that could not mean
anything; the raw hash of the canonical bytes is the whole mechanism.

## Rules, refusals, and the vectors that pin them

Each rule ships, or should ship, with a negative vector: a `.ccert` that
breaks exactly that rule, carrying the substring its refusal must contain.
The table records the current state. A dash marks a rule the grammar
enforces but the corpus does not yet exercise with a dedicated vector —
these are the gaps for the corpus-completion step, not rules that go
unchecked at runtime.

| Rule | Refusal substring | Vector |
|------|-------------------|--------|
| No byte-order mark | `byte order mark is not allowed` | `byte-order-mark` |
| One trailing newline, nothing after | `trailing bytes after the document` | `trailing-bytes` |
| No whitespace (value position) | `whitespace at offset` | `whitespace` |
| No whitespace (key position) | ``expected `"`` | — |
| Only the six types | `unexpected byte` | — |
| No JSON numbers | `numbers are not allowed in canonical form` | `json-number` |
| Only necessary escapes | `unknown escape` | `unknown-escape` |
| No `\/` | ``\/` is not minimal escaping`` | `escaped-solidus` |
| No non-minimal `\u` | `non-minimal escape \u` | `non-minimal-unicode-escape` |
| No raw control bytes | `raw control byte at offset` | `raw-control-byte` |
| Key character set | `uses a byte outside [A-Za-z0-9._:-]` | `forbidden-key-byte` |
| No empty key | `empty object key at offset` | `empty-key` |
| Keys sorted and unique | `keys out of order or repeated at offset` | `reordered-keys` |
| Closed keys at every level | `unknown field` | `claim-`, `subject-`, `evidence-`, `asserts-`, `chain-step-`, `factor-entry-`, `witness-point-with-an-unread-field` |
| Evidence keyed by its own digest | `evidence does not hash to its key` | `broken-evidence-hash` |

Two rows still carry a dash. Whitespace in key position is the same rule
as whitespace in value position, which `whitespace` already pins from the
other side; the distinct message is a reader-internal detail, not a
separate rule to certify. The type restriction (`unexpected byte`) is a
catch-all the number, escape and control-byte vectors already exercise
in every concrete form a bundle can take. Every other rule above ships a
vector that breaks it and no other, each carrying the substring in its
row.
