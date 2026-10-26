# pii

Finds personal data in text, in pure Go with no dependencies (standard library only, `CGO_ENABLED=0`). It looks for:

- e-mail addresses
- phone numbers
- IBANs
- French social security numbers (NIR)
- payment card numbers
- IPv4 and IPv6 addresses

It was written for the go-llmflow gateway's PII guardrail, which masks prompts before they reach the model and masks completions before they reach the client. The package itself only reports what it found and where; the caller decides what to do with it.

```go
s := pii.New()                       // every kind; pii.New(pii.IBAN, pii.Card) for some
ms := s.Find(text)                   // []pii.Match{Kind, Start, End}, ordered, no overlap
clean := pii.Mask(text, ms, pii.Placeholder) // "IBAN [IBAN], mail [EMAIL]"
```

## What a match means

A recogniser that has a check digit uses it. A match is therefore a value that could exist, not just a string with the right number of digits.

| kind | recognised by | checked by |
|---|---|---|
| `iban` | 2 letters, 2 digits, then alphanumerics; single spaces allowed (the printed groups of four) | ISO 13616: the exact length for the country, and mod 97 = 1 after moving the first four characters to the end with A=10 … Z=35 |
| `nir` | sex 1/2/3/4/7/8, year, month, department (2A/2B for Corsica), commune, order number, 2-digit key; spaces allowed | key = 97 − (the 13 digits mod 97), with 2A read as 19 and 2B as 18 (INSEE); month 01–13, 20–42 or 50–99 |
| `card` | 13–19 digits, single spaces or dashes allowed | Luhn (ISO/IEC 7812-1 annex B), plus a known network's prefix and length: Visa, Mastercard, American Express, Discover, JCB, Diners |
| `email` | a practical subset of RFC 5322 addr-spec: a dot-atom local part, LDH domain labels, an alphabetic top-level label | local part ≤ 64 octets and address ≤ 254 (RFC 5321 §4.5.3.1). A `git@host:path` remote is not treated as a mailbox |
| `phone` | E.164 (`+`, at most 15 digits) and the French plan (`0` + 9 digits, `+33` / `0033`, the optional `(0)`), with space, dot or dash separators | format only, since phone numbers have no checksum |
| `ipv4` | dotted decimal, not inside a longer dotted run (version numbers, OIDs) | `net/netip` (which rejects octets with leading zeros) |
| `ipv6` | the three text forms of RFC 4291 §2.2, including a trailing IPv4 | `net/netip`; zones are not accepted |

When two candidates overlap, the one that starts first wins, then the longer one, then the checksum-validated kind. There is one exception. A phone number that was shortened to end before a separator (`+10000010` in `+10000010 0100000000`) gives way to any candidate that overlaps it. That way, shortening one value never leaves part of another in clear.

A candidate that is refused (preceded by a letter or digit, followed by a digit, failing its checksum) does not hide one that overlaps it: the search resumes just after its start. Since v0.2.0; v0.1.0 resumed after its end, and `FuzzFind` found numbers left in clear after masking.

`MaxLen` (254 bytes) bounds the length of any match. A caller masking a stream can hold back the last `MaxLen` bytes, and will then never release the start of a match whose end it has not seen yet.

## False positives, measured

`testdata/benign.txt` contains no personal data by construction. It is 45 lines of text a model reads and writes every day, chosen to look like the real thing:

- versions, OIDs, dates, timestamps, UUIDs, hashes;
- ISBN, EAN, SIREN and SIRET numbers;
- prices, coordinates, MAC addresses;
- C++ and Rust `::`, an SSH git remote;
- a card number that fails Luhn, a NIR and an IBAN with wrong keys;
- invalid IP addresses.

`TestFalsePositives` fails if any count rises above what was measured when the recognisers were written:

| kind | false positives |
|---|---|
| iban, nir, card, email, ipv4, ipv6 | 0 |
| phone | 1: `ref 0123456789`, a valid French number in every respect except its meaning |

Phone numbers are the one kind that cannot be checked. A guardrail that masks them will also mask 10-digit references starting with 0.

## Security

The input is untrusted (prompts and model output). Every regular expression runs on Go's RE2 engine, in linear time. `FuzzFind` checks on arbitrary input that:

- matches are ordered and within bounds;
- every checksum-validated match re-validates on its own;
- masking twice gives the same result as masking once.

RE2 is not enough on its own. **v0.1.0 was quadratic on long runs of digits**, and should be upgraded:

- the card recogniser tried every end of an unbounded candidate;
- 1 MiB of `1 1 1 …` took 11 min 56 s (measured 2026-10-26, on a loaded machine).

Since v0.2.0 card candidates are bounded at 19 digits. Patterns of bounded length are searched in 512-byte windows, and positions that cannot start a match are skipped. `TestLongRunsStayLinear` checks the growth from 128 KiB to 2 MiB on twelve adversarial inputs: linear is ×16, and the test fails above ×64.

The tests also run with `GOARCH=386`.

## How it finds, and why it is fast

Each pattern can only match bytes of a small ASCII class, and contains no assertion. So each match lies inside one maximal run of that class, and contains a trigger byte:

| kind | trigger |
|---|---|
| e-mail | `@` |
| IPv6 | `:` |
| E.164 phone | `+` |
| IPv4 | `.` |
| the other numbers | a digit |

`Find` looks for the trigger bytes (`strings.IndexByte`, vectorised in the standard library). It expands each run that holds one, and runs the regexp only on runs at least as long as the shortest match. On prose, that is a handful of short strings instead of nine passes of an automaton over the whole text.

This changes nothing in the results, and two tests check it:

- `TestRunsMatchWholeText` (20,000 generated texts) and `FuzzRunsMatchWholeText` compare with a scan of the whole text;
- `TestMasksAtLeastV010` checks a recorded corpus of what v0.1.0 found: every byte v0.1.0 masked is still masked.

v0.1.0, profiled on the gateway's 2 KB benchmark prompt (`BenchmarkFindPrompt`):

- two thirds of the time went to `regexp` over the whole text, nine times (e-mail and IPv6 a third between them);
- a third went to `runtime.madvise`, for the backtracker's bitmaps sized to the whole text.

## Compared with Microsoft Presidio

`bench/presidiocmp` compares pii with [Presidio](https://github.com/microsoft/presidio), the reference tool in this domain. Presidio is `presidio-analyzer` 2.2.364 with its default spaCy model, `en_core_web_lg`, run through `uv`. The harness is in Go; Python only runs Presidio. It is a separate module, so pii itself keeps no dependency.

**Detection quality, 2026-10-26** (`presidiocmp --quality-only --details`; quality does not depend on the machine's load).

The corpus is `testdata/labelled.txt`: 24 documents in French and English, with decoys (versions, OIDs, ISBN, SIRET, MAC addresses, a card that fails Luhn, invalid addresses, a git remote). A finding counts when it overlaps a labelled value of its kind:

| kind | pii precision / recall | Presidio precision / recall |
|---|---|---|
| card | 1.00 / 1.00 | 1.00 / 1.00 |
| email | 1.00 / 1.00 | 0.89 / 1.00 (`git@github.com` from a git remote) |
| iban | 1.00 / 1.00 | 1.00 / 1.00 |
| ip (v4 and v6) | 1.00 / 1.00 | 0.82 / 1.00 (a version number, an OID) |
| phone | 0.93 / 0.87 | 0.74 / 0.93 (dates, order numbers, an IP address, the tail of an IBAN) |
| nir | 1.00 / 1.00 | n/a: Presidio has no French recogniser |

Read this with three caveats:
- I wrote the corpus knowing pii's rules, which favours it.
- pii misses phone numbers in national formats other than the French one (`(212) 555-1234`, `030 901820`), which Presidio finds.
- Presidio misses `+44 7700 900123`.

Both take the reference `0123456789` for a phone number.

**Latency** is measured single-threaded, in interleaved rounds, and only at load ≤ 4 (the harness refuses otherwise). The figures are not in yet: the machine has been above load 80 all morning.

## References

- ISO 13616 (IBAN) and the SWIFT registry lengths: https://en.wikipedia.org/wiki/International_Bank_Account_Number
- NIR structure and key, Corsica: https://fr.wikipedia.org/wiki/Num%C3%A9ro_de_s%C3%A9curit%C3%A9_sociale_en_France
- ISO/IEC 7812-1 annex B (Luhn) and network prefixes: https://en.wikipedia.org/wiki/Luhn_algorithm, https://en.wikipedia.org/wiki/Payment_card_number
- ITU-T E.164: https://en.wikipedia.org/wiki/E.164; the French numbering plan: https://en.wikipedia.org/wiki/Telephone_numbers_in_France
- RFC 5322 §3.2.3, §3.4.1; RFC 5321 §4.5.3.1: https://www.rfc-editor.org/rfc/rfc5322, https://www.rfc-editor.org/rfc/rfc5321
- RFC 4291 §2.2: https://www.rfc-editor.org/rfc/rfc4291

## Licence

See [LICENSE](LICENSE).
