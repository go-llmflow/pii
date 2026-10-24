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

When two candidates overlap, the one that starts first wins, then the longer one, then the checksum-validated kind.

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

The tests also run with `GOARCH=386`.

## Performance

`BenchmarkFind` scans 64 KiB of the benign corpus. The comparison against Microsoft Presidio, the reference in this domain, has not been made yet: the machine was too loaded to measure (load average 81).

## References

- ISO 13616 (IBAN) and the SWIFT registry lengths: https://en.wikipedia.org/wiki/International_Bank_Account_Number
- NIR structure and key, Corsica: https://fr.wikipedia.org/wiki/Num%C3%A9ro_de_s%C3%A9curit%C3%A9_sociale_en_France
- ISO/IEC 7812-1 annex B (Luhn) and network prefixes: https://en.wikipedia.org/wiki/Luhn_algorithm, https://en.wikipedia.org/wiki/Payment_card_number
- ITU-T E.164: https://en.wikipedia.org/wiki/E.164; the French numbering plan: https://en.wikipedia.org/wiki/Telephone_numbers_in_France
- RFC 5322 §3.2.3, §3.4.1; RFC 5321 §4.5.3.1: https://www.rfc-editor.org/rfc/rfc5322, https://www.rfc-editor.org/rfc/rfc5321
- RFC 4291 §2.2: https://www.rfc-editor.org/rfc/rfc4291

## Licence

See [LICENSE](LICENSE).
