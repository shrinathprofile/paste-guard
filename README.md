# Paste Guard

A second pair of eyes before you paste into ChatGPT or Claude.

Paste Guard watches your macOS clipboard. When you copy something that looks like a tax file number, bank details, card number, API key or other personal data, a dialog tells you what it found and offers to redact it. Everything runs on your Mac. Nothing is sent anywhere.

> **Not a security product.** It catches exact formats well and misses things a person would spot (names, for one). Treat it as a reminder, not a guarantee.

## Run it

Needs macOS and Python 3.10+. No dependencies.

```bash
git clone https://github.com/shrinathprofile/paste-guard
cd paste-guard
python3 paste_guard.py
```

Copy `My TFN is 123 456 782` and a dialog appears. Click **Redact**, paste, and you get `My TFN is [TFN]`. Stop it with Ctrl-C.

Run the self-check:

```bash
python3 paste_guard.py --check
```

## What it checks

| How it's confirmed | What |
|---|---|
| **Check digit** (official algorithm, few false alarms) | TFN (9-digit, and old 8-digit after "TFN"), ABN, ACN, credit card, IBAN |
| **Format** | Email, Australian phone, Centrelink CRN, street address, state + postcode, IP address, API keys (OpenAI/Anthropic, AWS, GitHub, Slack, Google), JWT, private keys |
| **Format after a keyword** (too generic on their own) | BSB, bank account, passport, driver licence, date of birth |

## How it works

```
copy → pbpaste (every 0.5 s) → regex + check digits → found? → macOS dialog → Redact → pbcopy
```

- One file, standard library only. macOS's own `pbpaste`, `pbcopy` and `osascript` do the clipboard and the dialog.
- The dialog shows only *what kind* of data was found, never the text itself.
- The terminal logs only the length of what you copied, never the content.

## Known limits

- **Names aren't detected.** No pattern can tell a name from ordinary words.
- **About 1 in 10 random 9-digit numbers pass the TFN or ACN check digit.** Expect the odd false alarm.
- **Driver licence formats differ by state**, so they're only caught after a word like "licence" or "DL".
- **ABN and ACN are public numbers.** They're flagged because a sole trader's ABN identifies a person. Remove those rows if they get noisy.
- **It warns, it doesn't block.** It checks when you copy; it can't stop a paste.

## Add a check

1. Add a row to `PATTERNS` in `paste_guard.py`: `(label, regex, validator or None)`.
2. Add a sample to `one_each` in `check()`.
3. Run `python3 paste_guard.py --check`.

Ideas: New Zealand IRD number, UK National Insurance number.

## Credits

Australian check-digit logic follows the recognisers in [Microsoft Presidio](https://github.com/microsoft/presidio) (MIT), which is also the best place to go if you need a full PII toolkit.

## License

MIT
