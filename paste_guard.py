"""Paste Guard v0.1 — warns when you copy sensitive text. macOS, local only.

Run:    python3 paste_guard.py
Check:  python3 paste_guard.py --check
Checksums ported from Microsoft Presidio's AU recognizers (MIT).
"""
import re, subprocess, sys, time

POLL_SECONDS = 0.5    # ponytail: pbpaste polling, NSPasteboard.changeCount via pyobjc if CPU ever matters
ENV = {"LANG": "en_US.UTF-8"}  # pbpaste mangles non-ASCII without a UTF-8 locale


def _digits(s):
    return re.sub(r"\D", "", s)

def _weighted(digits, weights):
    return sum(int(d) * w for d, w in zip(digits, weights))

def is_luhn(d):
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0

def is_tfn(d):      return len(d) == 9 and _weighted(d, [1, 4, 3, 7, 5, 8, 6, 9, 10]) % 11 == 0
def is_tfn8(d):     return len(d) == 8 and _weighted(d, [10, 7, 8, 4, 6, 3, 5, 1]) % 11 == 0  # pre-1990s TFNs
def is_acn(d):      return len(d) == 9 and (10 - _weighted(d, [8, 7, 6, 5, 4, 3, 2, 1]) % 10) % 10 == int(d[8])
def is_abn(d):      return len(d) == 11 and _weighted(str(int(d[0]) - 1) + d[1:], [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]) % 89 == 0
def is_card(d):     return 13 <= len(d) <= 19 and is_luhn(d)

def is_iban(s):
    s = s.replace(" ", "")
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1

# Bare digit runs: first checksum that passes wins (TFN before ACN).
# ponytail: TFN/ACN checksums still pass ~1 in 10 random 9-digit numbers, fine for a warning, not for blocking
NUMBER_CHECKS = [("TFN", is_tfn), ("ACN", is_acn), ("ABN", is_abn), ("CARD", is_card)]
DIGIT_RUN = re.compile(r"\b\d(?:[ -]?\d){8,18}\b")

def ctx(keywords, value):
    """Value only counts after a keyword, e.g. 'BSB: 062-000'. Formats too generic to match bare."""
    return re.compile(rf"(?i:\b(?:{keywords})\b)(?:[\s:#.-]|(?i:file|card|no|num|number)\b)*(?P<v>{value})")

DATE = r"\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{1,2}\s+[A-Z][a-z]{2,8}\s+\d{4}"
STATES = "NSW|VIC|QLD|SA|WA|TAS|NT|ACT"
STREET = "St|Street|Rd|Road|Ave|Avenue|Dr|Drive|Ct|Court|Pl|Place|Cres|Crescent|Tce|Terrace|Hwy|Highway|Pde|Parade|Ln|Lane|Way|Blvd|Boulevard"

# (label, regex, validator or None). Earlier entries win when matches overlap.
PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), None),
    ("JWT", re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}"), None),
    ("API_KEY", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})"), None),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), None),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), is_iban),
    ("TFN", ctx("TFN|tax file", r"\d{3}[ -]?\d{3}[ -]?\d{2}(?!\d)"), lambda s: is_tfn8(_digits(s))),
    ("BSB", ctx("BSB", r"\d{3}[- ]?\d{3}\b"), None),
    ("BANK_ACCOUNT", ctx("acc(?:oun)?t|acc", r"\d(?:[ -]?\d){5,9}\b"), None),
    ("PASSPORT", ctx("passport", r"[A-Z]{1,2}\d{7}\b"), None),
    ("DRIVER_LICENCE", ctx(r"driver'?s?\s+licen[cs]e|licen[cs]e|DL", r"(?=[A-Z0-9]*\d)[A-Z0-9]{6,11}\b"), None),
    ("DOB", ctx(r"DOB|D\.O\.B|date of birth|born(?: on)?", DATE), None),
    ("CRN", re.compile(r"\b\d{3} ?\d{3} ?\d{3}[A-Za-z]\b"), None),  # Centrelink Customer Reference Number
    ("PHONE", re.compile(r"(?:\+61 ?|\b0)[2-478](?:[ -]?\d){8}\b"), None),
    ("ADDRESS", re.compile(rf"\b\d{{1,5}}[A-Za-z]?\s+(?:[A-Z][a-z]+\s+){{1,3}}(?:{STREET})\b|\b(?:{STATES})\s+\d{{4}}\b"), None),
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), None),
]


def find_spans(text):
    """Return [(start, end, label)] for exact-format sensitive data."""
    spans = []
    def add(s, e, label):
        if not any(s < E and S < e for S, E, _ in spans):
            spans.append((s, e, label))
    for label, rx, valid in PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span("v") if "v" in rx.groupindex else m.span()
            if valid is None or valid(text[s:e]):
                add(s, e, label)
    for m in DIGIT_RUN.finditer(text):
        label = next((name for name, ok in NUMBER_CHECKS if ok(_digits(m.group()))), None)
        if label:
            add(m.start(), m.end(), label)
    return sorted(spans)

def redact(text, spans):
    for s, e, label in reversed(spans):
        text = text[:s] + f"[{label}]" + text[e:]
    return text


def ask(message, buttons):
    # message is passed as argv, never spliced into the script, so clipboard text can't inject AppleScript
    script = ['on run argv', f'display dialog (item 1 of argv) with title "Paste Guard" buttons {{{buttons}}} default button 1', 'end run']
    out = subprocess.run(["osascript", *sum((["-e", l] for l in script), []), message], capture_output=True, text=True)
    return out.stdout.strip().removeprefix("button returned:")

def watch():
    last = None
    while True:
        text = subprocess.run(["pbpaste"], capture_output=True, text=True, env=ENV).stdout
        if text and text != last:
            last = text
            spans = find_spans(text)
            if spans:
                labels = ", ".join(sorted({l for _, _, l in spans}))
                if ask(f"Your clipboard contains: {labels}", '"Redact", "Ignore"') == "Redact":
                    last = redact(text, spans)
                    subprocess.run(["pbcopy"], input=last, text=True, env=ENV)
            print(time.strftime("%H:%M:%S"), "checked", len(text), "chars")  # never log the text itself
        time.sleep(POLL_SECONDS)


def check():
    # valid: ATO's example ABN, standard Luhn test card, checksum-valid TFN
    assert is_tfn("123456782") and not is_tfn("123456789")
    assert is_abn("51824753556") and not is_abn("51824753557")
    assert is_card("4111111111111111") and not is_card("4111111111111112")
    assert is_acn("004085616") and not is_acn("004085617")  # ASIC's example ACN
    assert is_tfn8("12345677") and not is_tfn8("12345678")
    assert is_iban("GB82WEST12345698765432") and not is_iban("GB82WEST12345698765433")

    text = "TFN 123 456 782, call 0412 345 678 or bob@example.com, card 4111-1111-1111-1111, order 123456789"
    labels = [l for _, _, l in find_spans(text)]
    assert labels == ["TFN", "PHONE", "EMAIL", "CARD"], labels  # order number fails every checksum
    assert redact(text, find_spans(text)) == "TFN [TFN], call [PHONE] or [EMAIL], card [CARD], order 123456789"

    one_each = {
        "ACN": "ACN 004 085 616", "ABN": "ABN 51 824 753 556", "TFN": "old TFN: 123 456 77", "BSB": "BSB: 062-000",
        "BANK_ACCOUNT": "account number 1234 5678", "PASSPORT": "Passport No. PA1234567",
        "DRIVER_LICENCE": "Driver licence 12345678", "DOB": "DOB: 03/04/1990",
        "CRN": "CRN 123 456 789A", "ADDRESS": "12 Rundle Street, Adelaide SA 5000", "IP_ADDRESS": "from 203.0.113.42",
        "IBAN": "GB82 WEST 1234 5698 7654 32", "JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4fwpM",
        "API_KEY": "key sk-ant-abcdefghijklmnopqrstuvwxyz", "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
    }
    for want, sample in one_each.items():
        got = {l for _, _, l in find_spans(sample)}
        assert want in got, (want, got)

    for clean in ["meeting at 3pm, room 12", "version 1.2.3", "the account was closed", "licence to drive", "order 123456789"]:
        assert find_spans(clean) == [], (clean, find_spans(clean))
    print("ok")


if __name__ == "__main__":
    check() if "--check" in sys.argv else watch()
