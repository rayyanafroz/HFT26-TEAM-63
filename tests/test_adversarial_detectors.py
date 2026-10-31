"""Attacks on the secret, personal-data and code detectors (SOT 7.3).

Each table is a way someone might hide a value from a pattern: look-alike or invisible characters, escapes,
encodings, breaks inside the value, unusual phrasing. Values come from ``fakes`` at run time, so the repo holds
no token-shaped text. Two things are checked for every disguise: it is found, and the redacted text keeps no
five-character piece of the value.
"""

import base64
import binascii
import random
import string
import time
import urllib.parse

import pytest

from shadowlens.analysis.engine import analyze_text, is_safe_to_send
from shadowlens.analysis.normalize import deobfuscate_command, fold, to_original
from shadowlens.analysis.settings import AnalysisSettings
from shadowlens.fakes import fake

SETTINGS = AnalysisSettings(salt=b"s" * 32)
ZW = "\u200b"
FULLWIDTH = {i: i + 0xFEE0 for i in range(0x21, 0x7F)}


def rules(text):
    return {f.rule_id for f in analyze_text(text, SETTINGS).findings}


def pieces(value, size=5):
    return {value[i:i + size] for i in range(len(value) - size + 1)}


def assert_hidden(value, text):
    result = analyze_text(text, SETTINGS)
    assert result.findings, f"not found: {text[:90]!r}"
    leaked = pieces(value) & {result.redacted_text[i:i + 5] for i in range(len(result.redacted_text) - 4)}
    assert not leaked, f"left visible: {sorted(leaked)[:3]} in {result.redacted_text[:120]!r}"


SECRET_KINDS = ["openai_key", "aws_access_key", "github_token", "stripe_key", "slack_token", "anthropic_key",
                "google_key", "hf_token"]


def disguises(value):
    mid = len(value) // 2
    return {
        "plain": value,
        "zero-width inside": value[:mid] + ZW + value[mid:],
        "zero-width after the prefix": value[:4] + ZW + value[4:],
        "soft hyphen": value[:mid] + "\u00ad" + value[mid:],
        "word joiner and BOM": value[:mid] + "\u2060\ufeff" + value[mid:],
        "fullwidth": value.translate(FULLWIDTH),
        "look-alike letters": value.replace("a", "\u0430").replace("e", "\u0435").replace("o", "\u043e"),
        "url-encoded": urllib.parse.quote(value, safe=""),
        "percent-encoded start": "%" + "%".join(f"{ord(c):02x}" for c in value[:3]) + value[3:],
        "json \\u escapes": "".join(f"\\u{ord(c):04x}" for c in value),
        "html entities": "".join(f"&#{ord(c)};" for c in value),
        "base64": base64.b64encode(value.encode()).decode(),
        "hex": binascii.hexlify(value.encode()).decode(),
        "two halves with a space": f"{value[:mid]} {value[mid:]}",
        "two halves on two lines": f"{value[:mid]}\n{value[mid:]}",
        "three pieces": f"{value[:8]} {value[8:16]} {value[16:]}",
        "string concatenation": f'"{value[:mid]}" + "{value[mid:]}"',
    }


@pytest.mark.parametrize("kind", SECRET_KINDS)
def test_a_disguised_secret_is_found_and_fully_redacted(kind):
    value = fake(kind, 7)
    for name, disguised in disguises(value).items():
        text = f"before {disguised} after"
        try:
            assert_hidden(value, text)
        except AssertionError as exc:
            raise AssertionError(f"{kind} / {name}: {exc}") from None
        assert is_safe_to_send(text, SETTINGS) is False, f"{kind} / {name} would be sent"


@pytest.mark.parametrize("kind", SECRET_KINDS)
def test_the_stored_preview_and_context_show_at_most_four_characters(kind):
    value = fake(kind, 8)
    for name, disguised in disguises(value).items():
        for finding in analyze_text(f"x {disguised} y", SETTINGS).findings:
            assert not pieces(value) & pieces(finding.masked_preview + finding.context), f"{kind} / {name}"


@pytest.mark.parametrize("before", ["key_", "KEY=", "OPENAI_API_KEY_", "x-api-key:", "(", "[", '"', "'", "=", "/", "#", "::"])
def test_a_key_stuck_to_other_characters_is_still_found(before):
    assert "SEC_OPENAI_KEY" in rules(f"a {before}{fake('openai_key', 4)} b")


@pytest.mark.parametrize("after", [")", "]", '"', ",", ".", ";", "/v1"])
def test_a_key_followed_by_punctuation_is_still_found(after):
    assert "SEC_OPENAI_KEY" in rules(f"a {fake('openai_key', 4)}{after} b")


def random_text(seed, alphabet, n):
    rnd = random.Random(seed)
    return "".join(rnd.choice(alphabet) for _ in range(n))


ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
VENDOR_TOKENS = {
    "groq": lambda: "gsk_" + random_text(1, ALNUM, 52), "replicate": lambda: "r8_" + random_text(2, ALNUM, 37),
    "perplexity": lambda: "pplx-" + random_text(3, ALNUM, 48), "xai": lambda: "xai-" + random_text(4, ALNUM, 80),
    "openrouter": lambda: "sk-or-v1-" + random_text(5, HEX, 64), "nvidia": lambda: "nvapi-" + random_text(6, ALNUM + "_-", 64),
    "langsmith": lambda: "lsv2_pt_" + random_text(7, HEX, 32) + "_" + random_text(8, HEX, 10),
    "fireworks": lambda: "fw_" + random_text(9, ALNUM, 28), "openai no-project": lambda: "sk-None-" + random_text(10, ALNUM + "_-", 60),
    "slack app": lambda: "xapp-1-A0" + random_text(11, string.ascii_uppercase + string.digits, 9) + "-" + random_text(12, string.digits, 12) + "-" + random_text(13, HEX, 40),
    "anthropic admin": lambda: "sk-ant-admin01-" + random_text(14, ALNUM + "_-", 80), "gitlab": lambda: "glpat-" + random_text(15, ALNUM, 20),
    "digitalocean": lambda: "dop_v1_" + random_text(16, HEX, 64), "shopify": lambda: "shpat_" + random_text(17, HEX, 32),
    "sendgrid": lambda: "SG." + random_text(18, ALNUM, 22) + "." + random_text(19, ALNUM, 43), "npm": lambda: "npm_" + random_text(20, ALNUM, 36),
    "google oauth": lambda: "ya29." + random_text(21, ALNUM, 48), "twilio": lambda: "SK" + random_text(22, HEX, 32),
    "telegram": lambda: "123456789:AA" + random_text(23, ALNUM, 33), "slack webhook": lambda: "https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFGH/" + random_text(24, ALNUM, 24),
}


@pytest.mark.parametrize("vendor", sorted(VENDOR_TOKENS))
def test_ai_and_cloud_vendor_tokens_are_found(vendor):
    token = VENDOR_TOKENS[vendor]()
    assert_hidden(token, f"here: {token} end")
    assert_hidden(token, f"api_key = {token}")


ASSIGNMENTS = [
    "the admin password is {v} ok", "pwd: {v}", "pass={v}", "pw={v}", "passwd {v}", "my api key: {v}", "apikey={v}", "auth={v}",
    "login with root and the password {v}", "private_key={v}", "export DB_PASS={v}", "password:\n  {v}", '{{"password": "{v}"}}',
    "PASSWORD={v}", "mysql -u root -p{v}", "tool --password {v}", "tool --token={v}", "x-api-key: {v}", "client secret: {v}",
    "https://x.example/login?user=a&password={v}", "https://deploy:{v}@git.corp/repo.git", "Authorization: Bearer {v}{v}",
    "credentials: admin / {v}", "sshpass -p {v} ssh host", "password\uff1a{v}", "pass\u200bword={v}",
]


@pytest.mark.parametrize("template", ASSIGNMENTS)
def test_a_password_or_token_is_found_however_it_is_phrased(template):
    value = "Xk39aQ2zLm7pR" if "Bearer" not in template else "aB3dE5fG7hI9jK1l"
    text = template.format(v=value)
    assert "SEC_GENERIC_ASSIGNMENT" in rules(text) or any(r.startswith("SEC_") for r in rules(text)), text


def test_a_quoted_passphrase_with_spaces_is_found():
    assert rules("password = 'my secret phrase here 99'") & {"SEC_GENERIC_ASSIGNMENT"}


def test_pem_headers_in_any_case_and_an_unlabelled_body_are_found():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu"
    assert "SEC_PRIVATE_KEY" in rules(f"-----begin rsa private key-----\n{body}\n-----end rsa private key-----")
    assert "SEC_PRIVATE_KEY" in rules('{"private_key":"-----BEGIN PRIVATE KEY-----\\n' + body.replace("\n", "\\n") + '\\n-----END PRIVATE KEY-----\\n"}')
    assert rules(body)                                                   # a key body with no header is still caught by entropy


def digits_of(kind, n):
    return "".join(c for c in fake(kind, n) if c.isdigit())


def groups(digits, size=4, sep=" "):
    return sep.join(digits[i:i + size] for i in range(0, len(digits), size))


@pytest.mark.parametrize("separator", [" ", "-", ".", "/", "\n", "\u00a0"])
def test_a_card_number_is_found_with_any_separator(separator):
    assert "PII_CREDIT_CARD" in rules("card " + groups(digits_of("card_visa", 5), 4, separator))


def test_a_card_number_is_found_in_other_layouts():
    d = digits_of("card_visa", 6)
    for text in (d, f"{d[:4]} {d[4:10]} {d[10:]}", " ".join(d), d[:8] + ZW + d[8:], d.translate({i: i + 0xFEE0 for i in range(0x30, 0x3A)}),
                 f'{{"cc": {d}}}', groups(d, 4, "\n")):
        assert "PII_CREDIT_CARD" in rules("pay " + text), text
    for kind in ("card_mc", "card_amex"):
        assert "PII_CREDIT_CARD" in rules("pay " + fake(kind, 3))


def test_aadhaar_ssn_pan_and_iban_in_their_other_spellings():
    a = digits_of("aadhaar", 4)
    for text in (a, groups(a), groups(a, 4, "-"), groups(a, 4, "."), a[:6] + ZW + a[6:]):
        assert "PII_AADHAAR" in rules("id " + text), text
    ssn = fake("ssn", 4)
    assert "PII_SSN" in rules("ssn " + ssn.replace("-", ""))
    assert "PII_SSN" in rules("my social security number is " + ssn.replace("-", " "))
    assert "PII_SSN" not in rules("order " + ssn.replace("-", ""))      # nine digits alone are just a number
    pan = fake("pan", 4)
    for text in (pan, pan.lower(), pan[:5] + " " + pan[5:9] + " " + pan[9:]):
        assert "PII_PAN" in rules("pan " + text), text
    iban = fake("iban", 4)
    for text in (iban, groups(iban), iban.lower()):
        assert "PII_IBAN" in rules("iban " + text), text


def test_emails_written_to_slip_past_a_filter():
    email = fake("email", 5)
    local, domain = email.split("@")
    spelled = {
        "upper": email.upper(), "plus tag": local + "+tag@" + domain, "(at)": f"{local}(at){domain}",
        "[at] and [dot]": f"{local} [at] {domain.replace('.', ' [dot] ')}", "zero-width": email.replace("@", ZW + "@"),
        "fullwidth @": email.replace("@", "\uff20"), "unicode domain": "user@m\u00fcnchen.de",
    }
    for name, text in spelled.items():
        assert "PII_EMAIL" in rules("mail " + text), name


@pytest.mark.parametrize("phone", ["+91 98765 43210", "9876543210", "98765-43210", "(+91) 98765 43210", "098765 43210",
                                   "(415) 555-2671", "415.555.2671", "+1-415-555-2671", "+44 20 7946 0958"])
def test_phone_numbers_in_common_layouts(phone):
    assert "PII_PHONE" in rules("call " + phone)


@pytest.mark.parametrize("marker", ["CONFIDENTIAL", "Proprietary and Confidential", "Internal Use Only", "TRADE SECRET",
                                    "C O N F I D E N T I A L", "CONFIDEN" + ZW + "TIAL", "do not distribute"])
def test_confidential_markers_next_to_a_copyright_notice(marker):
    assert "CODE_CONFIDENTIAL_MARKER" in rules(f"// Copyright 2024 Acme Corp. {marker}\nint main() {{}}")


BENIGN_TEXTS = [
    "Please review this function and suggest improvements.", "The quick brown fox jumps over the lazy dog 1234567890.",
    "Meeting on 12/03/2024 at 10:30, room 4B, call 555 1234.", "Order #4111-2222 total $4111.50 shipped to Austin.",
    "git commit a3f5c9d1e2b4a6c8d0e2f4a6b8c0d2e4f6a8b0c2", "uuid 550e8400-e29b-41d4-a716-446655440000",
    "Please pass the salt. The password policy requires 12 characters. Bypass=true; compass points north.",
    "token count: 4096, max_tokens=1024, secret santa is on Friday.", "auth=basic mode and pw reset flow",
    "const token = getToken(); const password = process.env.DB_PASSWORD;", "password: ${DB_PASSWORD}", "api_key = os.environ['API_KEY']",
    "export API_KEY=your_api_key_here", "password = 'changeme'", "pass: example", "see https://example.com/docs?page=2&sort=asc",
    "https://github.com/org/repo/blob/main/src/app.py#L10-L20", "email me at john@example.com or support@test.com",
    "unix time 1700000000 and 1700000001", "def add(a, b):\n    return a + b\n", "SELECT name, email FROM users WHERE id = 5;",
    "100% sure, 50%off, 20%25 done, a%20b", "Version v2.0.1-rc1 released.", "I said sk-learn is a library and sk-image too",
    "see ghp_ prefix docs", "AKIA prefixes mark AWS keys", "hex 0123456789abcdef0123456789abcdef is a md5",
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "line one\nline two with a few words\nline three",
    "image data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
    "Tell the user the sky is blue and that task-1234 is done.", "the reversed words are tset and krow",
]


@pytest.mark.parametrize("text", BENIGN_TEXTS)
def test_ordinary_text_stays_quiet(text):
    assert rules(text) == set()


# ---- the folded view ---------------------------------------------------------------------------------------

def test_plain_ascii_is_not_copied():
    view, starts, ends = fold("just some plain text")
    assert view == "just some plain text" and starts is None and ends is None


def test_a_span_in_the_view_maps_back_onto_the_original_text():
    text = "k s\u200bk-\uff50roj \\u0073k %73k &#115;k"
    view, starts, ends = fold(text)
    assert view == "k sk-proj sk sk sk"
    first, last = to_original(2, 8, starts, ends)
    assert text[first:last] == "s\u200bk-\uff50ro"
    first, last = to_original(10, 12, starts, ends)
    assert text[first:last] == "\\u0073k"


def test_lone_surrogate_escapes_and_control_characters_do_not_break_folding():
    view, _, _ = fold("a\\ud800b\x00c\x07d")
    assert view == "abcd"


@pytest.mark.parametrize("command,expected", [
    ("r''m -rf /", "rm -rf /"), ("\\rm -rf /", "rm -rf /"), ("r\\m -rf /", "rm -rf /"), ("rm${IFS}-rf${IFS}/", "rm -rf /"),
    ("$'\\x72\\x6d' -rf /", "rm -rf /"), ("{rm,-rf,/}", "rm -rf /"), ('["rm", "-rf", "/"]', '["rm -rf /"]'), ("x && \\rm -rf /", "x && rm -rf /"),
])
def test_shell_disguises_are_undone(command, expected):
    assert deobfuscate_command(command) == expected


# ---- hostile input -----------------------------------------------------------------------------------------

N = 65536
HOSTILE = {
    "digits spaced": "1 " * (N // 2), "digits grouped": "4111 " * (N // 5), "digits on lines": "1\n" * (N // 2), "dots": "a." * (N // 2),
    "sk- repeated": "sk-" * (N // 3), "AKIA repeated": "AKIA" * (N // 4), "password repeated": "password " * (N // 9), "pass= repeated": "pass=" * (N // 5),
    "quotes": "'" * N, "at brackets": "[at]" * (N // 4), "emails": "a@" * (N // 2), "percent": "%41" * (N // 3), "u escapes": "\\u0041" * (N // 6),
    "entities": "&#65;" * (N // 5), "zero-width": ZW * N, "fullwidth": "\uff21" * N, "brackets": "[" * N, "spaces": " " * N, "mixed separators": "1 - . / \n" * (N // 9),
    "credentials": "credentials: a / " * (N // 17), "url creds": "a://b:" * (N // 6), "mysql -p": "mysql -p" * (N // 8), "emoji": "\U0001f600" * (N // 2),
    "many cards": " ".join(groups(digits_of("card_visa", i), 4) for i in range(1, 2000)),
}


@pytest.mark.parametrize("label", sorted(HOSTILE))
def test_hostile_text_is_analysed_quickly(label):
    started = time.perf_counter()
    analyze_text(HOSTILE[label], SETTINGS)
    assert time.perf_counter() - started < 6.0, label


def test_thousands_of_matches_in_one_text_do_not_make_overlap_resolution_slow():
    text = "\n".join(fake("email", i) for i in range(20000))
    started = time.perf_counter()
    analyze_text(text, SETTINGS)
    assert time.perf_counter() - started < 6.0
