"""A plain view of text for detection, with an exact way back to the original (SOT 7.3).

Anyone can dress a secret up so a pattern does not recognize it: fullwidth letters, zero-width characters
inside the key, look-alike letters from another alphabet, or ``\\u0073``, ``%73`` and ``&#115;`` written
for ``s``. The person's AI tool still reads it as the key. ``fold`` writes the text the way a reader would
see it, and remembers where every character came from, so a match in the view can be redacted in the
original text, character for character.

This is only a view for detection. The text that is stored, redacted or sent is always the original.
"""

from __future__ import annotations

import re
import unicodedata

# Anything that may need changing: an escape sequence, a non-ASCII character or an ASCII control character.
_INTERESTING = re.compile(
    r"\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}|&#(?:[xX][0-9a-fA-F]{1,6}|\d{1,7});|[^\x00-\x7f]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)
_KEEP_CONTROL = "\t\n\r"
_DROPPED_CATEGORIES = frozenset({"Cf", "Mn", "Me", "Cc", "Cs", "Co"})   # invisible, joiners, combining, control

# Dashes and minus signs that NFKC leaves alone but a reader sees as "-".
_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"), "-")
# Look-alikes from other alphabets (Cyrillic, Greek) for ASCII letters. Only letters that really are
# written the same: this is not a translation table.
_LOOKALIKES = dict(zip(
    map(ord, "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u0455\u0501\u0261\u0410\u0412\u0415\u041a"
             "\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406\u0408\u0405\u03bf\u03b1\u03b5\u03b9\u03bd\u03c1"
             "\u0391\u0392\u0395\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a7\u0417"),
    "aeopcxyijsdgABEKMHOPCTXIJSoaeivpABEHIKMNOPTX3",
))


def _clean_char(ch: str) -> str:
    """What a reader sees for one character: compatibility form, plain dash, plain letter, or nothing."""
    if ch in _KEEP_CONTROL:
        return ch
    out = []
    for piece in unicodedata.normalize("NFKC", ch):
        if unicodedata.category(piece) in _DROPPED_CATEGORIES and piece not in _KEEP_CONTROL:
            continue
        out.append(piece.translate(_DASHES).translate(_LOOKALIKES))
    return "".join(out)


def _decode(raw: str) -> str:
    """The character an escape stands for. Unknown or unprintable escapes stay as written."""
    if raw.startswith("\\u"):
        code = int(raw[2:], 16)
    elif raw.startswith("%"):
        code = int(raw[1:], 16)
        if not 0x20 <= code < 0x7F:
            return raw                                   # a %XX byte that is not plain text: leave it
    elif raw.startswith("&#"):
        body = raw[2:-1]
        code = int(body[1:], 16) if body[:1] in "xX" else int(body)
    else:
        return raw
    if 0xD800 <= code <= 0xDFFF or code > 0x10FFFF:
        return ""
    return chr(code)


def fold(text: str) -> tuple[str, list[int] | None, list[int] | None]:
    """``(view, starts, ends)``. ``starts[i]``/``ends[i]`` are where view character ``i`` begins and ends in
    ``text``. Plain ASCII text with no escapes comes back unchanged with ``None`` for both lists."""
    if text.isascii() and _INTERESTING.search(text) is None:
        return text, None, None
    parts: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    position = 0
    for match in _INTERESTING.finditer(text):
        if match.start() > position:
            parts.append(text[position:match.start()])
            starts.extend(range(position, match.start()))
            ends.extend(range(position + 1, match.start() + 1))
        raw = match.group(0)
        cleaned = "".join(_clean_char(c) for c in (_decode(raw) if raw[0] in "\\%&" else raw))
        parts.append(cleaned)
        starts.extend([match.start()] * len(cleaned))
        ends.extend([match.end()] * len(cleaned))
        position = match.end()
    if position < len(text):
        parts.append(text[position:])
        starts.extend(range(position, len(text)))
        ends.extend(range(position + 1, len(text) + 1))
    return "".join(parts), starts, ends


def to_original(start: int, end: int, starts: list[int] | None, ends: list[int] | None) -> tuple[int, int]:
    """A span in the view as a span in the original text."""
    if starts is None or ends is None or end <= start:
        return start, end
    return starts[start], ends[end - 1]


_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_ESCAPES = re.compile(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{4}|[0-7]{1,3}|[abefnrtv\\'\"])")
_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"'}


def _ansi_c(match: re.Match[str]) -> str:
    """The text of a bash ``$'...'`` string with its escapes resolved."""
    def one(escape: re.Match[str]) -> str:
        code = escape.group(1)
        if code[0] in "xu":
            return chr(int(code[1:], 16))
        if code[0] in "01234567":
            return chr(int(code, 8) & 0xFF)
        return _SIMPLE.get(code, code)
    return _ESCAPES.sub(one, match.group(1))


def deobfuscate_command(command: str) -> str:
    """A shell command written the way the shell will read it, for rule matching only.

    Undoes the usual disguises: empty quotes inside a word (``r''m``), a backslash before a letter
    (``\\rm``, ``r\\m``), ``${IFS}`` standing for a space, and uncommon spacing and Unicode.
    """
    view, _, _ = fold(command)
    view = _ANSI_C.sub(_ansi_c, view)                                  # $'\x72\x6d' is rm
    view = re.sub(r"\{([^{}\s,]+(?:,[^{}\s,]+)+)\}", lambda m: m.group(1).replace(",", " "), view)   # {rm,-rf,/}
    view = re.sub(r"[\"']\s*,\s*[\"']", " ", view)                    # ["rm", "-rf", "/"] is rm -rf /
    view = re.sub(r"\$\{IFS[^}]*\}|\$IFS\b", " ", view)
    view = re.sub(r"(?<=[A-Za-z0-9_])(?:''|\"\")(?=[A-Za-z0-9_])", "", view)
    view = re.sub(r"(?<=[A-Za-z])\\(?=[A-Za-z])", "", view)           # r\m
    view = re.sub(r"(?<![\\\w:])\\(?=[A-Za-z])", "", view)           # \rm at the start of a word
    return re.sub(r"[ \t]+", " ", view)
