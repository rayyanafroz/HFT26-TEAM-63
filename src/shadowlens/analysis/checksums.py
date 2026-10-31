"""Checksums that separate real-looking IDs from random digits (SOT 7.3, 8.1).

Bad input returns ``False`` and never raises. The ``*_check_digit`` builders are
used by ``fakes.py`` to generate values that pass these checks at runtime.
"""

from __future__ import annotations

import re

_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")

# Verhoeff tables: dihedral group multiplication, position permutation, inverse.
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def _is_digits(value: object) -> bool:
    # isascii: str.isdigit alone also accepts characters such as a superscript 2.
    return isinstance(value, str) and value.isascii() and value.isdigit()


# ---- Luhn (cards) -------------------------------------------------------------

def _luhn_sum(digits: str, double_first: bool) -> int:
    total = 0
    double = double_first
    for char in reversed(digits):
        digit = int(char)
        if double:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
        double = not double
    return total


def luhn_valid(digits: str) -> bool:
    if not _is_digits(digits) or len(digits) < 2:
        return False
    return _luhn_sum(digits, double_first=False) % 10 == 0


def luhn_check_digit(partial: str) -> str:
    """The digit to append to ``partial`` so the whole number passes Luhn."""
    if not _is_digits(partial):
        raise ValueError("partial must contain only digits")
    return str(-_luhn_sum(partial, double_first=True) % 10)


# ---- Verhoeff (Aadhaar) -------------------------------------------------------

def verhoeff_valid(digits: str) -> bool:
    if not _is_digits(digits) or len(digits) < 2:
        return False
    check = 0
    for index, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][int(char)]]
    return check == 0


def verhoeff_check_digit(partial: str) -> str:
    """The digit to append to ``partial`` so the whole number passes Verhoeff."""
    if not _is_digits(partial):
        raise ValueError("partial must contain only digits")
    check = 0
    for index, char in enumerate(reversed(partial)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[(index + 1) % 8][int(char)]]
    return str(_VERHOEFF_INV[check])


# ---- mod-97 (IBAN) ------------------------------------------------------------

def _mod97(text: str) -> int:
    # int(char, 36) maps 0-9 to themselves and A-Z to 10-35, as ISO 13616 requires.
    return int("".join(str(int(char, 36)) for char in text)) % 97


def iban_valid(text: str) -> bool:
    if not isinstance(text, str) or not _IBAN_RE.match(text):
        return False
    return _mod97(text[4:] + text[:4]) == 1


def iban_check_digits(country: str, bban: str) -> str:
    """The two check digits that go between ``country`` and ``bban``."""
    return f"{98 - _mod97(bban + country + '00'):02d}"
