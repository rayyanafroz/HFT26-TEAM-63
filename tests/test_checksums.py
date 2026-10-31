import pytest

from shadowlens.analysis.checksums import (
    iban_check_digits,
    iban_valid,
    luhn_check_digit,
    luhn_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)


def _with_one_digit_changed(value):
    """Every value made by changing exactly one digit of ``value``."""
    for index, char in enumerate(value):
        if char.isdigit():
            for other in "0123456789":
                if other != char:
                    yield value[:index] + other + value[index + 1:]


# ---- Luhn --------------------------------------------------------------------

def test_luhn_known_value():
    assert luhn_valid("79927398713")
    assert luhn_check_digit("7992739871") == "3"
    assert not luhn_valid("79927398710")


@pytest.mark.parametrize("partial", ["4" + "1" * 14, "51" + "0" * 13, "34" + "9" * 12, "0"])
def test_luhn_builder_round_trip(partial):
    full = partial + luhn_check_digit(partial)
    assert luhn_valid(full)
    assert not any(luhn_valid(changed) for changed in _with_one_digit_changed(full))


# ---- Verhoeff ----------------------------------------------------------------

def test_verhoeff_known_value():
    assert verhoeff_valid("2363")
    assert verhoeff_check_digit("236") == "3"
    assert not verhoeff_valid("2364")


@pytest.mark.parametrize("partial", ["23456789012", "98765432109", "20000000000", "5"])
def test_verhoeff_builder_round_trip(partial):
    full = partial + verhoeff_check_digit(partial)
    assert verhoeff_valid(full)
    assert not any(verhoeff_valid(changed) for changed in _with_one_digit_changed(full))


def test_verhoeff_catches_swapped_neighbours():
    partial = "23456789012"
    full = partial + verhoeff_check_digit(partial)
    for index in range(len(full) - 1):
        if full[index] != full[index + 1]:
            swapped = full[:index] + full[index + 1] + full[index] + full[index + 2:]
            assert not verhoeff_valid(swapped)


# ---- IBAN --------------------------------------------------------------------

def test_iban_builder_round_trip():
    bban = "ACME" + "12345678901234"
    full = "GB" + iban_check_digits("GB", bban) + bban
    assert iban_valid(full)
    assert not any(iban_valid(changed) for changed in _with_one_digit_changed(full))


def test_iban_check_digits_are_always_two_characters():
    for number in range(200):
        assert len(iban_check_digits("DE", f"{number:018d}")) == 2


# ---- bad input never raises --------------------------------------------------

@pytest.mark.parametrize("check", [luhn_valid, verhoeff_valid, iban_valid])
@pytest.mark.parametrize("bad", ["", "abc", "12 34", "12-34", "²²²", None, 1234])
def test_bad_input_returns_false(check, bad):
    assert check(bad) is False


def test_single_digit_is_not_valid():
    assert not luhn_valid("0")
    assert not verhoeff_valid("0")
