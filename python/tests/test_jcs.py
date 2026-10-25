import json
import random
import struct

import pytest
import rfc8785

from veritaschain_vcp.jcs import CanonicalizationError, canonicalize, canonicalize_str, format_number


def f64(hex_bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(hex_bits))[0]


# RFC 8785 Appendix B
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits,expected", APPENDIX_B)
def test_appendix_b_numbers(bits, expected):
    assert format_number(f64(bits), strict=True) == expected


@pytest.mark.parametrize("bits", ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"])
def test_non_finite_rejected(bits):
    with pytest.raises(CanonicalizationError):
        format_number(f64(bits))


def test_rfc8785_section_3_2_4_example():
    src = (
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonicalize_str(json.loads(src)) == expected


def test_rfc8785_sorting_example():
    obj = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001F600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    keys = list(json.loads(canonicalize_str(obj)).keys())
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"]


def test_integers():
    assert format_number(0) == "0"
    assert format_number(-7) == "-7"
    assert format_number(2**53) == "9007199254740992"
    # default: exact digits for every integer, so different integers never collide
    assert format_number(2**60) == "1152921504606846976"
    assert format_number(1791504000123456768) == "1791504000123456768"
    assert format_number(1791504000123456800) == "1791504000123456800"
    assert format_number(-(2**63)) == "-9223372036854775808"
    assert format_number(10**21) == "1000000000000000000000"
    # strict: RFC 8785 applied to integers
    assert format_number(2**60, strict=True) == "1152921504606847000"
    assert format_number(1791504000123456768, strict=True) == "1791504000123456800"
    assert format_number(10**21, strict=True) == "1e+21"
    with pytest.raises(CanonicalizationError):
        format_number(1791504000123456800, strict=True)
    with pytest.raises(CanonicalizationError):
        format_number(10**400, strict=True)
    with pytest.raises(TypeError):
        format_number(True)


def test_ambiguous_floats():
    # an integral float of magnitude in [2**53, 1e21) would print like a different integer
    for x in (2.0**53, 1.8e18, -1.791504000123456768e18, 9.99e20):
        with pytest.raises(CanonicalizationError):
            format_number(x)
    assert format_number(1.8e18, strict=True) == "1800000000000000000"
    assert format_number(2.0**53 - 1) == "9007199254740991"
    assert format_number(1e21) == "1e+21"
    assert format_number(1.5) == "1.5"


def test_injective_on_integers_near_2_60():
    import random

    rng = random.Random(1)
    seen = {}
    for _ in range(20000):
        n = 1791504000000000000 + rng.randrange(10**12)
        s = format_number(n)
        assert seen.setdefault(s, n) == n


def test_depth_limit():
    v = []
    for _ in range(127):
        v = [v]
    canonicalize_str(v)  # 128 levels
    with pytest.raises(CanonicalizationError):
        canonicalize_str([v])


def test_strings_and_rejections():
    assert canonicalize_str("\u007f ") == '"\u007f "'
    assert canonicalize_str("\x01\x1f") == '"\\u0001\\u001f"'
    with pytest.raises(CanonicalizationError):
        canonicalize_str("\ud800")
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "x"})
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": object()})


def _random_value(rng: random.Random, depth: int = 0):
    r = rng.random()
    if depth > 3 or r < 0.3:
        choice = rng.randrange(6)
        if choice == 0:
            return rng.randrange(-(2**53) + 1, 2**53)
        if choice == 1:
            while True:
                x = f64(rng.getrandbits(64).to_bytes(8, "big").hex())
                if x == x and abs(x) != float("inf"):
                    return x
        if choice == 2:
            return "".join(chr(rng.choice([rng.randrange(0x20, 0x7F), rng.randrange(0, 0x20), rng.randrange(0xA0, 0xD7FF), rng.randrange(0x10000, 0x10FFFF)])) for _ in range(rng.randrange(8)))
        return [None, True, False][choice - 3]
    if r < 0.65:
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(5))]
    return {
        "".join(chr(rng.choice([rng.randrange(0x20, 0x7F), rng.randrange(0x80, 0xD800), rng.randrange(0xE000, 0x10000), rng.randrange(0x10000, 0x110000)])) for _ in range(rng.randrange(1, 5))): _random_value(rng, depth + 1)
        for _ in range(rng.randrange(5))
    }


def test_matches_rfc8785_reference_library():
    """Strict mode is RFC 8785: cross-check against the independent rfc8785 package (Trail of Bits).

    The default mode differs only for integers above 2**53 and for integral
    floats of magnitude 2**53 or more; the random values here are within the
    range where both modes and rfc8785 must agree, plus arbitrary floats.
    """
    rng = random.Random(8785)
    for _ in range(3000):
        v = _random_value(rng)
        assert canonicalize(v, strict=True) == rfc8785.dumps(v)
        try:
            assert canonicalize(v) == rfc8785.dumps(v)
        except CanonicalizationError:
            pass  # an integral float >= 2**53 somewhere in v
