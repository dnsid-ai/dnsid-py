"""Canonical JSON (JCS-style) serialization for C2SP entries.

Object members are sorted by UTF-16 code units (RFC 8785 §3.2.3) and strings
use minimal escaping so entry bytes are identical across SDKs.
"""

from __future__ import annotations

import json
import math
from typing import Any

from .errors import C2spTlogParseError

#: Largest integer representable exactly across SDKs (JS Number.MAX_SAFE_INTEGER).
_MAX_SAFE_INT = 9007199254740991


def canonical_json(value: object) -> str:
    """Serialize *value* to canonical JSON text."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        # JSON has no integer type: every number is an IEEE-754 double (RFC
        # 8785 / I-JSON), so an integer is canonicalized as the double it
        # denotes — this makes canonicalization idempotent (1e20's bytes
        # re-parse to a Python int that must produce the same string) and
        # keeps large integers JS-consistent (10**21 -> "1e+21", not a
        # 22-digit literal). Field-specific safe-integer bounds live in
        # event_codec, not here.
        try:
            as_double = float(value)
        except OverflowError:
            raise C2spTlogParseError("integer outside IEEE-754 double range") from None
        if int(as_double) != value:
            raise C2spTlogParseError(
                "integer is not exactly representable as an IEEE-754 double"
            )
        return _format_jcs_number(as_double)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise C2spTlogParseError("non-canonical JSON number")
        return _format_jcs_number(value)
    if isinstance(value, str):
        _assert_valid_unicode(value)
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        parts: list[str] = []
        for k in sorted(value.keys(), key=_utf16_sort_key):
            if not isinstance(k, str):
                raise C2spTlogParseError("JSON object keys must be strings")
            _assert_valid_unicode(k)
            v = value[k]
            parts.append(f"{json.dumps(k, ensure_ascii=False)}:{canonical_json(v)}")
        return "{" + ",".join(parts) + "}"
    raise C2spTlogParseError(f"unsupported JSON value: {type(value).__name__}")


def _format_jcs_number(value: float) -> str:
    """Serialize a finite float per RFC 8785 (ECMAScript Number::toString).

    Python's ``repr`` already yields the shortest digit string that
    round-trips the IEEE-754 double — the same digits ECMAScript uses — so
    only the formatting differs: ECMAScript switches to exponential notation
    outside 10**-6 .. 10**21 and writes exponents as ``e+21`` / ``e-7``,
    where Python would emit ``1e+21`` for fewer values and ``1e-06`` with
    zero padding.  This applies the ECMA-262 §6.1.6.1.20 cases directly.
    """
    if value == 0:
        return "0"  # covers -0.0: ECMAScript ToString(-0) is "0"
    sign = "-" if value < 0 else ""
    text = repr(abs(value))
    if "e" in text:
        mantissa, _, exp_text = text.partition("e")
        exponent = int(exp_text)
    else:
        mantissa, exponent = text, 0
    int_part, _, frac_part = mantissa.partition(".")
    all_digits = int_part + frac_part
    leading_zeros = len(all_digits) - len(all_digits.lstrip("0"))
    # value = 0.digits * 10**n with digits stripped of leading/trailing zeros
    n = len(int_part) + exponent - leading_zeros
    digits = all_digits.strip("0")
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    exp10 = n - 1
    exp_str = f"e+{exp10}" if exp10 >= 0 else f"e-{-exp10}"
    if k == 1:
        return sign + digits + exp_str
    return sign + digits[0] + "." + digits[1:] + exp_str


def canonical_bytes(value: object) -> bytes:
    """Serialize *value* to canonical JSON as UTF-8 bytes.

    Raises:
        C2spTlogParseError: If *value* cannot be canonically serialized (see
            :func:`canonical_json`).
    """
    return canonical_json(value).encode("utf-8")


def parse_json_no_duplicate_members(data: bytes) -> Any:
    """Parse JSON, rejecting duplicate object member names."""
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise C2spTlogParseError(f"entry is not valid UTF-8: {exc}") from exc

    def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise C2spTlogParseError(f"duplicate JSON member: {k}")
            out[k] = v
        return out

    try:
        return json.loads(text, object_pairs_hook=_no_dups)
    except C2spTlogParseError:
        raise
    except ValueError as exc:
        raise C2spTlogParseError(f"invalid JSON: {exc}") from exc


def assert_canonical_json_bytes(data: bytes, value: object | None = None) -> None:
    """Raise unless *data* is exactly the canonical serialization of its content."""
    parsed = parse_json_no_duplicate_members(data) if value is None else value
    got = data.decode("utf-8")
    want = canonical_json(parsed)
    if got != want:
        raise C2spTlogParseError("entry bytes are not canonical JCS")


def _utf16_sort_key(s: str) -> bytes:
    return s.encode("utf-16-be", errors="strict")


def _assert_valid_unicode(value: str) -> None:
    # Python strings may carry lone surrogates (e.g. via surrogatepass); they
    # are not valid JSON text.
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise C2spTlogParseError("JSON contains an unpaired surrogate") from exc
