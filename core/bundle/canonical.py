"""Canonical form and hashing.

One document, one byte sequence, one hash. Two runs of the same toolchain
must produce files that are identical byte for byte, otherwise content
addressing is meaningless and nothing downstream can be trusted.

The rules, chosen so that a second implementation can be written from this
docstring alone:

* UTF-8, no byte-order mark, exactly one trailing newline at end of file.
* Object keys sorted by code point, no whitespace between tokens.
* **No JSON numbers anywhere.** Every quantity is a decimal string. This
  removes the entire class of questions about integer width, float
  formatting and exponent notation. A verifier never has to guess whether
  ``1e3`` and ``1000`` are the same value, because neither can occur.
* Allowed types: object, array, string, true, false, null. Nothing else.
* Keys are restricted to ``[A-Za-z0-9._:-]`` so no escaping can change the
  sort order.

Rejecting is the point. An encoder that quietly accepts a float has
already broken the hash.
"""

from __future__ import annotations

import hashlib
import json
import re

__all__ = [
    "CanonicalError",
    "encode",
    "digest",
    "digest_bytes",
    "as_int",
    "as_str",
    "check_shape",
    "HASH_PREFIX",
]

HASH_PREFIX = "sha256:"

_KEY_RE = re.compile(r"\A[A-Za-z0-9._:-]+\Z")
_DEC_RE = re.compile(r"\A(0|-?[1-9][0-9]*)\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class CanonicalError(ValueError):
    """The value cannot be represented in canonical form."""


def as_str(value: int) -> str:
    """Encode an integer as a canonical decimal string."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalError(f"expected int, got {type(value).__name__}")
    return str(value)


def as_int(value: str, *, field: str = "value") -> int:
    """Decode a canonical decimal string, rejecting anything sloppy.

    Leading zeros, plus signs, underscores and whitespace are all refused:
    they would let two different strings mean the same number, and then a
    document would have two valid encodings.
    """
    if not isinstance(value, str):
        raise CanonicalError(f"{field}: expected a decimal string")
    if not _DEC_RE.match(value):
        raise CanonicalError(f"{field}: not a canonical decimal string: {value!r}")
    return int(value)


def check_shape(obj: object, *, path: str = "$") -> None:
    """Walk a document and refuse anything the format does not allow."""
    if obj is None or isinstance(obj, bool) or isinstance(obj, str):
        return
    if isinstance(obj, (int, float)):
        raise CanonicalError(
            f"{path}: numbers are not allowed; encode quantities as strings"
        )
    if isinstance(obj, list):
        for index, item in enumerate(obj):
            check_shape(item, path=f"{path}[{index}]")
        return
    if isinstance(obj, dict):
        for key, item in obj.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            if not _KEY_RE.match(key):
                raise CanonicalError(f"{path}: key not allowed: {key!r}")
            check_shape(item, path=f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: type {type(obj).__name__} cannot be encoded")


def encode(obj: object) -> bytes:
    """Return the canonical byte encoding of a document."""
    check_shape(obj)
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def digest_bytes(data: bytes) -> str:
    """Hash raw canonical bytes."""
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def digest(obj: object) -> str:
    """Hash a document by way of its canonical encoding."""
    return digest_bytes(encode(obj))


def is_digest(value: object) -> bool:
    """Whether a value looks like one of our content addresses."""
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))
