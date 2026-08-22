"""Reproducing curve parameters from a published seed.

A curve is called verifiably random when its coefficient b is derived from
a seed by a documented procedure, so that nobody could have quietly gone
looking for a curve with a weakness only they knew about. Checking that
claim means running the procedure and seeing the published b come back.

The procedure below is the one in ANSI X9.62, also given as A.1.3 in FIPS
186-4. With t the bit length of p, s = (t - 1) // 160 and h = t - 160s:

    H  = SHA-1(seed), and c0 is the rightmost h bits of H with its
         leftmost bit cleared
    Wi = SHA-1((seed + i) mod 2^g) for i = 1..s
    c  = c0 || W1 || ... || Ws, read as an integer

and the curve satisfies the relation c * b^2 = -27 (mod p).

SHA-1 is broken for collisions, and that is not a problem here. Nothing in
this check depends on the difficulty of finding two inputs with the same
hash: it reproduces one published derivation from one published seed. A
reader who flinches at seeing SHA-1 in 2026 is right to look twice, and
right to conclude it is harmless in this one use.

Note what the check does and does not establish. It shows the parameters
follow from the seed. It says nothing about where the seed came from, and
a seed can itself be searched for. Quantifying that freedom is a separate
question, and the one the constants registry is meant to answer.
"""

from __future__ import annotations

import hashlib

__all__ = ["derive_c", "relation_holds", "METHOD"]

METHOD = "ansi-x9.62-sha1"


def derive_c(seed: bytes, p: int) -> int:
    """Run the seed through the derivation and return the integer c."""
    if not seed:
        raise ValueError("the seed is empty")
    bits = len(seed) * 8
    if bits < 160:
        raise ValueError("the standard requires a seed of at least 160 bits")

    length = p.bit_length()
    blocks = (length - 1) // 160
    remainder = length - 160 * blocks

    digest = int.from_bytes(hashlib.sha1(seed).digest(), "big")
    c0 = digest & ((1 << remainder) - 1)
    c0 &= ~(1 << (remainder - 1))  # the leftmost bit of c0 is cleared

    value = c0
    base = int.from_bytes(seed, "big")
    for index in range(1, blocks + 1):
        stepped = (base + index) % (1 << bits)
        word = hashlib.sha1(stepped.to_bytes(bits // 8, "big")).digest()
        value = (value << 160) | int.from_bytes(word, "big")
    return value


def relation_holds(c: int, b: int, p: int) -> bool:
    """Whether c * b^2 = -27 (mod p), the relation the standard imposes."""
    return (c * b * b) % p == (-27) % p
