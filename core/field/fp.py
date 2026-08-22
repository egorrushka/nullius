"""Arithmetic in F_p and on curves over it.

A deliberate mirror of :mod:`core.field.fp2`, method for method. The
point-order evidence covers curves over both fields, and it does so by
asking the field what shape it is rather than by branching on it. Two
classes with one interface cost a little repetition and save every caller
from an ``if degree == 1`` that would otherwise spread through the
producer.

Elements are one-tuples rather than bare integers, again for the sake of
that shared interface: a coefficient list of length one serialises the
same way a list of length two does, so the certificate carries the same
shape at either degree and the verifier reads it with the same code.

Nothing here is constant-time. This is a producer working on published
parameters; see the note in the F_p^2 module.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isqrt

__all__ = ["Fp", "CurveFp", "FpError"]


class FpError(ValueError):
    """The field, the curve, or a point is not what it claims to be."""


# An element as a one-tuple, so it matches the F_p^2 representation.
Element = tuple[int]

Point = tuple[Element, Element] | None


@dataclass(frozen=True)
class Fp:
    """The field of integers modulo a prime p."""

    p: int

    def __post_init__(self) -> None:
        if self.p < 5:
            raise FpError("this module expects a prime p > 3")
        if self.p % 2 == 0:
            raise FpError("p must be odd")

    # -- shape -------------------------------------------------------

    @property
    def degree(self) -> int:
        return 1

    @property
    def q(self) -> int:
        return self.p

    def hasse_window(self) -> tuple[int, int]:
        """Bounds on the order of a curve over F_p, inclusive.

        The square root of p is not an integer, so an integer square root
        is taken and the result widened by one on each side. Widening is
        the safe direction: a window one wider can only refuse to pin an
        order that a tighter window would have pinned, never pin a wrong
        one.
        """
        root = isqrt(4 * self.p)
        return self.p + 1 - root - 1, self.p + 1 + root + 1

    def coefficients(self, a: Element) -> tuple[int, ...]:
        return (a[0],)

    # -- constants ---------------------------------------------------

    @property
    def zero(self) -> Element:
        return (0,)

    @property
    def one(self) -> Element:
        return (1,)

    def element(self, c0: int, *rest: int) -> Element:
        """Reduce into the field. Extra coefficients must be zero."""
        for extra in rest:
            if extra % self.p != 0:
                raise FpError("a prime field has no second coefficient")
        return (c0 % self.p,)

    def is_zero(self, a: Element) -> bool:
        return a[0] == 0

    # -- ring operations ---------------------------------------------

    def add(self, a: Element, b: Element) -> Element:
        return ((a[0] + b[0]) % self.p,)

    def sub(self, a: Element, b: Element) -> Element:
        return ((a[0] - b[0]) % self.p,)

    def neg(self, a: Element) -> Element:
        return ((-a[0]) % self.p,)

    def mul(self, a: Element, b: Element) -> Element:
        return ((a[0] * b[0]) % self.p,)

    def scale(self, a: Element, k: int) -> Element:
        return ((a[0] * k) % self.p,)

    def square(self, a: Element) -> Element:
        return ((a[0] * a[0]) % self.p,)

    def inv(self, a: Element) -> Element:
        if self.is_zero(a):
            raise FpError("zero has no inverse")
        return (pow(a[0], -1, self.p),)

    def div(self, a: Element, b: Element) -> Element:
        return self.mul(a, self.inv(b))

    def pow(self, a: Element, exponent: int) -> Element:
        if exponent < 0:
            return self.pow(self.inv(a), -exponent)
        return (pow(a[0], exponent, self.p),)


@dataclass(frozen=True)
class CurveFp:
    """y^2 = x^3 + a x + b over F_p, in affine coordinates."""

    field: Fp
    a: Element
    b: Element

    def __post_init__(self) -> None:
        f = self.field
        a3 = f.mul(f.square(self.a), self.a)
        disc = f.add(f.scale(a3, 4), f.scale(f.square(self.b), 27))
        if f.is_zero(disc):
            raise FpError("the curve is singular: 4a^3 + 27b^2 vanishes")

    def is_on_curve(self, point: Point) -> bool:
        if point is None:
            return True
        f = self.field
        x, y = point
        right = f.add(f.add(f.mul(f.square(x), x), f.mul(self.a, x)), self.b)
        return f.square(y) == right

    def require_on_curve(self, point: Point) -> None:
        if not self.is_on_curve(point):
            raise FpError("the point does not satisfy the curve equation")

    # -- group law ---------------------------------------------------

    def negate(self, point: Point) -> Point:
        if point is None:
            return None
        x, y = point
        return (x, self.field.neg(y))

    def add(self, p1: Point, p2: Point) -> Point:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        f = self.field
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2:
            if y1 == y2 and not f.is_zero(y1):
                return self.double(p1)
            return None
        slope = f.div(f.sub(y2, y1), f.sub(x2, x1))
        x3 = f.sub(f.sub(f.square(slope), x1), x2)
        return (x3, f.sub(f.mul(slope, f.sub(x1, x3)), y1))

    def double(self, point: Point) -> Point:
        if point is None:
            return None
        f = self.field
        x, y = point
        if f.is_zero(y):
            return None
        slope = f.div(f.add(f.scale(f.square(x), 3), self.a), f.scale(y, 2))
        x3 = f.sub(f.square(slope), f.scale(x, 2))
        return (x3, f.sub(f.mul(slope, f.sub(x, x3)), y))

    def multiply(self, point: Point, scalar: int) -> Point:
        if scalar < 0:
            return self.multiply(self.negate(point), -scalar)
        result: Point = None
        addend = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            scalar >>= 1
        return result

    # -- points ------------------------------------------------------

    def ordinate(self, x: Element) -> Element | None:
        """The smaller of the two ordinates at x, or None.

        A function of x alone, so two runs pick the same point and the
        bundle hashes identically.
        """
        f = self.field
        rhs = f.add(f.add(f.mul(f.square(x), x), f.mul(self.a, x)), self.b)
        root = _sqrt_fp(rhs[0], f.p)
        return None if root is None else (root,)

    def first_point(self, limit: int = 10_000) -> Point:
        f = self.field
        for c0 in range(1, limit):
            x = f.element(c0)
            y = self.ordinate(x)
            if y is not None:
                point = (x, y)
                self.require_on_curve(point)
                return point
        raise FpError("no point found in the searched range")


def _sqrt_fp(value: int, p: int) -> int | None:
    """Square root modulo a prime, or None. Tonelli-Shanks.

    The smaller root is returned so the result is a function of the input.
    """
    value %= p
    if value == 0:
        return 0
    if pow(value, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        root = pow(value, (p + 1) // 4, p)
        return min(root, p - root)

    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m, c = s, pow(z, q, p)
    t, root = pow(value, q, p), pow(value, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = (t2 * t2) % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, (b * b) % p
        t = (t * c) % p
        root = (root * b) % p
    return min(root, p - root)
