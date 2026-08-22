"""Arithmetic in F_p^2 and on curves defined over it.

Written in plain Python on purpose. The producer must be able to check a
witness *itself*: asking gp whether a point really has the order gp just
told us would make the evidence circular. Everything here is therefore
independent of the backend, and the Rust verifier will mirror it.

Three decisions are load-bearing.

**Elements are bare tuples.** An element of F_p^2 is ``(c0, c1)``, meaning
``c0 + c1*u``. No wrapper object, no operator overloading. Tuples are
cheap, hashable, and serialise to canonical strings without a translation
layer. The field object carries p and the modulus; the elements carry
nothing, so an element can never disagree with its field about which field
it is in.

**The extension is ``u^2 = beta``, with beta in F_p.** That covers every
pairing-friendly curve in scope, and it keeps multiplication to three
integer multiplications instead of a general polynomial routine. A field
that needs a different shape is a different class, not a flag here.

**Nothing is constant-time.** This is a producer. It handles published
parameters, never a secret, and a certificate is a public document. Adding
constant-time discipline here would suggest this code is safe to reuse in
a signing path, which it is not.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "Fp2",
    "CurveFp2",
    "Fp2Error",
]


class Fp2Error(ValueError):
    """The field, the curve, or a point is not what it claims to be."""


# An element of F_p^2 as a pair of residues: c0 + c1*u.
Element = tuple[int, int]

# A point in affine coordinates, or None for the point at infinity.
Point = tuple[Element, Element] | None


@dataclass(frozen=True)
class Fp2:
    """The field F_p[u] / (u^2 - beta).

    ``beta`` must be a quadratic non-residue mod p, otherwise the quotient
    is not a field and every result below is meaningless. The check runs
    once, at construction, because getting it wrong silently is the worst
    outcome available here.
    """

    p: int
    beta: int

    def __post_init__(self) -> None:
        if self.p < 5:
            raise Fp2Error("this module expects a prime p > 3")
        if self.p % 2 == 0:
            raise Fp2Error("p must be odd")
        beta = self.beta % self.p
        if beta == 0:
            raise Fp2Error("beta must be non-zero")
        # Euler's criterion. A residue would make u^2 - beta reducible.
        if pow(beta, (self.p - 1) // 2, self.p) != self.p - 1:
            raise Fp2Error(
                "beta is a quadratic residue mod p, so u^2 - beta factors "
                "and the quotient is not a field"
            )
        object.__setattr__(self, "beta", beta)

    # -- shape -------------------------------------------------------

    @property
    def degree(self) -> int:
        return 2

    @property
    def q(self) -> int:
        """The number of elements."""
        return self.p * self.p

    def hasse_window(self) -> tuple[int, int]:
        """Bounds on the order of a curve over this field, inclusive.

        Exact, with nothing widened: q is p squared, so its square root is
        p on the nose. Over a prime field the same expression needs a slack
        term because the root is not an integer; here it does not.
        """
        q = self.q
        return q + 1 - 2 * self.p, q + 1 + 2 * self.p

    def coefficients(self, a: Element) -> tuple[int, ...]:
        return (a[0], a[1])

    # -- constants ---------------------------------------------------

    @property
    def zero(self) -> Element:
        return (0, 0)

    @property
    def one(self) -> Element:
        return (1, 0)

    def element(self, c0: int, c1: int = 0) -> Element:
        """Reduce a pair into the field."""
        return (c0 % self.p, c1 % self.p)

    def is_zero(self, a: Element) -> bool:
        return a[0] == 0 and a[1] == 0

    # -- ring operations ---------------------------------------------

    def add(self, a: Element, b: Element) -> Element:
        return ((a[0] + b[0]) % self.p, (a[1] + b[1]) % self.p)

    def sub(self, a: Element, b: Element) -> Element:
        return ((a[0] - b[0]) % self.p, (a[1] - b[1]) % self.p)

    def neg(self, a: Element) -> Element:
        return ((-a[0]) % self.p, (-a[1]) % self.p)

    def mul(self, a: Element, b: Element) -> Element:
        """(a0 + a1 u)(b0 + b1 u) = a0b0 + beta a1b1 + (a0b1 + a1b0) u."""
        p = self.p
        a0, a1 = a
        b0, b1 = b
        t0 = a0 * b0
        t1 = a1 * b1
        # One fewer multiplication than the obvious form, and the saving is
        # real: this runs inside a double-and-add over a 380-bit scalar.
        cross = (a0 + a1) * (b0 + b1) - t0 - t1
        return ((t0 + self.beta * t1) % p, cross % p)

    def scale(self, a: Element, k: int) -> Element:
        """Multiply by an integer, which stays in the base field."""
        k %= self.p
        return ((a[0] * k) % self.p, (a[1] * k) % self.p)

    def square(self, a: Element) -> Element:
        p = self.p
        a0, a1 = a
        return (
            (a0 * a0 + self.beta * a1 * a1) % p,
            (2 * a0 * a1) % p,
        )

    def norm(self, a: Element) -> int:
        """a * conjugate(a), an element of the base field."""
        return (a[0] * a[0] - self.beta * a[1] * a[1]) % self.p

    def conjugate(self, a: Element) -> Element:
        """The non-trivial Galois conjugate: a0 - a1 u, which is a^p."""
        return (a[0], (-a[1]) % self.p)

    def inv(self, a: Element) -> Element:
        """Inverse via the norm: a^-1 = conjugate(a) / norm(a)."""
        if self.is_zero(a):
            raise Fp2Error("zero has no inverse")
        n = self.norm(a)
        if n == 0:  # impossible while beta is a non-residue; kept as a tripwire
            raise Fp2Error("norm vanished on a non-zero element")
        n_inv = pow(n, -1, self.p)
        return self.scale(self.conjugate(a), n_inv)

    def div(self, a: Element, b: Element) -> Element:
        return self.mul(a, self.inv(b))

    def pow(self, a: Element, exponent: int) -> Element:
        if exponent < 0:
            return self.pow(self.inv(a), -exponent)
        result = self.one
        base = a
        while exponent:
            if exponent & 1:
                result = self.mul(result, base)
            base = self.square(base)
            exponent >>= 1
        return result


@dataclass(frozen=True)
class CurveFp2:
    """y^2 = x^3 + a x + b over F_p^2, in affine coordinates.

    Affine rather than projective, and deliberately: a certificate records
    a point as two field elements, so the producer works in the same
    representation the document uses. Inversions cost more, but this runs
    a handful of times per bundle, not in a loop that matters.
    """

    field: Fp2
    a: Element
    b: Element

    def __post_init__(self) -> None:
        f = self.field
        # 4a^3 + 27b^2 must not vanish, or the curve is singular and the
        # points do not form a group.
        a3 = f.mul(f.square(self.a), self.a)
        disc = f.add(f.scale(a3, 4), f.scale(f.square(self.b), 27))
        if f.is_zero(disc):
            raise Fp2Error("the curve is singular: 4a^3 + 27b^2 vanishes")

    def is_on_curve(self, point: Point) -> bool:
        if point is None:
            return True
        f = self.field
        x, y = point
        left = f.square(y)
        right = f.add(f.add(f.mul(f.square(x), x), f.mul(self.a, x)), self.b)
        return left == right

    def require_on_curve(self, point: Point) -> None:
        if not self.is_on_curve(point):
            raise Fp2Error("the point does not satisfy the curve equation")

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
            # Either P + (-P), or a 2-torsion point doubling to infinity.
            return None
        slope = f.div(f.sub(y2, y1), f.sub(x2, x1))
        x3 = f.sub(f.sub(f.square(slope), x1), x2)
        y3 = f.sub(f.mul(slope, f.sub(x1, x3)), y1)
        return (x3, y3)

    def double(self, point: Point) -> Point:
        if point is None:
            return None
        f = self.field
        x, y = point
        if f.is_zero(y):
            return None
        num = f.add(f.scale(f.square(x), 3), self.a)
        slope = f.div(num, f.scale(y, 2))
        x3 = f.sub(f.square(slope), f.scale(x, 2))
        y3 = f.sub(f.mul(slope, f.sub(x, x3)), y)
        return (x3, y3)

    def multiply(self, point: Point, scalar: int) -> Point:
        """Double-and-add. Not constant-time; see the module docstring."""
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
        """A y with y^2 = x^3 + ax + b, or None if x is not an abscissa.

        Of the two roots the one with the smaller (c1, c0) is returned, so
        the choice is a function of x alone. A random pick would be just as
        correct mathematically and would change the bundle hash on every
        run, which costs more than it gains.
        """
        f = self.field
        rhs = f.add(f.add(f.mul(f.square(x), x), f.mul(self.a, x)), self.b)
        y = self._sqrt(rhs)
        if y is None:
            return None
        other = f.neg(y)
        return min(y, other, key=lambda e: (e[1], e[0]))

    def _sqrt(self, value: Element) -> Element | None:
        """Square root in F_p^2, or None.

        The norm map sends squares to squares, so a candidate root is built
        from a base-field square root of the norm. Whatever comes out is
        squared and compared before it is returned: a wrong root would
        otherwise produce a point that is not on the curve, and the whole
        argument would rest on it.
        """
        f = self.field
        if f.is_zero(value):
            return f.zero
        p = f.p
        # Handle the base-field case directly; it is the common one for the
        # abscissas we search.
        if value[1] == 0:
            root = _sqrt_fp(value[0], p)
            if root is not None:
                candidate = (root, 0)
                if f.square(candidate) == value:
                    return candidate
            # value = c0 with c0 a non-residue, so c0 = beta * (c0/beta) and
            # the root lives on the u axis.
            quotient = (value[0] * pow(f.beta, -1, p)) % p
            root = _sqrt_fp(quotient, p)
            if root is None:
                return None
            candidate = (0, root)
            return candidate if f.square(candidate) == value else None

        norm = f.norm(value)
        n_root = _sqrt_fp(norm, p)
        if n_root is None:
            return None
        inv_two = pow(2, -1, p)
        for sign_root in (n_root, (-n_root) % p):
            half = ((value[0] + sign_root) * inv_two) % p
            c0 = _sqrt_fp(half, p)
            if c0 is None or c0 == 0:
                continue
            c1 = (value[1] * pow(2 * c0, -1, p)) % p
            candidate = (c0, c1)
            if f.square(candidate) == value:
                return candidate
        return None

    def first_point(self, limit: int = 10_000) -> Point:
        """The point with the smallest abscissa the search finds.

        Abscissas are tried in a fixed order, so two independent runs pick
        the same point and the bundle hashes identically.
        """
        f = self.field
        for c1 in range(limit):
            for c0 in range(limit):
                if c0 == 0 and c1 == 0:
                    continue
                x = f.element(c0, c1)
                y = self.ordinate(x)
                if y is not None:
                    point = (x, y)
                    self.require_on_curve(point)
                    return point
        raise Fp2Error("no point found in the searched range")


def _sqrt_fp(value: int, p: int) -> int | None:
    """Square root modulo a prime p, or None. Tonelli-Shanks.

    The smaller of the two roots is returned so the result is a function of
    the input alone.
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
