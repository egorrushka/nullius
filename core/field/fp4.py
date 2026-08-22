"""Arithmetic over `F_p^4`, built as a tower on `F_p^2`.

BLS24 and KSS16 put their second group over a degree-4 extension, and
with them the 192-bit level and the conservative alternatives the
literature has recommended since the tower sieve. Everything below exists
to make those curves reachable.

**Why a tower and not a quartic.** `F_p^4` could be written directly as
`F_p[w]/(f)` for an irreducible quartic, and then every multiplication
would be a four-by-four convolution reduced modulo `f`. Building it as
`F_p^2[v]/(v^2 - xi)` instead means the multiplication is the same
two-term formula `fp2` already uses, over a coefficient ring that happens
to be `F_p^2` rather than `F_p`. One formula, written once, applied twice.
That is worth more than the arithmetic it saves: a quartic reduction is a
place to make a mistake that nothing else in the file would catch.

The element layout follows from the same choice. An element is a pair of
`F_p^2` elements, so its coefficient list is four integers in the order
`(c0.c0, c0.c1, c1.c0, c1.c1)` — the flattening a certificate carries, and
the order a second implementation has to agree with.

**What must be checked and is.** `xi` has to be a non-residue *in
`F_p^2`*, not merely in `F_p`; the criterion is `xi^((p^2-1)/2) != 1`, and
a residue there makes the quotient a ring with zero divisors in which
every conclusion drawn is void. The Hasse window is exact at this degree:
`q = p^4` and `sqrt(q) = p^2` with nothing widened, which is the same
piece of luck that makes degree 2 tight and degree 3 not.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.field.fp2 import Element as Fp2Element, Fp2

__all__ = ["Fp4", "Fp4Error", "CurveFp4", "Element", "Point"]

# `c0 + c1*v`, each coefficient an element of F_p^2.
Element = tuple[Fp2Element, Fp2Element]
Point = tuple[Element, Element] | None


class Fp4Error(ValueError):
    """The parameters do not describe a field of degree four."""


@dataclass(frozen=True)
class Fp4:
    """`F_p^2[v] / (v^2 - xi)`, with `F_p^2 = F_p[u] / (u^2 - beta)`."""

    p: int
    beta: int
    xi: tuple[int, int]

    def __post_init__(self) -> None:
        base = Fp2(self.p, self.beta)
        object.__setattr__(self, "_base", base)
        element = base.element(*self.xi)
        if base.is_zero(element):
            raise Fp4Error("xi must be non-zero")
        # Euler's criterion in F_p^2, not in F_p. An xi that is a square
        # here makes v^2 - xi reducible, the quotient a ring with zero
        # divisors, and every order computed in it meaningless.
        if base.pow(element, (self.p * self.p - 1) // 2) == base.one:
            raise Fp4Error(
                "xi is a square in F_p^2, so the quotient is not a field"
            )
        object.__setattr__(self, "_xi", element)

    @property
    def base(self) -> Fp2:
        return self._base  # type: ignore[attr-defined]

    @property
    def degree(self) -> int:
        return 4

    @property
    def q(self) -> int:
        return self.p**4

    def hasse_window(self) -> tuple[int, int]:
        """Bounds on the order of a curve over this field, inclusive.

        Exact, with nothing widened: `sqrt(p^4)` is `p^2` on the nose. The
        window is `q + 1 -+ 2p^2`, and it is about `2^631` wide for a
        315-bit p — which is why the witness argument cannot reach these
        curves and elimination can.
        """
        spread = 2 * self.p * self.p
        return self.q + 1 - spread, self.q + 1 + spread

    # -- construction --------------------------------------------------

    def element(self, *coefficients: int) -> Element:
        """An element from four integers, low order first.

        The flattening is part of the format: `(c0.c0, c0.c1, c1.c0,
        c1.c1)`. Fewer coefficients are padded with zeros so that
        `element(7)` is seven, which keeps small constants readable.
        """
        if len(coefficients) > 4:
            raise Fp4Error("a degree 4 element has at most four coefficients")
        padded = list(coefficients) + [0] * (4 - len(coefficients))
        base = self.base
        return (base.element(padded[0], padded[1]), base.element(padded[2], padded[3]))

    def coefficients(self, a: Element) -> tuple[int, ...]:
        base = self.base
        return base.coefficients(a[0]) + base.coefficients(a[1])

    @property
    def zero(self) -> Element:
        return (self.base.zero, self.base.zero)

    @property
    def one(self) -> Element:
        return (self.base.one, self.base.zero)

    def is_zero(self, a: Element) -> bool:
        return self.base.is_zero(a[0]) and self.base.is_zero(a[1])

    # -- arithmetic ----------------------------------------------------

    def add(self, a: Element, b: Element) -> Element:
        base = self.base
        return (base.add(a[0], b[0]), base.add(a[1], b[1]))

    def sub(self, a: Element, b: Element) -> Element:
        base = self.base
        return (base.sub(a[0], b[0]), base.sub(a[1], b[1]))

    def neg(self, a: Element) -> Element:
        base = self.base
        return (base.neg(a[0]), base.neg(a[1]))

    def mul(self, a: Element, b: Element) -> Element:
        """`(a0 + a1 v)(b0 + b1 v) = a0b0 + xi a1b1 + (a0b1 + a1b0) v`.

        The same shape as the degree-2 formula, over `F_p^2` instead of
        `F_p`. Karatsuba on the cross term, for the same reason: one
        fewer multiplication in the coefficient ring, and here that ring
        is itself an extension, so the saving is worth taking.
        """
        base = self._base  # type: ignore[attr-defined]
        t0 = base.mul(a[0], b[0])
        t1 = base.mul(a[1], b[1])
        cross = base.sub(
            base.sub(base.mul(base.add(a[0], a[1]), base.add(b[0], b[1])), t0), t1
        )
        return (base.add(t0, base.mul(self._xi, t1)), cross)  # type: ignore[attr-defined]

    def scale(self, a: Element, k: int) -> Element:
        base = self.base
        return (base.scale(a[0], k), base.scale(a[1], k))

    def square(self, a: Element) -> Element:
        return self.mul(a, a)

    def norm(self, a: Element) -> Fp2Element:
        """`a0^2 - xi a1^2`, an element of `F_p^2`.

        The norm down to the base of the tower, not all the way to
        `F_p` — which is what inversion needs and all it needs.
        """
        base = self._base  # type: ignore[attr-defined]
        return base.sub(
            base.square(a[0]), base.mul(self._xi, base.square(a[1]))  # type: ignore[attr-defined]
        )

    def conjugate(self, a: Element) -> Element:
        return (a[0], self.base.neg(a[1]))

    def inv(self, a: Element) -> Element:
        if self.is_zero(a):
            raise ZeroDivisionError("no inverse of zero")
        base = self.base
        norm_inv = base.inv(self.norm(a))
        conjugate = self.conjugate(a)
        return (base.mul(conjugate[0], norm_inv), base.mul(conjugate[1], norm_inv))

    def div(self, a: Element, b: Element) -> Element:
        return self.mul(a, self.inv(b))

    def pow(self, a: Element, exponent: int) -> Element:
        if exponent < 0:
            return self.pow(self.inv(a), -exponent)
        result, base_element = self.one, a
        while exponent:
            if exponent & 1:
                result = self.mul(result, base_element)
            base_element = self.square(base_element)
            exponent >>= 1
        return result

    # -- square roots --------------------------------------------------

    def is_square(self, a: Element) -> bool:
        if self.is_zero(a):
            return True
        return self.pow(a, (self.q - 1) // 2) == self.one

    def sqrt(self, a: Element) -> Element | None:
        """A square root, or None. The result is always squared and
        checked before it is returned, so a wrong root cannot escape —
        though a missed one would quietly shrink a point search.

        Tonry-Shanks over the whole extension. `q - 1` is even, and the
        generic algorithm is short enough to be read; specialising it to
        the tower would save time nobody is waiting for.
        """
        if self.is_zero(a):
            return self.zero
        if not self.is_square(a):
            return None

        q_minus_one = self.q - 1
        s, e = q_minus_one, 0
        while s % 2 == 0:
            s //= 2
            e += 1

        if e == 1:
            root = self.pow(a, (self.q + 1) // 4)
            return root if self.square(root) == a else None

        # A non-residue is needed to generate the 2-power part, and it
        # cannot be looked for among the integers.
        #
        # Every element of F_p is a square in F_p^4. For a in F_p*,
        # a^((p^4-1)/2) = (a^(p-1))^((p^3+p^2+p+1)/2), the exponent is an
        # integer because the sum of four odd terms is even, and a^(p-1)
        # is one. So scanning constants finds nothing however far it
        # runs — a search that silently never succeeds, which is worse
        # than one that fails loudly.
        #
        # The scan therefore runs over the field itself, in the same
        # fixed order used elsewhere so that two builds agree.
        non_residue = None
        for c0 in range(0, 32):
            for c1 in range(0, 32):
                candidate = self.element(c0, c1, 1)
                if not self.is_zero(candidate) and not self.is_square(candidate):
                    non_residue = candidate
                    break
            if non_residue is not None:
                break
        if non_residue is None:
            raise Fp4Error(
                "no non-residue found in the scanned range; the field is not "
                "what it claims to be"
            )

        x = self.pow(a, (s + 1) // 2)
        b = self.pow(a, s)
        g = self.pow(non_residue, s)
        rounds = e

        while True:
            if b == self.one:
                return x if self.square(x) == a else None
            m = 0
            squared = b
            while squared != self.one and m < rounds:
                squared = self.square(squared)
                m += 1
            if m == rounds:
                return None
            gs = self.pow(g, 1 << (rounds - m - 1))
            g = self.square(gs)
            x = self.mul(x, gs)
            b = self.mul(b, g)
            rounds = m


@dataclass(frozen=True)
class CurveFp4:
    """`y^2 = x^3 + a x + b` over an `Fp4`."""

    field: Fp4
    a: Element
    b: Element

    def __post_init__(self) -> None:
        f = self.field
        cube = f.mul(f.square(self.a), self.a)
        disc = f.add(f.scale(cube, 4), f.scale(f.square(self.b), 27))
        if f.is_zero(disc):
            raise Fp4Error("4a^3 + 27b^2 vanishes, so the curve is singular")

    def is_on_curve(self, point: Point) -> bool:
        if point is None:
            return True
        f = self.field
        x, y = point
        right = f.add(f.add(f.mul(f.square(x), x), f.mul(self.a, x)), self.b)
        return f.square(y) == right

    def negate(self, point: Point) -> Point:
        if point is None:
            return None
        return (point[0], self.field.neg(point[1]))

    def add(self, p1: Point, p2: Point) -> Point:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        f = self.field
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2:
            if y1 != y2 or f.is_zero(y1):
                return None
            return self.double(p1)
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
        result, addend = None, point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            scalar >>= 1
        return result

    def ordinate(self, x: Element) -> Element | None:
        """The smaller of the two roots, or None if x is not an abscissa.

        "Smaller" by the flattened coefficient tuple, which is arbitrary
        but fixed — and fixed is what matters, because the bytes of a
        certificate depend on which root a producer picked.
        """
        f = self.field
        right = f.add(f.add(f.mul(f.square(x), x), f.mul(self.a, x)), self.b)
        root = f.sqrt(right)
        if root is None:
            return None
        other = f.neg(root)
        return min(root, other, key=f.coefficients)

    def first_point(self) -> Point:
        """The first point found by scanning abscissas in a fixed order.

        Deterministic, because two builds must write the same evidence.
        """
        f = self.field
        for c0 in range(0, 64):
            for c1 in range(0, 64):
                x = f.element(c0, c1)
                y = self.ordinate(x)
                if y is not None:
                    point = (x, y)
                    if not f.is_zero(y) or True:
                        return point
        return None
