"""PARI/GP backend.

A thin, deliberately distrustful wrapper around the ``gp`` executable.

Design decisions this module implements, in order of importance:

1. Communication happens through generated script files and ``gp -q``.
   Never through an interactive stdin: no prompts, no keyboard layouts,
   no console encoding, no shell quoting.
2. The path to ``gp`` comes from configuration, falling back to the
   environment and then to PATH. Nothing here assumes a machine layout.
3. Every call carries a hard timeout and the process is killed when it
   expires. A stuck SEA computation must not stall a farm worker.
4. Output is parsed strictly. Exactly the expected number of value lines
   between sentinels, nothing outside them, empty stderr, integers that
   are integers. Anything else raises. This matters more than it looks:
   ``gp`` exits with status 0 even after an error, so the exit code is
   useless and the protocol is the only real signal.
5. What comes back is a *candidate*, not a fact. ``ellcard`` returning a
   number is not proof of the group order; it is a claim that the
   verifier will later re-establish from evidence. The only checks done
   here are cheap sanity bounds that catch a broken pipeline early.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "GpBackend",
    "GpConfig",
    "GpError",
    "GpNotFound",
    "GpTimeout",
    "GpProtocolError",
    "GpComputationError",
    "find_gp",
    "twist_cardinality",
    "hasse_interval",
]

_BEGIN = "---CCERT-BEGIN---"
_END = "---CCERT-END---"
_INT_RE = re.compile(r"\A-?[0-9]+\Z")

# Refuse absurd inputs before they reach a subprocess. Nothing legitimate
# in this project needs an integer this large.
_MAX_BITS = 8192

_WINDOWS_HINTS = (
    r"C:\pari\gp.exe",
    r"C:\Program Files\PARI\gp.exe",
    r"C:\Program Files (x86)\PARI\gp.exe",
)

_CREATE_NO_WINDOW = 0x08000000  # keeps a console from flashing under a GUI


class GpError(RuntimeError):
    """Base class for every failure of this backend."""


class GpNotFound(GpError):
    """The gp executable could not be located."""


class GpTimeout(GpError):
    """The computation exceeded its budget and the process was killed."""


class GpProtocolError(GpError):
    """Output did not match the expected shape. Treated as total failure."""


class GpComputationError(GpError):
    """gp reported a problem on stderr."""


def find_gp(explicit: str | os.PathLike | None = None) -> Path:
    """Locate the gp executable.

    Order: explicit argument, ``CCERT_GP`` environment variable, PATH,
    then a few conventional Windows locations.
    """
    candidates: list[str | os.PathLike] = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("CCERT_GP")
    if env:
        candidates.append(env)

    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file():
            return path.resolve()
        raise GpNotFound(f"gp not found at the configured path: {path}")

    found = shutil.which("gp") or shutil.which("gp.exe")
    if found:
        return Path(found).resolve()

    if os.name == "nt":
        for hint in _WINDOWS_HINTS:
            path = Path(hint)
            if path.is_file():
                return path.resolve()

    raise GpNotFound(
        "gp not found. Install PARI/GP, then either add its folder to PATH "
        "or set the CCERT_GP environment variable to the full path of gp.exe."
    )


@dataclass(frozen=True)
class GpConfig:
    """Runtime configuration for the backend."""

    exe: Path | None = None
    timeout: float = 600.0
    parisize: int = 512 * 1024 * 1024
    # Lets PARI grow its stack on demand. Certificate search needs far more
    # room than point counting, and running out looks like a crash.
    parisizemax: int = 2 * 1024 * 1024 * 1024
    max_rows: int = 4096  # refuse implausibly long tables
    keep_scripts: bool = False  # leave generated scripts on disk to debug


def hasse_interval(p: int) -> tuple[int, int]:
    """Bounds on the number of points of a curve over F_p, inclusive.

    Uses an integer square root so the bound is exact, never a float
    approximation that could accept a value it should reject.
    """
    root = _isqrt(4 * p)
    # root <= 2*sqrt(p) < root + 1, so widening by one is safe.
    return p + 1 - root - 1, p + 1 + root + 1


def twist_cardinality(p: int, cardinality: int) -> int:
    """Order of the quadratic twist, from #E + #E' = 2p + 2.

    Computed here rather than asked of gp: an identity we can evaluate
    ourselves is one less thing to trust a subprocess about.
    """
    return 2 * p + 2 - cardinality


def _isqrt(n: int) -> int:
    if n < 0:
        raise ValueError("negative input to isqrt")
    return int(__import__("math").isqrt(n))


def _check_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value.bit_length() > _MAX_BITS:
        raise ValueError(f"{name} exceeds {_MAX_BITS} bits")
    return value


class GpBackend:
    """Runs short scripts through gp and returns integers.

    The backend is stateless between calls on purpose: every call gets a
    fresh process, so a computation cannot poison the next one and a
    worker that dies mid-task leaves nothing behind.
    """

    def __init__(self, config: GpConfig | None = None) -> None:
        self.config = config or GpConfig()
        self.exe = find_gp(self.config.exe)
        self._last_elapsed: float = 0.0

    # -- protocol ---------------------------------------------------

    def _build_script(self, setup: list[str], exprs: list[str]) -> str:
        lines = [
            # parisize is set on the command line, not here: default() emits a
            # "new stack size" warning on stderr, and stderr must stay empty.
            'default(colors, "no");',
            "default(linewrap, 0);",
            "default(breakloop, 0);",
            "default(timer, 0);",
            "default(echo, 0);",
        ]
        lines.extend(s.rstrip().rstrip(";") + ";" for s in setup)
        lines.append(f'print("{_BEGIN}");')
        lines.extend(f"print({e});" for e in exprs)
        lines.append(f'print("{_END}");')
        lines.append("quit(0);")
        return "\n".join(lines) + "\n"

    def _run(self, script: str, timeout: float) -> tuple[str, str, float]:
        workdir = Path(tempfile.mkdtemp(prefix="ccert-gp-"))
        script_path = workdir / "task.gp"
        script_path.write_text(script, encoding="ascii", newline="\n")

        kwargs: dict = {}
        if os.name == "nt":
            kwargs["creationflags"] = _CREATE_NO_WINDOW

        started = time.monotonic()
        proc = subprocess.Popen(
            [
                str(self.exe),
                "-q",
                "-s",
                str(self.config.parisize),
                # Both limits go on the command line: default() would write a
                # warning to stderr, and stderr must stay empty.
                "--default",
                f"parisizemax={self.config.parisizemax}",
                str(script_path),
            ],
            stdin=subprocess.DEVNULL,  # gp waits on stdin if a script fails
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(workdir),
            text=True,
            encoding="ascii",
            errors="replace",
            **kwargs,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise GpTimeout(
                f"gp exceeded its budget of {timeout:g} s and was killed"
            ) from None
        finally:
            elapsed = time.monotonic() - started
            if not self.config.keep_scripts:
                shutil.rmtree(workdir, ignore_errors=True)

        return out, err, elapsed

    @staticmethod
    def _parse(out: str, err: str, expected: int) -> list[int]:
        if err.strip():
            first = " / ".join(err.strip().splitlines()[:3])
            raise GpComputationError(f"gp reported: {first}")

        lines = [ln.strip() for ln in out.replace("\r\n", "\n").split("\n")]

        try:
            start = lines.index(_BEGIN)
            stop = lines.index(_END)
        except ValueError:
            raise GpProtocolError("sentinels missing from gp output") from None
        if lines.count(_BEGIN) != 1 or lines.count(_END) != 1 or stop < start:
            raise GpProtocolError("malformed sentinels in gp output")

        preamble = [ln for ln in lines[:start] if ln]
        if preamble:
            raise GpProtocolError(f"unexpected output before results: {preamble[0]!r}")
        trailing = [ln for ln in lines[stop + 1 :] if ln]
        if trailing:
            raise GpProtocolError(f"unexpected output after results: {trailing[0]!r}")

        values = lines[start + 1 : stop]
        if len(values) != expected:
            raise GpProtocolError(
                f"expected {expected} result line(s), got {len(values)}"
            )
        for value in values:
            if not _INT_RE.match(value):
                raise GpProtocolError(f"result is not an integer: {value!r}")
        return [int(v) for v in values]

    def eval_ints(
        self,
        exprs: list[str],
        setup: list[str] | None = None,
        timeout: float | None = None,
    ) -> list[int]:
        """Evaluate expressions and return their integer values.

        ``exprs`` must be expressions that print as plain integers.
        Callers build them from validated integers, never from user text.
        """
        if not exprs:
            raise ValueError("nothing to evaluate")
        budget = self.config.timeout if timeout is None else timeout
        script = self._build_script(setup or [], exprs)
        out, err, elapsed = self._run(script, budget)
        self._last_elapsed = elapsed
        return self._parse(out, err, len(exprs))

    def eval_table(
        self,
        setup: list[str],
        count_expr: str,
        row_exprs: list[str],
        timeout: float | None = None,
    ) -> list[list[int]]:
        """Evaluate a table whose height is not known in advance.

        The first result line is the row count, and exactly that many rows
        must follow. A declared count that does not match what arrives is
        the same class of failure as a missing line: total.
        """
        if not row_exprs:
            raise ValueError("a table needs at least one column")

        script_setup = list(setup)
        printers = "; ".join(f"print({expr})" for expr in row_exprs)
        script_setup.append(f"zn = {count_expr}")

        lines = [
            f'print("{_BEGIN}");',
            "print(zn);",
            f"for(i = 1, zn, {printers});",
            f'print("{_END}");',
        ]
        head = [
            'default(colors, "no");',
            "default(linewrap, 0);",
            "default(breakloop, 0);",
            "default(timer, 0);",
            "default(echo, 0);",
        ]
        head.extend(s.rstrip().rstrip(";") + ";" for s in script_setup)
        script = "\n".join(head + lines + ["quit(0);"]) + "\n"

        budget = self.config.timeout if timeout is None else timeout
        out, err, elapsed = self._run(script, budget)
        self._last_elapsed = elapsed

        if err.strip():
            first = " / ".join(err.strip().splitlines()[:3])
            raise GpComputationError(f"gp reported: {first}")

        body = [ln.strip() for ln in out.replace("\r\n", "\n").split("\n")]
        try:
            start = body.index(_BEGIN)
            stop = body.index(_END)
        except ValueError:
            raise GpProtocolError("sentinels missing from gp output") from None
        values = body[start + 1 : stop]
        if not values:
            raise GpProtocolError("table is empty")
        for value in values:
            if not _INT_RE.match(value):
                raise GpProtocolError(f"result is not an integer: {value!r}")

        rows = int(values[0])
        if rows < 0 or rows > self.config.max_rows:
            raise GpProtocolError(f"implausible row count: {rows}")
        width = len(row_exprs)
        payload = values[1:]
        if len(payload) != rows * width:
            raise GpProtocolError(
                f"declared {rows} row(s) of {width}, received {len(payload)} value(s)"
            )
        numbers = [int(v) for v in payload]
        return [numbers[i * width : (i + 1) * width] for i in range(rows)]

    @property
    def last_elapsed(self) -> float:
        """Wall-clock seconds spent in the most recent call."""
        return self._last_elapsed

    # -- callers ----------------------------------------------------

    def version(self, timeout: float = 30.0) -> tuple[int, int, int]:
        """Version of the gp binary, as a triple."""
        parts = self.eval_ints(
            ["version()[1]", "version()[2]", "version()[3]"], timeout=timeout
        )
        return parts[0], parts[1], parts[2]

    def has_seadata(self, timeout: float = 60.0) -> bool:
        """Whether the seadata package is installed.

        Without it, point counting on large primes falls back to code that
        is orders of magnitude slower, which looks like a hang.
        """
        try:
            self.eval_ints(["poldegree(ellmodulareqn(11)[1], x)"], timeout=timeout)
        except GpComputationError:
            return False
        return True

    def curve_cardinality(
        self, a: int, b: int, p: int, timeout: float | None = None
    ) -> int:
        """Candidate order of y^2 = x^3 + ax + b over F_p.

        The Hasse check below is not a proof of anything. It is a tripwire:
        a value outside the interval means the pipeline is broken, and
        continuing would be worse than failing.
        """
        a = _check_int("a", a)
        b = _check_int("b", b)
        p = _check_int("p", p)
        if p < 5:
            raise ValueError("this backend expects a prime p > 3")

        (card,) = self.eval_ints(
            [f"ellcard(ellinit([{a}, {b}], {p}))"], timeout=timeout
        )
        low, high = hasse_interval(p)
        if not low <= card <= high:
            raise GpProtocolError(
                "cardinality outside the Hasse interval; the backend is lying "
                "or misconfigured"
            )
        return card

    def is_pseudoprime(self, n: int, timeout: float | None = None) -> bool:
        """Cheap primality screen. Not evidence, only a filter.

        A true prime still needs a certificate; this exists to avoid
        spending hours certifying a number that is obviously composite.
        """
        n = _check_int("n", n)
        (flag,) = self.eval_ints([f"ispseudoprime({n})"], timeout=timeout)
        if flag not in (0, 1):
            raise GpProtocolError(f"ispseudoprime returned {flag}")
        return flag == 1


    def primality_certificate(
        self, n: int, timeout: float | None = None
    ) -> list[dict[str, int]]:
        """An Atkin-Morain certificate chain for n.

        Each step is ``N, t, s, a`` and a point ``(x, y)``. With
        ``m = N + 1 - t`` and ``q = m / s``, the step reduces the primality
        of N to the primality of q, and q is the next step's N. Nothing is
        checked here; that is the verifier's work.
        """
        n = _check_int("n", n)
        if n < 2:
            raise ValueError("only integers above 1 can be prime")

        rows = self.eval_table(
            [f"zc = primecert({n})"],
            "#zc",
            [
                "zc[i][1]",
                "zc[i][2]",
                "zc[i][3]",
                "zc[i][4]",
                "zc[i][5][1]",
                "zc[i][5][2]",
            ],
            timeout=timeout,
        )
        if not rows:
            raise GpProtocolError("primecert returned nothing; n is likely composite")
        keys = ("N", "t", "s", "a", "x", "y")
        steps = [dict(zip(keys, row)) for row in rows]
        if steps[0]["N"] != n:
            raise GpProtocolError("the certificate chain does not start at n")
        return steps

    def factorization(
        self, n: int, timeout: float | None = None
    ) -> list[tuple[int, int]]:
        """Complete factorisation of n, as (prime, exponent) pairs.

        Expensive and occasionally hopeless for a general number. The caller
        decides whether to attempt it; a timeout here is a normal outcome,
        not a bug.
        """
        n = _check_int("n", n)
        if n < 2:
            raise ValueError("only integers above 1 can be factored")
        rows = self.eval_table(
            [f"zf = factor({n})"],
            "matsize(zf)[1]",
            ["zf[i, 1]", "zf[i, 2]"],
            timeout=timeout,
        )
        factors = [(row[0], row[1]) for row in rows]
        product = 1
        for prime, exponent in factors:
            product *= prime**exponent
        if product != n:  # the backend is not trusted, even about arithmetic
            raise GpProtocolError("the returned factors do not multiply back to n")
        return factors

    def core_discriminant(self, value: int, timeout: float | None = None) -> int:
        """The fundamental discriminant hiding inside a discriminant.

        Any discriminant factors as f^2 * D with D fundamental. D is what
        names the CM field; f is an artefact of the particular curve.
        """
        value = _check_int("value", value)
        (core,) = self.eval_ints([f"coredisc({value})"], timeout=timeout)
        return core

    def multiplicative_order(
        self, base: int, modulus: int, timeout: float | None = None
    ) -> int:
        """Order of base in the multiplicative group modulo modulus.

        For a curve this is the embedding degree: the smallest k with
        n dividing p^k - 1, which is what a pairing attack would exploit.
        """
        base = _check_int("base", base)
        modulus = _check_int("modulus", modulus)
        (order,) = self.eval_ints(
            [f"znorder(Mod({base}, {modulus}))"], timeout=timeout
        )
        return order

    def first_point(
        self, a: int, b: int, p: int, timeout: float | None = None
    ) -> tuple[int, int]:
        """A point on the curve, chosen deterministically.

        The smallest positive x with an ordinate, and the smaller of the two
        roots. A random point would work mathematically but would change the
        bundle's hash on every run, which costs more than it gains.
        """
        a = _check_int("a", a)
        b = _check_int("b", b)
        p = _check_int("p", p)
        setup = [
            f"zE = ellinit([{a}, {b}], {p})",
            "zP = [0, 0]",
            "for(x = 1, 10000, zv = lift(ellordinate(zE, x)); "
            "if(#zv, zP = [x, vecmin(zv)]; break()))",
        ]
        x, y = self.eval_ints(["zP[1]", "zP[2]"], setup=setup, timeout=timeout)
        if (x, y) == (0, 0):
            raise GpProtocolError("no point found in the searched range")
        return x, y


# -- self test ------------------------------------------------------

# secp256k1: the reference values the toolchain must reproduce.
_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_A = 0
_SECP256K1_B = 7
_SECP256K1_N = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)


def _self_test(gp_path: str | None) -> int:
    try:
        backend = GpBackend(GpConfig(exe=Path(gp_path) if gp_path else None))
    except GpNotFound as exc:
        print(f"FAIL  {exc}")
        return 1

    print(f"gp:        {backend.exe}")
    try:
        major, minor, patch = backend.version()
        print(f"version:   {major}.{minor}.{patch}")

        seadata = backend.has_seadata()
        print(f"seadata:   {'present' if seadata else 'MISSING'}")
        if not seadata:
            print("           point counting will be very slow without it")

        card = backend.curve_cardinality(_SECP256K1_A, _SECP256K1_B, _SECP256K1_P)
        print(f"ellcard:   {backend.last_elapsed:.2f} s")
    except GpError as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}")
        return 1

    ok = card == _SECP256K1_N
    print(f"secp256k1: {'matches the reference order' if ok else 'MISMATCH'}")
    if not ok:
        print(f"  expected {_SECP256K1_N}")
        print(f"  got      {card}")
        return 1

    twist = twist_cardinality(_SECP256K1_P, card)
    print(f"twist:     {twist}")
    print("\nBackend is working.")
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="PARI/GP backend self test.")
    parser.add_argument("--gp", help="full path to gp.exe")
    parser.add_argument(
        "--self-test", action="store_true", help="run the secp256k1 check"
    )
    args = parser.parse_args()

    if not args.self_test:
        parser.print_help()
        return 0
    return _self_test(args.gp)


if __name__ == "__main__":
    raise SystemExit(main())
