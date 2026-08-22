"""Tests for the PARI/GP backend.

Split deliberately: the parser and the arithmetic are tested without gp
installed, because those are the parts that decide whether a wrong number
gets through. The rest is marked and skipped when gp is absent.
"""

import pytest

from core.backends import gp as G

BEGIN = "---CCERT-BEGIN---"
END = "---CCERT-END---"

SECP_P = 2**256 - 2**32 - 977
SECP_N = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)


def out(*value_lines: str) -> str:
    return "\n".join([BEGIN, *value_lines, END]) + "\n"


# -- parser: everything below must fail loudly ----------------------


def test_accepts_well_formed_output():
    assert G.GpBackend._parse(out("7", "-3"), "", 2) == [7, -3]


def test_accepts_crlf():
    assert G.GpBackend._parse(out("7").replace("\n", "\r\n"), "", 1) == [7]


def test_rejects_stderr_noise():
    with pytest.raises(G.GpComputationError):
        G.GpBackend._parse(out("7"), "  *** something went wrong", 1)


def test_rejects_missing_sentinels():
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse("7\n", "", 1)


def test_rejects_wrong_count():
    """The dangerous case: gp skipped a statement after an error."""
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse(out("7"), "", 2)


def test_rejects_extra_line():
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse(out("7", "8"), "", 1)


def test_rejects_non_integer():
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse(out("x^2 + 1"), "", 1)


def test_rejects_wrapped_number():
    """A long integer split across lines must never be silently glued."""
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse(out("1157920892373161954235709850086", "87907853"), "", 1)


def test_rejects_chatter_around_results():
    noisy = "Reading GPRC\n" + out("7")
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse(noisy, "", 1)


def test_rejects_duplicate_sentinels():
    with pytest.raises(G.GpProtocolError):
        G.GpBackend._parse(out("7") + out("8"), "", 1)


# -- arithmetic done on our side, not gp's --------------------------


def test_hasse_contains_secp256k1():
    low, high = G.hasse_interval(SECP_P)
    assert low <= SECP_N <= high


def test_hasse_is_tight_enough_to_be_useful():
    low, high = G.hasse_interval(SECP_P)
    assert (high - low).bit_length() <= 131  # about 4*sqrt(p)


def test_twist_identity():
    twist = G.twist_cardinality(SECP_P, SECP_N)
    assert SECP_N + twist == 2 * SECP_P + 2


def test_argument_validation():
    with pytest.raises(TypeError):
        G._check_int("n", "1")
    with pytest.raises(TypeError):
        G._check_int("n", True)
    with pytest.raises(ValueError):
        G._check_int("n", 2**9000)


def test_missing_gp_path_is_reported():
    with pytest.raises(G.GpNotFound):
        G.find_gp("/definitely/not/here/gp")


# -- live gp --------------------------------------------------------


def gp_available() -> bool:
    try:
        G.find_gp()
    except G.GpNotFound:
        return False
    return True


live = pytest.mark.skipif(not gp_available(), reason="gp not installed")


@pytest.fixture(scope="module")
def backend():
    return G.GpBackend()


@live
def test_version(backend):
    major, minor, _ = backend.version()
    assert (major, minor) >= (2, 9)


@live
def test_secp256k1_order(backend):
    assert backend.curve_cardinality(0, 7, SECP_P) == SECP_N


@live
def test_pseudoprime_screen(backend):
    assert backend.is_pseudoprime(SECP_N)
    assert not backend.is_pseudoprime(SECP_N - 1)


@live
def test_timeout_kills_the_process(backend):
    slow = G.GpBackend(G.GpConfig(exe=backend.exe, timeout=0.5))
    with pytest.raises(G.GpTimeout):
        slow.eval_ints(["sum(i = 1, 10^10, i)"])


@live
def test_gp_error_becomes_our_error(backend):
    with pytest.raises(G.GpError):
        backend.eval_ints(["1/0"], timeout=30)
