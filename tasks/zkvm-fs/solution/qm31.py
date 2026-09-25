"""QM31 (SecureField) arithmetic over 2^31-1 for the zkvm-fs reference solve.

Represented as four M31 limbs (a, b, c, d) meaning (a + b*i) + (c + d*i)*u,
where i^2 = -1 and u^2 = 2 + i, all arithmetic mod p = 2^31 - 1.
"""

P = (1 << 31) - 1


def m31_add(x: int, y: int) -> int:
    return (x + y) % P


def m31_sub(x: int, y: int) -> int:
    return (x - y) % P


def m31_mul(x: int, y: int) -> int:
    return (x * y) % P


def m31_inv(x: int) -> int:
    return pow(x, P - 2, P)


def cm31_mul(x, y):
    """(a + b i)(c + d i) mod p with i^2 = -1."""
    a, b = x
    c, d = y
    real = m31_sub(m31_mul(a, c), m31_mul(b, d))
    imag = m31_add(m31_mul(a, d), m31_mul(b, c))
    return (real, imag)


def cm31_sub(x, y):
    return (m31_sub(x[0], y[0]), m31_sub(x[1], y[1]))


def cm31_add(x, y):
    return (m31_add(x[0], y[0]), m31_add(x[1], y[1]))


def cm31_inv(x):
    """Inverse of a + b i: (a - b i) / (a^2 + b^2)."""
    a, b = x
    norm = m31_add(m31_mul(a, a), m31_mul(b, b))
    if norm == 0:
        raise ZeroDivisionError("CM31 zero not invertible")
    inv_norm = m31_inv(norm)
    return (m31_mul(a, inv_norm), m31_mul(m31_sub(0, b), inv_norm))


class QM31:
    """(a + b i) + (c + d i) u; stored as cm31 pair ((a, b), (c, d))."""

    __slots__ = ("x0", "x1")

    def __init__(self, a=0, b=0, c=0, d=0):
        self.x0 = (a % P, b % P)
        self.x1 = (c % P, d % P)

    @classmethod
    def from_limbs(cls, limbs):
        a, b, c, d = limbs
        return cls(a, b, c, d)

    @classmethod
    def one(cls):
        return cls(1, 0, 0, 0)

    def is_zero(self):
        return self.x0 == (0, 0) and self.x1 == (0, 0)

    def __eq__(self, other):
        return isinstance(other, QM31) and self.x0 == other.x0 and self.x1 == other.x1

    def __hash__(self):
        return hash((self.x0, self.x1))

    def __repr__(self):
        a, b = self.x0
        c, d = self.x1
        return f"QM31({a},{b},{c},{d})"

    def limbs(self):
        return (self.x0[0], self.x0[1], self.x1[0], self.x1[1])

    def __add__(self, other):
        return QM31(
            m31_add(self.x0[0], other.x0[0]),
            m31_add(self.x0[1], other.x0[1]),
            m31_add(self.x1[0], other.x1[0]),
            m31_add(self.x1[1], other.x1[1]),
        )

    def __sub__(self, other):
        return QM31(
            m31_sub(self.x0[0], other.x0[0]),
            m31_sub(self.x0[1], other.x0[1]),
            m31_sub(self.x1[0], other.x1[0]),
            m31_sub(self.x1[1], other.x1[1]),
        )

    def __mul__(self, other):
        x0, x1 = self.x0, self.x1
        y0, y1 = other.x0, other.x1
        t00 = cm31_mul(x0, y0)
        t01 = cm31_mul(x0, y1)
        t10 = cm31_mul(x1, y0)
        t11 = cm31_mul(x1, y1)
        u_coeff = cm31_add(t01, t10)
        r = cm31_mul(t11, (2, 1))  # u^2 = 2 + i
        return QM31(
            m31_add(t00[0], r[0]),
            m31_add(t00[1], r[1]),
            u_coeff[0],
            u_coeff[1],
        )

    def __truediv__(self, other):
        return self * other.inverse()

    def conjugate(self):
        """QM31 involution: u -> -u (x0 + x1 u -> x0 - x1 u)."""
        return QM31(
            self.x0[0],
            self.x0[1],
            m31_sub(0, self.x1[0]),
            m31_sub(0, self.x1[1]),
        )

    def inverse(self):
        """x^-1 = conj(x) / N(x), N(x) = x*conj(x) = x0^2 - x1^2*(2+i) in CM31."""
        x0, x1 = self.x0, self.x1
        x0sq = cm31_mul(x0, x0)
        x1sq = cm31_mul(x1, x1)
        norm = cm31_sub(x0sq, cm31_mul(x1sq, (2, 1)))
        norm_inv = cm31_inv(norm)
        return self.conjugate() * QM31(norm_inv[0], norm_inv[1], 0, 0)


def parse_limb_list(s: str) -> QM31:
    parts = [int(x) % P for x in s.strip().split(",")]
    if len(parts) != 4:
        raise ValueError(f"expected 4 limbs, got {parts!r}")
    return QM31(*parts)


if __name__ == "__main__":
    # Self-test: inverses, commutativity, distributivity, field identities.
    import random

    random.seed(1)
    one = QM31.one()
    for _ in range(500):
        a = QM31.from_limbs([random.randrange(P) for _ in range(4)])
        b = QM31.from_limbs([random.randrange(P) for _ in range(4)])
        if not a.is_zero():
            assert (a * a.inverse()) == one, f"inverse failed for {a}"
        assert (a * b) == (b * a)
        assert ((a + b) * (a - b)) == (a * a - b * b)
    assert m31_add(P, 5) == 5
    print("qm31 self-test OK")
