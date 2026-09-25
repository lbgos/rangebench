#!/usr/bin/env python3
"""zkvm-fs reference solve: Fiat-Shamir transcript-ordering forgery.

Runs entirely against the bundle in /work/harness:
  1. forge a proof of the pinned statement with honest claimed sums
  2. probe the OODS equality (a = target from the proof, b = evaluated)
  3. measure the linear response of b to a +-1 claimed-sum adjustment
  4. solve k* = (a - b0) / slope in QM31
  5. confirm the adjusted proof verifies, patch it, and submit
"""

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qm31 import QM31  # noqa: E402

HARNESS = Path("/work/harness")
FORGE = HARNESS / "forge"
STATEMENT = HARNESS / "statement"
WORK = Path("/tmp/zkvm-fs-solve")

INSTR_RE = re.compile(r"INSTR ([ab])=(\d+),(\d+),(\d+),(\d+)")


def run(args: list[str], **kw) -> str:
    proc = subprocess.run(
        [str(FORGE)] + args, capture_output=True, text=True, cwd="/tmp", **kw
    )
    return proc.returncode, proc.stdout + proc.stderr


def probe(adjust: str | None) -> tuple[QM31, QM31]:
    """Run verify-probe and return the (a, b) sides of the OODS equality."""
    args = ["verify-probe", "--statement", str(STATEMENT), "--in", "/tmp/zkvm-fs-solve/base.bin"]
    if adjust is not None:
        args += ["--adjust", adjust]
    rc, out = run(args)
    a = b = None
    for m in INSTR_RE.finditer(out):
        limbs = tuple(int(m.group(i)) for i in range(2, 6))
        if m.group(1) == "a":
            a = QM31(*limbs)
        else:
            b = QM31(*limbs)
    if a is None or b is None:
        if "VERIFY OK" in out:
            raise RuntimeError("unexpected VERIFY OK during probing")
        print(out[-2000:])
        raise RuntimeError(f"probe failed rc={rc}: no instrumented sides")
    return a, b


def main() -> int:
    WORK.mkdir(exist_ok=True)
    base = WORK / "base.bin"
    forged = WORK / "forged.bin"

    # positive control: the honest pipeline works end to end
    rc, out = run(["prove-honest", "--statement", str(STATEMENT), "--out", "/tmp/zkvm-fs-solve/honest.bin"])
    assert rc == 0, out[-2000:]
    rc, out = run(["verify-probe", "--statement", str(STATEMENT), "--in", "/tmp/zkvm-fs-solve/honest.bin", "--honest"])
    assert "VERIFY OK" in out, out[-2000:]
    print("[+] positive control: honest proof verifies")

    # 1. forged-view proof with honest claimed sums
    rc, out = run(["forge", "--statement", str(STATEMENT), "--out", str(base)])
    assert rc == 0, out[-2000:]
    print("[+] forged-view proof generated")

    # 2-4. two probes + QM31 solve
    a, b0 = probe(None)
    print(f"[+] probe k=0: a={a}")
    _, b1 = probe("0:+1,0,0,0;1:-1,0,0,0")
    slope = b1 - b0
    if slope.is_zero():
        # try the next component pair; (0, j) probes
        for j in range(2, 8):
            _, bj = probe(f"0:+1,0,0,0;{j}:-1,0,0,0")
            slope = bj - b0
            if not slope.is_zero():
                j_pair = (0, j)
                break
        else:
            raise RuntimeError("no working component pair found")
    else:
        j_pair = (0, 1)
    k = (a - b0) / slope
    print(f"[+] slope={slope}, pair={j_pair}, k*={k}")

    adjust = f"0:+{','.join(map(str, k.limbs()))};{j_pair[1]}:-{','.join(map(str, k.limbs()))}"
    if j_pair[0] != 0:
        adjust = f"{j_pair[0]}:+{','.join(map(str, k.limbs()))};{j_pair[1]}:-{','.join(map(str, k.limbs()))}"

    # 5. confirm the adjusted proof satisfies the OODS equality locally
    rc, out = run(["verify-probe", "--statement", str(STATEMENT), "--in", "/tmp/zkvm-fs-solve/base.bin", "--adjust", adjust])
    assert "VERIFY OK" in out, out[-2000:]
    print("[+] adjusted claimed sums satisfy the OODS equality")

    # 6. materialize the forged proof and submit it
    rc, out = run(["patch", "--in", "/tmp/zkvm-fs-solve/base.bin", "--out", str(forged), "--adjust", adjust])
    assert rc == 0, out[-2000:]
    rc, out = run(["submit", "--host", "verifier:31337", "--in", str(forged)])
    print(out.strip())
    if "ACCEPT" in out:
        return 0
    print("submission rejected", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
