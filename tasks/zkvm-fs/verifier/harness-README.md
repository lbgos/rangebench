# forge tool (nexus-harness)

This bundle carries the pinned guest program and the proving/verification
harness for the deployed zkVM verifier service. The verifier at
`verifier:31337` releases its flag only when a submitted proof verifies for
the fixed public statement baked into `statement`.

## contents

- `forge`       the harness binary (same build the verifier service runs)
- `guest.elf`   the pinned guest program (sha256 in `statement`)
- `statement`   the fixed public statement (guest hash, inputs, expected output)

## usage

```
./forge info --statement statement
    print the statement data and encodings

./forge prove-honest --statement statement --out proof.bin
    prove the honest execution (guest prints its actual result)

./forge forge --statement statement --out proof.bin
    prove the pinned statement with the public output forced to the
    expected encoding; component claimed sums stay honest

./forge verify-probe --statement statement --in proof.bin [--adjust <spec>]
    run verification of a proof against the pinned statement locally;
    on OODS mismatch prints both sides of the equality as QM31 limbs
      INSTR a=<a0>,<a1>,<a2>,<a3>
      INSTR b=<b0>,<b1>,<b2>,<b3>
    limbs are M31 values mod 2^31-1 in (a + b i) + (c + d i) u order

./forge patch --in proof.bin --out patched.bin --adjust <spec>
    apply claimed-sum adjustments to a proof file and re-serialize

./forge submit --host verifier:31337 --in proof.bin
    submit a proof to the verifier service (prints the response)

adjust spec: "0:+<a>,<b>,<c>,<d>;1:-<a>,<b>,<c>,<d>"
    adds the QM31 value (a,b,c,d) to component 0's claimed sum and
    subtracts it from component 1's claimed sum
```

The guest program is hash-pinned; the verifier refuses statements whose ELF
digest differs from the pinned one, and the preprocessed-trace commitment
binds every proof to the pinned program.
