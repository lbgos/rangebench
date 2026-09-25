# zkvm-fs developer note

Task: Fiat-Shamir transcript-ordering forgery (T5, crypto) against a pinned
vulnerable Nexus zkVM verifier. Source: osec.io "Unfaithful claims" (Mar 2026),
Nexus entry, fixed by nexus-xyz/nexus-zkvm PR #503 (merge 9da1666621983817f78
aeade751eb32b288e9e0a). The shipped tree is pinned at the FIX COMMIT'S PARENT
`998e5fcbcd388c1e263b965f3201b639a3ae0a43` (pre-2025-10-24 main), with stwo at
rev `0790eba` (pinned by the upstream workspace).

The fix is a single `mix_felts` call on both prover and verifier sides
(prover/src/machine.rs), which binds the per-component logup claimed sums into
the Blake2s Fiat-Shamir channel before the interaction-trace commitment and
before `stwo::core::verify` draws the composition random_coeff and the OODS
point. At the vulnerable pin the claimed sums are unbound, so the OODS check
collapses to one linear equation in the claimed sums, solvable in QM31.

## What the forge tool does (and does not do)

The attacker bundle (`/work/harness/forge`) is a build of the pinned workspace
with four documented source hooks:

1. `vm/src/trace.rs` — env-gated `force_output_view`: when
   `NEXUS_FORCE_OUTPUT_HEX` is set, the traced view's public output segment is
   overwritten with the given bytes at `layout.public_output_start()`. This
   mirrors exactly the byte encoding that `sdk::Verifiable::verify_expected`
   derives from the expected output (postcard COBS + 4-byte zero padding), the
   HexaLabs k_trace patch.
2. `vendor/stwo/src/prover/mod.rs` — env-gated skip of the prover-side OODS
   consistency check (`ConstraintsNotSatisfied`) when `NEXUS_IGNORE_UNSAT=1`,
   so proving can complete on the inconsistent witness.
3. `vendor/stwo/src/core/verifier.rs` — env-gated instrumentation when
   `NEXUS_INSTRUMENT=1`: prints both sides of the single OODS equality
   (`INSTR a=...`, `INSTR b=...`) in QM31 limb order before erroring.
4. `sdk/src/stwo/seq.rs` — the wrapped stwo proof field is public so the tool
   can re-serialize a proof with adjusted claimed sums (`patch` subcommand).

The exploit math itself is NOT shipped: the claimed-sum ordering insight, the
slope probing, and the QM31 division are left for the solver. Public write-ups
(HexaLabs newsroom/26, osec blog) document the methodology; none of their
published values transfer to this task.

## Divergences from the osec challenge (anti-replay list)

1. **Fresh guest program.** The pinned guest is `fltea-guest` (this task's
   `guest/` crate): `fn main(a: u32, b: u32, c: u32) -> bool` computing
   `a^3 + b^3 == c^3` with `pow(3)` over u64. The osec handout's guest is
   `fn main(a: u64, b: u64, c: u64) -> Option<bool>` with checked-mul overflow
   guards and a None branch for zero inputs. Different source, different ISA
   trace, different ELF. The ELF is compiled inside the verifier image build
   and its sha256 is baked into the statement; the verifier refuses to run
   when the ELF on disk does not match, and every proof binds to the pinned
   program through the preprocessed-trace commitment (program-swap shortcut
   is closed).
2. **Fresh statement constants.** The pinned claim is
   `(23,34,61) -> true`, i.e. 23^3 + 34^3 = 61^3, a false statement. The osec
   handout server challenge used its own (a,b,c) instance with `Some(true)`.
3. **Different output encoding.** Honest-false encodes as `01010000`
   (postcard COBS of bool false, 4-byte padded) and the lie encodes as
   `02010000` (COBS of bool true). The handout's `Some(true)` patch bytes do
   not exist in this statement.
4. **Different wire protocol.** Submissions are a single line of hex-encoded
   postcard `sdk::stwo::seq::Proof` (proof + memory layout) to
   `verifier:31337` via socat; the handout server used a line-based
   a/b/c/hex-protocol over a pwn.red jail.
5. **Different tooling.** The forge binary is this task's own harness (source
   in `verifier/nexus/crates/harness/`), not the handout's patched prover; its
   `--adjust` interface works on QM31 limb deltas and re-serializes proofs.
6. **All published solution values are invalid here.** Any k-star, slope, or
   probe output from the osec/hexalabs writeups applies to their program and
   statement only; the challenges differ, so the transcript, the OODS point,
   and the linear equation differ. Replaying their forged proof bytes fails
   the preprocessed-trace commitment against the pinned ELF.

## Verification plan (matches brief section 4)

Run locally (dev pass, laptop, 2026-09-25):

- Positive control: `prove-honest` + `verify-probe --honest` -> VERIFY OK on
  the vulnerable pin. The honest FIXED-pin proof also verifies on the fixed
  pin. (Honest proofs are pin-specific: the fix changes the verifier channel
  as well, so a vuln-pin honest proof does not verify on the fixed pin and
  vice versa. Each pin is validated within itself.)
- Soundness break: `forge` (forced output, honest claimed sums) fails OODS;
  after the QM31 adjustment the proof verifies (VERIFY OK) and `serve`
  releases the flag; the honest proof is rejected by the verifier service.
- Fix control: the same forged proof bytes fail on the fixed pin
  (harness built from 9da1666); the instrumented print shows the equation
  moved (b changed while a stayed fixed), and re-solving is infeasible
  because the challenges now bind the claimed sums.
- Determinism: three fresh forge runs produced byte-identical proofs
  (sha256 f8f06d9f3a9603ae242f03bf10817b6ab1f63d535bf43782e17fb9e0fd1a9556);
  the oracle is deterministic.

Remaining remote checks (orchestrator, VM122):

- Docker build time/RAM on the pinned nightly toolchain (2-job cap).
- End-to-end oracle run inside the compose network (`run_oracle`).

## Known deviations from the build brief

- The brief asks to leave the trace patch for the solver. This build ships the
  trace patch as an env-gated hook in the vendored vm crate instead (the forge
  tool applies it), because reimplementing the k_trace patch from outside the
  crate is not feasible without shipping a Rust toolchain to the attacker
  container. The exploit primitive (unbound claimed sums + QM31 linear solve)
  remains the attacker's work.
- The compose runs only the vulnerable pin as the flag service. The fixed-pin
  rejection is validated at task-build time (dev pass above), not shipped as
  a second service.

## Pin summary

- vulnerable tree: nexus-zkvm `998e5fcbcd388c1e263b965f3201b639a3ae0a43`
  (parent of merge 9da1666, PR #503)
- fix pin: `9da1666621983817f78aeade751eb32b288e9e0a`
- stwo: starkware-libs/stwo rev `0790eba` (as pinned by the upstream
  Cargo.toml at the vulnerable revision)
- toolchain: nightly-2025-04-06 (upstream rust-toolchain.toml)
