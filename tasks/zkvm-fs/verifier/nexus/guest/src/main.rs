//! Fermat checker: reads (a, b, c) from the public input tape and reports
//! whether a^3 + b^3 == c^3. Honest executions report `false`; the verifier
//! deployment pins the impossible statement `true` for the fixed inputs.

#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
#[nexus_rt::public_input(a, b, c)]
fn main(a: u32, b: u32, c: u32) -> bool {
    let lhs = (a as u64).pow(3) + (b as u64).pow(3);
    let rhs = (c as u64).pow(3);
    lhs == rhs
}
