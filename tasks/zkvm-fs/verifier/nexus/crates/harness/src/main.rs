//! Developer harness for the zkvm-fs task.
//!
//! Two roles share this binary:
//!   * verifier service (`serve`): reads a hex-encoded postcard `sdk::Proof` from
//!     stdin, verifies it against the fixed public statement, prints the flag on
//!     success and a reject line otherwise.
//!   * forge tool (`prove-honest`, `forge`, `verify-probe`, `submit`, `info`):
//!     the attacker-side proving harness. `forge` runs the honest execution of
//!     the pinned guest program and forces the public output segment to the
//!     statement's expected (false) encoding before proving, so that the only
//!     remaining inconsistency is the logup claimed sums. `verify-probe` runs the
//!     verification equation locally and reports the two OODS sides so the
//!     claimed-sum adjustment can be solved for.

mod statement;

use nexus_sdk::stwo::seq::Proof as SdkProof;
use nexus_sdk::{stwo::seq::Stwo, KnownExitCodes, Prover, Verifiable, Viewable};
use sha2::{Digest, Sha256};
use statement::Statement;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use std::io::{Read, Write};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let status = match args[1].as_str() {
        "serve" => cmd_serve(&args[2..]),
        "info" => cmd_info(&args[2..]),
        "patch" => cmd_patch(&args[2..]),
        "prove-honest" => cmd_prove_honest(&args[2..]),
        "forge" => cmd_forge(&args[2..]),
        "verify-probe" => cmd_verify_probe(&args[2..]),
        "submit" => cmd_submit(&args[2..]),
        "help" | "--help" | "-h" => {
            help();
            0
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            help();
            2
        }
    };
    std::process::exit(status);
}

fn usage() {
    eprintln!("usage: nexus-harness <subcommand> [flags]  (see `nexus-harness help`)");
    std::process::exit(2);
}

fn help() {
    println!("nexus-harness - verifier service and forge tool for the pinned zkVM");
    println!();
    println!("  serve      verifier service mode (stdin line protocol)");
    println!("  info       print statement data, guest ELF digest, proof stats");
    println!("  prove-honest   prove the honest execution of the guest program");
    println!("  forge      prove the statement with the public output forced to the");
    println!("             expected (false) encoding; claimed sums stay honest");
    println!("  verify-probe   run verification of a proof against the statement,");
    println!("             printing the two sides of the OODS equality on mismatch");
    println!("  submit     send a proof to the verifier service over TCP");
    println!("  patch      apply claimed-sum adjustments to a proof file");
    println!();
    println!("Common flags:");
    println!("  --statement <file>    statement file (required)");
    println!("  --out <file>          write the postcard proof bytes here");
    println!("  --in <file>           read the postcard proof bytes from here");
    println!("  --host <host:port>    verifier service address for submit");
    println!("  --adjust <spec>       claimed-sum adjustment(s), e.g.");
    println!("                        \"0:+<a>,<b>,<c>,<d>;1:-<a>,<b>,<c>,<d>\"");
    println!("                        (QM31 limbs, decimal, each mod 2^31-1)");
    println!("  --honest              (verify-probe) expect the honest output instead");
    println!("  --force-output <hex>  (forge) override the forced public output bytes");
}

fn flag_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().map(|s| s.as_str());
        }
    }
    None
}

fn require_arg<'a>(args: &'a [String], name: &str) -> &'a str {
    flag_arg(args, name).unwrap_or_else(|| panic!("missing required flag {name}"))
}

fn adjust_specs<'a>(args: &'a [String]) -> Vec<&'a str> {
    args.iter()
        .scan(false, |keep, a| {
            if *keep {
                *keep = false;
                Some(Some(a.as_str()))
            } else if a == "--adjust" {
                *keep = true;
                Some(None)
            } else {
                Some(None)
            }
        })
        .flatten()
        .collect()
}

/// Parse `"<idx>:<+|-><a>,<b>,<c>,<d>"` into (idx, plus, limbs).
fn parse_adjust(spec: &str) -> Result<(usize, bool, [u32; 4]), String> {
    let (idx_part, rest) = spec
        .split_once(':')
        .ok_or_else(|| format!("adjust spec missing ':': {spec}"))?;
    let idx: usize = idx_part
        .trim()
        .parse()
        .map_err(|e| format!("adjust spec index: {e}"))?;
    let (plus, limbs_part) = if let Some(stripped) = rest.strip_prefix('+') {
        (true, stripped)
    } else if let Some(stripped) = rest.strip_prefix('-') {
        (false, stripped)
    } else {
        return Err(format!("adjust spec must start with +/-: {spec}"));
    };
    let parts: Vec<u32> = limbs_part
        .split(',')
        .map(|p| {
            p.trim()
                .parse::<u32>()
                .map_err(|e| format!("adjust spec limb: {e}"))
        })
        .collect::<Result<_, _>>()?;
    if parts.len() != 4 {
        return Err(format!("adjust spec needs 4 limbs: {spec}"));
    }
    Ok((idx, plus, [parts[0], parts[1], parts[2], parts[3]]))
}

fn cmd_serve(args: &[String]) -> i32 {
    let stmt_path = PathBuf::from(require_arg(args, "--statement"));
    let stmt = match Statement::load(&stmt_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let flag_file = flag_arg(args, "--flag-file")
        .map(PathBuf::from)
        .unwrap_or_else(|| stmt.flag_file.clone());

    println!("zkvm-fs verifier ready");
    println!("statement: {}", stmt_path.display());
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(0) => return 0,
        Ok(_) => {}
        Err(e) => {
            eprintln!("read error: {e}");
            return 1;
        }
    }
    let line = input.trim();
    let proof_bytes = match hex_decode(line) {
        Some(b) => b,
        None => {
            println!("REJECT: payload is not a hex string");
            return 0;
        }
    };
    match verify_statement_proof(&stmt, &proof_bytes) {
        Ok(()) => {
            let flag = std::fs::read_to_string(&flag_file)
                .map_err(|e| format!("FLAG-FILE-UNREADABLE ({e})"))
                .unwrap_or_else(|e| e);
            println!("ACCEPT");
            println!("{}", flag.trim());
        }
        Err(err) => {
            println!("REJECT: {err}");
        }
    }
    0
}

/// Full verifier-side check: ELF hash pin, proof parse, expected-view verify.
pub fn verify_statement_proof(stmt: &Statement, proof_bytes: &[u8]) -> Result<(), String> {
    let elf_bytes = std::fs::read(&stmt.guest)
        .map_err(|e| format!("cannot read guest elf {}: {e}", stmt.guest.display()))?;
    let hash = sha256_hex(&elf_bytes);
    if hash != stmt.guest_sha256 {
        return Err(format!(
            "guest ELF hash mismatch: expected {}, got {}",
            stmt.guest_sha256, hash
        ));
    }
    let sdk_proof: SdkProof = postcard::from_bytes(proof_bytes)
        .map_err(|e| format!("proof parse failed: {e}"))?;
    let elf = nexus_core::nvm::ElfFile::from_bytes(&elf_bytes)
        .map_err(|e| format!("elf parse failed: {e}"))?;
    sdk_proof
        .verify_expected::<(u32, u32, u32), bool>(
            &stmt.public_input,
            stmt.exit_code,
            &stmt.expected_output,
            &elf,
            &[],
        )
        .map_err(|e| format!("verification failed: {e}"))
}

fn cmd_info(args: &[String]) -> i32 {
    let stmt_path = PathBuf::from(require_arg(args, "--statement"));
    let stmt = match Statement::load(&stmt_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let elf_bytes = match std::fs::read(&stmt.guest) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read guest elf: {e}");
            return 2;
        }
    };
    println!("guest: {}", stmt.guest.display());
    println!("guest_sha256: {}", sha256_hex(&elf_bytes));
    println!("public_input: {},{},{}", stmt.public_input.0, stmt.public_input.1, stmt.public_input.2);
    println!("exit_code: {}", stmt.exit_code);
    println!("expected_output: {}", stmt.expected_output);
    println!("encoded_public_input: {}", hex_encode(&stmt.encoded_public_input()));
    println!("encoded_expected_output: {}", hex_encode(&stmt.encoded_expected_output()));
    println!("flag_file: {}", stmt.flag_file.display());
    0
}

fn prove_statement(stmt: &Statement, force_output: Option<Vec<u8>>) -> Result<SdkProof, String> {
    if let Some(bytes) = force_output {
        std::env::set_var("NEXUS_FORCE_OUTPUT_HEX", hex_encode(&bytes));
    }
    // The vendored prover skips its own OODS consistency check under
    // NEXUS_IGNORE_UNSAT=1; the forge path needs it because the forced output
    // makes the witness inconsistent by construction.
    std::env::set_var("NEXUS_IGNORE_UNSAT", "1");

    let prover = Stwo::new_from_file(&stmt.guest).map_err(|e| format!("elf load: {e}"))?;
    let mut prover = prover;
    prover
        .set_associated_data(&[])
        .map_err(|e| format!("associated data: {e}"))?;
    let (view, proof) = prover
        .prove_with_input::<(), (u32, u32, u32)>(&(), &stmt.public_input)
        .map_err(|e| format!("proving failed: {e}"))?;
    std::env::remove_var("NEXUS_IGNORE_UNSAT");
    std::env::remove_var("NEXUS_FORCE_OUTPUT_HEX");
    let exit_ok = view
        .exit_code()
        .map(|c| c == KnownExitCodes::ExitSuccess as u32)
        .unwrap_or(false);
    eprintln!("trace exit code ok: {exit_ok}");
    Ok(proof)
}

fn write_proof(out_path: &str, proof: &SdkProof) -> Result<(), String> {
    let bytes = postcard::to_stdvec(proof).map_err(|e| format!("proof serialize: {e}"))?;
    std::fs::write(out_path, &bytes).map_err(|e| format!("write {}: {e}", out_path))?;
    eprintln!("proof written: {} bytes -> {}", bytes.len(), out_path);
    Ok(())
}

fn cmd_prove_honest(args: &[String]) -> i32 {
    let stmt_path = PathBuf::from(require_arg(args, "--statement"));
    let out_path = require_arg(args, "--out");
    let stmt = match Statement::load(&stmt_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    match prove_statement(&stmt, None).and_then(|p| write_proof(out_path, &p)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn cmd_forge(args: &[String]) -> i32 {
    let stmt_path = PathBuf::from(require_arg(args, "--statement"));
    let out_path = require_arg(args, "--out");
    let stmt = match Statement::load(&stmt_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let forced = match flag_arg(args, "--force-output") {
        Some(hex) => match hex_decode(hex) {
            Some(b) if !b.is_empty() => b,
            _ => {
                eprintln!("--force-output must be non-empty hex bytes");
                return 2;
            }
        },
        None => stmt.encoded_expected_output(),
    };
    let mut proof = match prove_statement(&stmt, Some(forced)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    for spec in adjust_specs(args).iter().flat_map(|s| s.split(';')) {
        if let Err(e) = apply_adjust(&mut proof, spec) {
            eprintln!("{e}");
            return 2;
        }
    }
    match write_proof(out_path, &proof) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn apply_adjust(proof: &mut SdkProof, spec: &str) -> Result<(), String> {
    let (idx, plus, limbs) = parse_adjust(spec)?;
    let val = SecureField::from_m31(
        m31_from_canonical(limbs[0]),
        m31_from_canonical(limbs[1]),
        m31_from_canonical(limbs[2]),
        m31_from_canonical(limbs[3]),
    );
    let sums = &mut proof.proof.claimed_sum;
    if idx >= sums.len() {
        return Err(format!("adjust index {idx} out of range (len {})", sums.len()));
    }
    if plus {
        sums[idx] = sums[idx] + val;
    } else {
        sums[idx] = sums[idx] - val;
    }
    Ok(())
}

fn m31_from_canonical(v: u32) -> M31 {
    // Limbs arrive canonical (< 2^31-1) from the statement-side tooling.
    M31::from_u32_unchecked(v)
}

/// Apply `--adjust` specs to a proof file and write the result. No proving.
fn cmd_patch(args: &[String]) -> i32 {
    let in_path = require_arg(args, "--in");
    let out_path = require_arg(args, "--out");
    let bytes = match std::fs::read(in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read proof: {e}");
            return 2;
        }
    };
    let mut sdk_proof: SdkProof = match postcard::from_bytes(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("proof parse failed: {e}");
            return 2;
        }
    };
    let specs = adjust_specs(args);
    if specs.is_empty() {
        eprintln!("patch requires at least one --adjust spec");
        return 2;
    }
    for spec in specs.iter().flat_map(|s| s.split(';')) {
        if let Err(e) = apply_adjust(&mut sdk_proof, spec) {
            eprintln!("{e}");
            return 2;
        }
    }
    match write_proof(out_path, &sdk_proof) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn cmd_verify_probe(args: &[String]) -> i32 {
    let stmt_path = PathBuf::from(require_arg(args, "--statement"));
    let in_path = require_arg(args, "--in");
    let stmt = match Statement::load(&stmt_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let mut stmt = stmt;
    if args.iter().any(|a| a == "--honest") {
        // Positive control: verify against the honest (false) output.
        stmt.expected_output = !stmt.expected_output;
    }
    let bytes = match std::fs::read(in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read proof: {e}");
            return 2;
        }
    };
    let mut sdk_proof: SdkProof = match postcard::from_bytes(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("proof parse failed: {e}");
            return 2;
        }
    };
    for spec in adjust_specs(args).iter().flat_map(|s| s.split(';')) {
        if let Err(e) = apply_adjust(&mut sdk_proof, spec) {
            eprintln!("{e}");
            return 2;
        }
    }
    // The instrumented stwo build prints the two OODS sides when this is set.
    std::env::set_var("NEXUS_INSTRUMENT", "1");
    let elf = match load_elf(&stmt) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let result = sdk_proof.verify_expected::<(u32, u32, u32), bool>(
        &stmt.public_input,
        stmt.exit_code,
        &stmt.expected_output,
        &elf,
        &[],
    );
    eprintln!("probe expected_output={}", stmt.expected_output);
    std::env::remove_var("NEXUS_INSTRUMENT");
    match result {
        Ok(()) => {
            println!("VERIFY OK");
            0
        }
        Err(e) => {
            eprintln!("VERIFY FAIL: {e}");
            1
        }
    }
}

fn load_elf(stmt: &Statement) -> Result<nexus_core::nvm::ElfFile, String> {
    let elf_bytes = std::fs::read(&stmt.guest)
        .map_err(|e| format!("cannot read guest elf {}: {e}", stmt.guest.display()))?;
    let hash = sha256_hex(&elf_bytes);
    if hash != stmt.guest_sha256 {
        return Err(format!(
            "guest ELF hash mismatch: expected {}, got {}",
            stmt.guest_sha256, hash
        ));
    }
    nexus_core::nvm::ElfFile::from_bytes(&elf_bytes).map_err(|e| format!("elf parse: {e}"))
}

fn cmd_submit(args: &[String]) -> i32 {
    let in_path = require_arg(args, "--in");
    let host = require_arg(args, "--host");
    let bytes = match std::fs::read(in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read proof: {e}");
            return 2;
        }
    };
    let payload = hex_encode(&bytes);
    let stream = match std::net::TcpStream::connect(host) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connect {host}: {e}");
            return 1;
        }
    };
    let mut stream = stream;
    if let Err(e) = stream.write_all(payload.as_bytes()) {
        eprintln!("send: {e}");
        return 1;
    }
    let _ = stream.write_all(b"\n");
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut response = String::new();
    if let Err(e) = stream.read_to_string(&mut response) {
        eprintln!("recv: {e}");
        return 1;
    }
    print!("{response}");
    0
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    hex_encode(&out)
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
