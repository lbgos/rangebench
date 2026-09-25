//! Statement file parsing shared by the verifier service and the forge tool.
//!
//! Statement file format (lines, `#` comments allowed):
//! ```text
//! guest = guest.elf
//! guest_sha256 = <64 hex chars>
//! public_input = 31,47,66
//! exit_code = 0
//! expected_output = true
//! flag_file = /flag
//! ```
//! `guest` is resolved relative to the statement file directory.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Statement {
    pub guest: PathBuf,
    pub guest_sha256: String,
    pub public_input: (u32, u32, u32),
    pub exit_code: u32,
    pub expected_output: bool,
    pub flag_file: PathBuf,
}

impl Statement {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read statement {}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut guest: Option<String> = None;
        let mut guest_sha256: Option<String> = None;
        let mut public_input: Option<(u32, u32, u32)> = None;
        let mut exit_code: Option<u32> = None;
        let mut expected_output: Option<bool> = None;
        let mut flag_file: Option<String> = None;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("statement line {}: missing '='", lineno + 1))?;
            let value = value.trim();
            match key.trim() {
                "guest" => guest = Some(value.to_string()),
                "guest_sha256" => guest_sha256 = Some(value.to_lowercase()),
                "public_input" => {
                    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
                    if parts.len() != 3 {
                        return Err(format!("statement line {}: expected 3 ints", lineno + 1));
                    }
                    let nums: Result<Vec<u32>, _> = parts.iter().map(|p| p.parse()).collect();
                    let nums = nums.map_err(|e| format!("statement line {}: {e}", lineno + 1))?;
                    public_input = Some((nums[0], nums[1], nums[2]));
                }
                "exit_code" => {
                    exit_code =
                        Some(value.parse().map_err(|e| format!("statement line {}: {e}", lineno + 1))?);
                }
                "expected_output" => match value {
                    "true" => expected_output = Some(true),
                    "false" => expected_output = Some(false),
                    other => {
                        return Err(format!(
                            "statement line {}: expected true/false, got {other}",
                            lineno + 1
                        ))
                    }
                },
                "flag_file" => flag_file = Some(value.to_string()),
                other => return Err(format!("statement line {}: unknown key {other}", lineno + 1)),
            }
        }
        Ok(Statement {
            guest: dir.join(guest.ok_or("statement missing 'guest'")?),
            guest_sha256: guest_sha256.ok_or("statement missing 'guest_sha256'")?,
            public_input: public_input.ok_or("statement missing 'public_input'")?,
            exit_code: exit_code.ok_or("statement missing 'exit_code'")?,
            expected_output: expected_output.ok_or("statement missing 'expected_output'")?,
            flag_file: PathBuf::from(flag_file.ok_or("statement missing 'flag_file'")?),
        })
    }

    /// Serialize the public input exactly the way the SDK encodes guest inputs
    /// (postcard COBS of the tuple, padded to 4-byte alignment).
    pub fn encoded_public_input(&self) -> Vec<u8> {
        encode_input_typed(&self.public_input)
    }

    /// Serialize the expected public output exactly the way
    /// `sdk::Verifiable::verify_expected` encodes it.
    pub fn encoded_expected_output(&self) -> Vec<u8> {
        encode_output_typed(&self.expected_output)
    }
}

/// Mirrors `sdk::Prover::encode_input`: postcard serialization, COBS framing
/// for non-empty payloads, zero padding to 4-byte alignment.
pub fn encode_input_typed<T: serde::Serialize + Sized>(val: &T) -> Vec<u8> {
    let mut encoded = postcard::to_stdvec(val).expect("postcard encode");
    if !encoded.is_empty() {
        encoded = postcard::to_stdvec_cobs(val).expect("postcard cobs encode");
        let padded_len = (encoded.len() + 3) & !3;
        encoded.resize(padded_len, 0x00); // cobs ignores 0x00 padding
    }
    encoded
}

/// Same encoding path as `verify_expected` uses for the public output.
pub fn encode_output_typed<T: serde::Serialize + Sized>(val: &T) -> Vec<u8> {
    encode_input_typed(val)
}
