//! Find asymmetric keys
use crate::error::Error;
use crate::key::{AsymmetricKey, RSAPartialPrivateKey, RSAPrivateKey, RSAPublicKey};

use rug::{integer::Order, Integer};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Base size of the buffer that is searched for keys.
/// A key has to fit into this size in order to be found.
/// A RSA-4096 private key in PEM format (so base64-encoded) takes 3247 bytes.
///
/// N.B. The larger the buffer, the more approximate the printed offset
const MARKER_BUFFER_BASE_SIZE: usize = 8096;

/// Mapping to decode hexadecimal-encoded data
const HEX_MAPPING: [i8; 256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10,
    11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

/// Mapping to decode base64-encoded data, included base64url-encoded data (where + is - and / is _)
const BASE64_MAPPING: [i8; 256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, -1, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

#[derive(Default)]
pub struct FinderConfig {
    pub verbose: bool,
    pub find_public: bool,
    pub keep_duplicate: bool,
}

impl FinderConfig {
    pub fn into_context(self) -> FinderContext {
        FinderContext {
            cfg: self,
            found_keys: HashMap::new(),
        }
    }
}

pub struct FinderContext {
    pub cfg: FinderConfig,
    pub found_keys: HashMap<Vec<u8>, AsymmetricKey>,
}

impl FinderContext {
    /// Find asymmetric keys in a file
    pub fn find_in_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<(), Error> {
        let file = File::open(&file_path)
            .map_err(|e| Error::IoWithPath(file_path.as_ref().to_path_buf(), e))?;
        let reader = BufReader::new(file);
        self.find_in_reader(reader).map_err(|e| match e {
            Error::IoWithoutPath(io_err) => {
                Error::IoWithPath(file_path.as_ref().to_path_buf(), io_err)
            }
            _ => e,
        })
    }

    /// Find asymmetric keys in a stream
    pub fn find_in_reader<R: Read>(&mut self, mut reader: R) -> Result<(), Error> {
        // Read bytes until finding a marker
        let mut buffer = vec![0; MARKER_BUFFER_BASE_SIZE * 2];
        let mut buffer_size = 0;
        let mut absolute_offset: u64 = 0;
        loop {
            let read_size = reader
                .read(&mut buffer[buffer_size..])
                .map_err(Error::IoWithoutPath)?;
            buffer_size += read_size;

            // Read while MARKER_BUFFER_BASE_SIZE has not been reached, except when reaching the end
            if buffer_size < MARKER_BUFFER_BASE_SIZE && read_size != 0 {
                continue;
            }

            self.find_in_buffer(&buffer[..buffer_size], absolute_offset, "");

            if buffer_size < MARKER_BUFFER_BASE_SIZE {
                break;
            }

            // Copy buffer[MARKER_BUFFER_BASE_SIZE..buffer_size] to the beginning of buffer
            buffer_size -= MARKER_BUFFER_BASE_SIZE;
            for offset in 0..buffer_size {
                buffer[offset] = buffer[MARKER_BUFFER_BASE_SIZE + offset];
            }
            absolute_offset += MARKER_BUFFER_BASE_SIZE as u64;
        }
        Ok(())
    }

    /// Find asymmetric keys in a buffer.
    ///
    /// Decode the buffer as base64 or hexadecimal, recursively, and find keys in the data
    pub fn find_in_buffer(&mut self, buffer: &[u8], absolute_offset: u64, zone_kind: &str) {
        let zone_or_raw = if zone_kind.is_empty() {
            "raw"
        } else {
            zone_kind
        };
        self.find_in_binary_buffer(buffer, absolute_offset, zone_or_raw);

        // For base64 and hexadecimal decoding, the offset is modified "incorrectly", with some approximation.
        // It is not worth it to have a byte-precise position of the key, and knowing which page contained it enables
        // for a more precise search.

        // Bytes decoded from hexadecimal
        let mut hex_buffer0 = Vec::new();
        // Bytes decoded from hexadecimal with a shift of 4 bits
        let mut hex_buffer4 = vec![0];
        let mut hex_state = 0;

        // Bytes decoded from base64, with shifts of 0, 2, 4 or 6 bits for the first byte (in case of false-start)
        let mut base64_buffer0 = Vec::new();
        let mut base64_buffer2 = vec![0];
        let mut base64_buffer4 = vec![0];
        let mut base64_buffer6 = vec![0];
        let mut base64_state = 0;

        for cur_byte in buffer.iter() {
            let hex_symbol = HEX_MAPPING[*cur_byte as usize];
            if hex_symbol >= 0 {
                match hex_state {
                    0 => {
                        hex_buffer0.push((hex_symbol as u8) << 4);
                        *hex_buffer4.last_mut().unwrap() += hex_symbol as u8;
                        hex_state = 1;
                    }
                    1 => {
                        *hex_buffer0.last_mut().unwrap() += hex_symbol as u8;
                        hex_buffer4.push((hex_symbol as u8) << 4);
                        hex_state = 0;
                    }
                    _ => unreachable!(),
                }
            }
            let b64_symbol = BASE64_MAPPING[*cur_byte as usize];
            if b64_symbol >= 0 {
                match base64_state {
                    0 => {
                        base64_buffer0.push((b64_symbol as u8) << 2);
                        *base64_buffer2.last_mut().unwrap() += b64_symbol as u8;
                        *base64_buffer4.last_mut().unwrap() += (b64_symbol as u8) >> 2;
                        base64_buffer4.push((b64_symbol as u8) << 6);
                        *base64_buffer6.last_mut().unwrap() += (b64_symbol as u8) >> 4;
                        base64_buffer6.push((b64_symbol as u8) << 4);
                        base64_state = 1;
                    }
                    1 => {
                        *base64_buffer0.last_mut().unwrap() += (b64_symbol as u8) >> 4;
                        base64_buffer0.push((b64_symbol as u8) << 4);
                        base64_buffer2.push((b64_symbol as u8) << 2);
                        *base64_buffer4.last_mut().unwrap() += b64_symbol as u8;
                        *base64_buffer6.last_mut().unwrap() += (b64_symbol as u8) >> 2;
                        base64_buffer6.push((b64_symbol as u8) << 6);
                        base64_state = 2;
                    }
                    2 => {
                        *base64_buffer0.last_mut().unwrap() += (b64_symbol as u8) >> 2;
                        base64_buffer0.push((b64_symbol as u8) << 6);
                        *base64_buffer2.last_mut().unwrap() += (b64_symbol as u8) >> 4;
                        base64_buffer2.push((b64_symbol as u8) << 4);
                        base64_buffer4.push((b64_symbol as u8) << 2);
                        *base64_buffer6.last_mut().unwrap() += b64_symbol as u8;
                        base64_state = 3;
                    }
                    3 => {
                        *base64_buffer0.last_mut().unwrap() += b64_symbol as u8;
                        *base64_buffer2.last_mut().unwrap() += (b64_symbol as u8) >> 2;
                        base64_buffer2.push((b64_symbol as u8) << 6);
                        *base64_buffer4.last_mut().unwrap() += (b64_symbol as u8) >> 4;
                        base64_buffer4.push((b64_symbol as u8) << 4);
                        base64_buffer6.push((b64_symbol as u8) << 2);
                        base64_state = 0;
                    }
                    _ => unreachable!(),
                }
            }
        }
        if hex_buffer0.len() >= 0x10 {
            let zone_prefix = if zone_kind.is_empty() {
                "hex".to_owned()
            } else {
                format!("{}/hex", zone_kind)
            };
            self.find_in_buffer(&hex_buffer0, absolute_offset, &zone_prefix);
            self.find_in_buffer(&hex_buffer4, absolute_offset, &(zone_prefix + "+4"));
        }
        if base64_buffer0.len() >= 0x10 {
            let zone_prefix = if zone_kind.is_empty() {
                "b64".to_owned()
            } else {
                format!("{}/b64", zone_kind)
            };
            self.find_in_buffer(&base64_buffer0, absolute_offset, &zone_prefix);
            self.find_in_buffer(
                &base64_buffer2,
                absolute_offset,
                &format!("{}+2", zone_prefix),
            );
            self.find_in_buffer(
                &base64_buffer4,
                absolute_offset,
                &format!("{}+4", zone_prefix),
            );
            self.find_in_buffer(
                &base64_buffer6,
                absolute_offset,
                &format!("{}+6", zone_prefix),
            );
        }
    }

    /// Find asymmetric keys in a buffer, without trying to decode it in base64
    pub fn find_in_binary_buffer(&mut self, buffer: &[u8], absolute_offset: u64, zone_kind: &str) {
        for start_offset in 0..buffer.len() {
            // ASN.1 sequence in DER format, with at least 128 bytes of data
            if buffer[start_offset] == 0x30 && start_offset + 128 < buffer.len() {
                // Decode length:
                // * Length between 0 and 127 are encoded as-is, on one bytes.
                // * Larger lengths are encoded by [0x80 + size of length] and the length, in Big Endian.
                let seq_len_byte = buffer[start_offset + 1];
                if seq_len_byte < 0x80 {
                    // Skip "keys" that would be too small
                    if seq_len_byte >= 0x20 {
                        let mut end_offset = start_offset + 2 + (seq_len_byte as usize);
                        if end_offset >= buffer.len() {
                            // Support truncated ASN.1 objects
                            end_offset = buffer.len()
                        }
                        self.gather_from_asn1_der_seq(
                            &buffer[start_offset + 2..end_offset],
                            absolute_offset + (start_offset as u64),
                            zone_kind,
                        );
                    }
                } else if seq_len_byte == 0x81 {
                    // 1-byte length
                    let seq_len = buffer[start_offset + 2] as usize;
                    let mut end_offset = start_offset + 3 + seq_len;
                    if end_offset >= buffer.len() {
                        end_offset = buffer.len()
                    }
                    self.gather_from_asn1_der_seq(
                        &buffer[start_offset + 3..end_offset],
                        absolute_offset + (start_offset as u64),
                        zone_kind,
                    );
                } else if seq_len_byte == 0x82 {
                    // 2-byte length
                    let seq_len = ((buffer[start_offset + 2] as usize) << 8)
                        | (buffer[start_offset + 3] as usize);
                    let mut end_offset = start_offset + 4 + seq_len;
                    if end_offset >= buffer.len() {
                        end_offset = buffer.len()
                    }
                    self.gather_from_asn1_der_seq(
                        &buffer[start_offset + 4..end_offset],
                        absolute_offset + (start_offset as u64),
                        zone_kind,
                    );
                }
            }

            // SSH RSA key pattern, with string length + "ssh-rsa",
            // with at least 128 bytes of data
            if buffer[start_offset] == 0x07
                && start_offset + 128 < buffer.len()
                && &buffer[start_offset + 1..start_offset + 8] == b"ssh-rsa"
            {
                self.gather_from_ssh_rsa(
                    &buffer[start_offset + 8..],
                    absolute_offset + (start_offset as u64),
                    zone_kind,
                )
            }
        }
    }

    fn gather_found_key(
        &mut self,
        key: AsymmetricKey,
        function: &str,
        absolute_offset: u64,
        zone_kind: &str,
    ) {
        // If the key already exists, replace it if it is newer
        if let Some(existing_key) = self.found_keys.get(key.hash()) {
            if key.is_better_than(existing_key) {
                if self.cfg.verbose {
                    println!(
                        "Expanding info for {} key @{:#x}[{}]: {}",
                        function, absolute_offset, zone_kind, key
                    );
                }
                self.found_keys.insert(key.hash().to_vec(), key);
            } else if self.cfg.keep_duplicate && self.cfg.verbose {
                println!(
                    "Found duplicate {} key @{:#x}[{}]: {}",
                    function, absolute_offset, zone_kind, key
                );
            }
        } else {
            if self.cfg.verbose {
                println!(
                    "Found new {} key @{:#x}[{}]: {}",
                    function, absolute_offset, zone_kind, key
                );
            }
            self.found_keys.insert(key.hash().to_vec(), key);
        }
    }

    /// Gather asymmetric keys from a buffer that could be an ASN.1 sequence encoded in DER
    pub fn gather_from_asn1_der_seq(
        &mut self,
        buffer: &[u8],
        absolute_offset: u64,
        zone_kind: &str,
    ) {
        if let Some(key) = find_key_in_asn1_der_seq(&self.cfg, buffer) {
            self.gather_found_key(key, "ASN.1", absolute_offset, zone_kind);
        }
    }

    /// Gather asymmetric keys from a buffer that could be an SSH RSA public or private key
    pub fn gather_from_ssh_rsa(&mut self, buffer: &[u8], absolute_offset: u64, zone_kind: &str) {
        if let Some(key) = find_key_in_ssh_rsa(&self.cfg, buffer) {
            self.gather_found_key(key, "SSH", absolute_offset, zone_kind);
        }
    }
}

/// Decode an ASN.1 integer in DER format as a big integer
fn decode_asn1_integer(buffer: &[u8], offset: &mut usize) -> Option<Integer> {
    // The minimal size of an integer is 3, for the tag, size and content
    if *offset + 3 > buffer.len() {
        return None;
    }
    // Check that the object uses an Integer tag
    if buffer[*offset] != 0x02 {
        return None;
    }
    let len_byte = buffer[*offset + 1];
    let offset_start;
    let offset_end;
    if len_byte == 0 {
        return None;
    } else if len_byte < 0x80 {
        offset_start = *offset + 2;
        offset_end = offset_start + (len_byte as usize);
    } else if len_byte == 0x81 {
        let int_len = buffer[*offset + 2] as usize;
        offset_start = *offset + 3;
        offset_end = offset_start + int_len;
    } else if len_byte == 0x82 {
        let int_len = ((buffer[*offset + 2] as usize) << 8) | (buffer[*offset + 3] as usize);
        offset_start = *offset + 4;
        offset_end = offset_start + int_len;
    } else {
        // Do not consider integers larger that 2**(2**16)
        return None;
    }
    if offset_end > buffer.len() {
        return None;
    }
    *offset = offset_end;
    Some(Integer::from_digits(
        &buffer[offset_start..offset_end],
        Order::Msf,
    ))
}

/// Find asymmetric keys in a buffer that could be an ASN.1 sequence encoded in DER
fn find_key_in_asn1_der_seq(cfg: &FinderConfig, buffer: &[u8]) -> Option<AsymmetricKey> {
    // It needs at least some bytes in order to be interesting
    if buffer.len() <= 0x10 {
        return None;
    }

    // RSA public keys are encoded as sequences of two integers: modulus, publicExponent
    // RSA private keys are encoded as sequences of integers: version, modulus, publicExponent, privateExponent, prime1, prime2
    // Integer tag
    if buffer[0] == 0x02 {
        let mut offset = 0;
        // RSA private keys starts with a "version" field which is a 1-byte integer
        if buffer[..2] == [0x02, 0x01] {
            offset += 3;
        }

        if let Some(modulus) = decode_asn1_integer(buffer, &mut offset) {
            // Filter-out even modulus and small modulus
            if modulus.is_odd() || modulus > 0x0010_0000 {
                if let Some(pubexp) = decode_asn1_integer(buffer, &mut offset) {
                    if pubexp >= 3 {
                        // Try getting a private key
                        if let Some(privexp) = decode_asn1_integer(buffer, &mut offset) {
                            if privexp > 1 {
                                if let Some(p) = decode_asn1_integer(buffer, &mut offset) {
                                    if let Some(q) = decode_asn1_integer(buffer, &mut offset) {
                                        if let Some(privkey) = RSAPrivateKey::checked_new(
                                            &modulus, &pubexp, &privexp, &p, &q,
                                        ) {
                                            return Some(AsymmetricKey::RSAPriv(privkey));
                                        }
                                    }
                                }
                                // Reading the primes failed. Try building a partial private key
                                if let Some(privkey) =
                                    RSAPartialPrivateKey::checked_new(&modulus, &pubexp, &privexp)
                                {
                                    return Some(AsymmetricKey::RSAPartPriv(privkey));
                                }
                            }
                        }
                        // Reading a private RSA key failed. Try build a public key
                        if cfg.find_public {
                            if let Some(pubkey) = RSAPublicKey::checked_new(&modulus, &pubexp) {
                                return Some(AsymmetricKey::RSAPub(pubkey));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Decode an integer in openSSH format as a big integer
fn decode_openssh_integer(buffer: &[u8], offset: &mut usize) -> Option<Integer> {
    let cur_offset = *offset;
    let offset_start = cur_offset + 4;
    if offset_start > buffer.len() {
        return None;
    }
    let int_length = Integer::from_digits(&buffer[cur_offset..offset_start], Order::Msf)
        .to_u32()
        .expect("Integer::to_u32");
    if int_length == 0 {
        return None;
    }
    let offset_end = offset_start + (int_length as usize);
    if offset_end > buffer.len() {
        return None;
    }
    *offset = offset_end;
    Some(Integer::from_digits(
        &buffer[offset_start..offset_end],
        Order::Msf,
    ))
}

/// Find asymmetric keys in a buffer that could be in OpenSSH format
///
/// buffer points right after a "ssh-rsa" token
fn find_key_in_ssh_rsa(cfg: &FinderConfig, buffer: &[u8]) -> Option<AsymmetricKey> {
    // It needs at least some bytes in order to be interesting
    if buffer.len() <= 0x10 {
        return None;
    }

    // In OpenSSH keys, byte vectors are prefixed by  their size as 32-bit Big Endian integer.
    // RSA public keys are encoded as ["ssh-rsa", public_exponent, modulus]
    // RSA private keys are encoded as ["ssh-rsa", modulus, public_exponent, private_exponent, qInv, p, q, comment]
    let mut offset = 0;
    if let Some(n1) = decode_openssh_integer(buffer, &mut offset) {
        if let Some(n2) = decode_openssh_integer(buffer, &mut offset) {
            if n1.is_odd() && n2.is_odd() {
                let (modulus, pub_exp) = if n1 > n2 { (n1, n2) } else { (n2, n1) };
                if let Some(priv_exp) = decode_openssh_integer(buffer, &mut offset) {
                    if let Some(q_inv) = decode_openssh_integer(buffer, &mut offset) {
                        if let Some(p) = decode_openssh_integer(buffer, &mut offset) {
                            if let Some(q) = decode_openssh_integer(buffer, &mut offset) {
                                if let Some(privkey) = RSAPrivateKey::checked_new(
                                    &modulus, &pub_exp, &priv_exp, &p, &q,
                                ) {
                                    // Check qInv = q^-1 mod p
                                    let q_ii = q_inv.invert(&p).expect("q_inv.invert");
                                    assert_eq!(q_ii, q);
                                    return Some(AsymmetricKey::RSAPriv(privkey));
                                }
                            }
                            // Maybe q is corrupted, try recovering it from qInc
                            if let Ok(q_ii) = q_inv.invert(&p) {
                                if let Some(privkey) = RSAPrivateKey::checked_new(
                                    &modulus, &pub_exp, &priv_exp, &p, &q_ii,
                                ) {
                                    return Some(AsymmetricKey::RSAPriv(privkey));
                                }
                            }
                        }
                    }
                    // Reading the primes failed. Try building a partial private key
                    if let Some(privkey) =
                        RSAPartialPrivateKey::checked_new(&modulus, &pub_exp, &priv_exp)
                    {
                        return Some(AsymmetricKey::RSAPartPriv(privkey));
                    }
                }
                // Reading a private RSA key failed. Try build a public key
                if cfg.find_public {
                    if let Some(pubkey) = RSAPublicKey::checked_new(&modulus, &pub_exp) {
                        return Some(AsymmetricKey::RSAPub(pubkey));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    #[test]
    fn test_openssl_rsa_key() {
        // Generate a RSA key in PEM format using OpenSSL and convert it to DER
        let tmp_dir = TempDir::new().expect("TempDir::new");
        let privkey_pem_file = tmp_dir.path().join("privkey.pem");
        let privkey_der_file = tmp_dir.path().join("privkey.der");
        let pubkey_pem_file = tmp_dir.path().join("pubkey.pem");
        let pubkey_der_file = tmp_dir.path().join("pubkey.der");
        assert!(Command::new("openssl")
            .arg("genrsa")
            .arg("-out")
            .arg(&privkey_pem_file)
            .arg("2048")
            .stderr(Stdio::null())
            .status()
            .expect("run openssl genrsa")
            .success());
        assert!(Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&privkey_pem_file)
            .arg("-out")
            .arg(&privkey_der_file)
            .arg("-outform")
            .arg("DER")
            .stderr(Stdio::null())
            .status()
            .expect("run openssl rsa")
            .success());

        // Read the RSA key in DER format
        let mut privkey_der = Vec::new();
        File::open(&privkey_der_file)
            .expect("File::open(privkey.der)")
            .read_to_end(&mut privkey_der)
            .expect("privkey_der_file.read_to_end");

        let mut ctx_der = FinderConfig::default().into_context();
        ctx_der.find_in_binary_buffer(&privkey_der, 0, "");
        assert_eq!(ctx_der.found_keys.len(), 1);
        let generated_key = ctx_der
            .found_keys
            .values()
            .next()
            .expect("found_keys.values().next()")
            .as_rsa_priv()
            .expect("as_rsa_priv")
            .clone();
        drop(ctx_der);

        {
            let mut ctx_der2 = FinderConfig::default().into_context();
            ctx_der2.find_in_buffer(&privkey_der, 0, "");
            assert_eq!(ctx_der2.found_keys.len(), 1);
            assert_eq!(
                ctx_der2
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPriv(generated_key.clone())
            );
        }

        // Read the RSA key in PEM format
        let mut privkey_pem = Vec::new();
        File::open(&privkey_pem_file)
            .expect("File::open(privkey.pem)")
            .read_to_end(&mut privkey_pem)
            .expect("privkey_pem_file.read_to_end");
        {
            let mut ctx_pem = FinderConfig::default().into_context();
            ctx_pem.find_in_buffer(&privkey_pem, 0, "");
            assert_eq!(ctx_pem.found_keys.len(), 1);
            assert_eq!(
                ctx_pem
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPriv(generated_key.clone())
            );
        }

        // Encode the PEM with hexadecimal and spaces, to check hex+base64 encoding
        {
            let mut hex_string = String::with_capacity(3 * privkey_pem.len());
            for x in privkey_pem.iter() {
                write!(hex_string, "{:02x} ", x).expect("write");
            }
            let mut ctx_hexpem = FinderConfig::default().into_context();
            ctx_hexpem.find_in_buffer(hex_string.as_bytes(), 0, "");
            assert_eq!(ctx_hexpem.found_keys.len(), 1);
            assert_eq!(
                ctx_hexpem
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPriv(generated_key.clone())
            );
        }
        // Hexadecimal again, but uppercase and with a shift
        {
            let mut hex_string = String::with_capacity(3 + 2 * privkey_pem.len());
            write!(hex_string, "101").expect("write");
            for x in privkey_pem.iter() {
                write!(hex_string, "{:02X}", x).expect("write");
            }
            let mut ctx_hexpem = FinderConfig::default().into_context();
            ctx_hexpem.find_in_buffer(hex_string.as_bytes(), 0, "");
            assert_eq!(ctx_hexpem.found_keys.len(), 1);
            assert_eq!(
                ctx_hexpem
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPriv(generated_key.clone())
            );
        }

        // Truncate the private key to corrupt the prime, and ensure that the key is partially recovered
        {
            let generated_partial_key = generated_key.clone_to_partial();
            let mut ctx_truncated_pem = FinderConfig::default().into_context();
            ctx_truncated_pem.find_in_buffer(&privkey_pem[..privkey_pem.len() / 2], 0, "");
            assert_eq!(ctx_truncated_pem.found_keys.len(), 1);
            assert_eq!(
                ctx_truncated_pem
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPartPriv(generated_partial_key.clone())
            );
        }

        // Convert the key into a public key
        let generated_pubkey = generated_key.clone_to_pub();
        assert!(Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&privkey_pem_file)
            .arg("-pubout")
            .arg("-out")
            .arg(&pubkey_der_file)
            .arg("-outform")
            .arg("DER")
            .stderr(Stdio::null())
            .status()
            .expect("run openssl rsa")
            .success());
        let mut pubkey_der = Vec::new();
        File::open(&pubkey_der_file)
            .expect("File::open(pubkey.der)")
            .read_to_end(&mut pubkey_der)
            .expect("pubkey_der_file.read_to_end");
        {
            let mut ctx_pub_der = FinderConfig::default().into_context();
            ctx_pub_der.find_in_buffer(&pubkey_der, 0, "");
            // Found nothing, because find_public option was false.
            assert_eq!(ctx_pub_der.found_keys.len(), 0);
            ctx_pub_der.cfg.find_public = true;
            ctx_pub_der.find_in_buffer(&pubkey_der, 0, "");
            assert_eq!(ctx_pub_der.found_keys.len(), 1);
            assert_eq!(
                ctx_pub_der
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPub(generated_pubkey.clone())
            );
        }

        assert!(Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&privkey_pem_file)
            .arg("-pubout")
            .arg("-out")
            .arg(&pubkey_pem_file)
            .arg("-outform")
            .arg("PEM")
            .stderr(Stdio::null())
            .status()
            .expect("run openssl rsa")
            .success());
        let mut pubkey_pem = Vec::new();
        File::open(pubkey_pem_file)
            .expect("File::open(pubkey.pem)")
            .read_to_end(&mut pubkey_pem)
            .expect("pubkey_pem_file.read_to_end");
        {
            let mut ctx_pub_pem = FinderConfig::default().into_context();
            ctx_pub_pem.find_in_buffer(&pubkey_pem, 0, "");
            assert_eq!(ctx_pub_pem.found_keys.len(), 0);
            ctx_pub_pem.cfg.find_public = true;
            ctx_pub_pem.find_in_buffer(&pubkey_pem, 0, "");
            assert_eq!(ctx_pub_pem.found_keys.len(), 1);
            assert_eq!(
                ctx_pub_pem
                    .found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPub(generated_pubkey.clone())
            );
        }
    }

    #[test]
    fn test_openssh_rsa_key() {
        // Generate a RSA key using OpenSSH's ssh-keygen
        let tmp_dir = TempDir::new().expect("TempDir::new");
        let privkey_file = tmp_dir.path().join("id_rsa_test");
        let pubkey_file = tmp_dir.path().join("id_rsa_test.pub");
        assert!(Command::new("ssh-keygen")
            .arg("-t")
            .arg("rsa")
            .arg("-b")
            .arg("2048")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&privkey_file)
            .stdout(Stdio::null())
            .status()
            .expect("run ssh-keygen -t rsa")
            .success());

        // Read the SSH private key
        let mut privkey = Vec::new();
        File::open(&privkey_file)
            .expect("File::open(ssh-privkey)")
            .read_to_end(&mut privkey)
            .expect("privkey.read_to_end");

        // Read the SSH public key
        let mut pubkey = Vec::new();
        File::open(&pubkey_file)
            .expect("File::open(ssh-pubkey)")
            .read_to_end(&mut pubkey)
            .expect("pubkey.read_to_end");

        // Find the private key
        let generated_key = {
            let mut ctx = FinderConfig::default().into_context();
            ctx.find_in_buffer(&privkey, 0, "");
            assert_eq!(ctx.found_keys.len(), 1);
            ctx.found_keys
                .values()
                .next()
                .expect("found_keys.values().next()")
                .as_rsa_priv()
                .expect("as_rsa_priv")
                .clone()
        };

        // Find the public key
        let generated_pubkey = generated_key.clone_to_pub();
        {
            let mut ctx = FinderConfig::default().into_context();
            ctx.find_in_buffer(&pubkey, 0, "");
            assert_eq!(ctx.found_keys.len(), 0);

            ctx.cfg.find_public = true;
            ctx.find_in_buffer(&pubkey, 0, "");
            assert_eq!(ctx.found_keys.len(), 1);
            assert_eq!(
                ctx.found_keys
                    .values()
                    .next()
                    .expect("found_keys.values().next()"),
                &AsymmetricKey::RSAPub(generated_pubkey.clone())
            );
        }
    }
}
