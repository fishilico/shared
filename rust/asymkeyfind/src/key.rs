//! Hold information about asymmetric keys
#![allow(clippy::many_single_char_names)]
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};
use std::fmt;

/// RSA public key
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RSAPublicKey {
    /// Modulus
    pub n: Integer,
    /// Public exponent
    pub e: Integer,
    hash: Vec<u8>,
}

impl RSAPublicKey {
    pub fn checked_new(n: &Integer, e: &Integer) -> Option<Self> {
        // Only accept the key if a looks reasonable enough
        if *e != 0x10001 {
            if *e < 3 {
                return None;
            }
            if e > n {
                return None;
            }
            if e.is_even() {
                return None;
            }
        }
        Some(RSAPublicKey {
            hash: RSAPublicKey::hash_n_e(&n, &e),
            n: n.clone(),
            e: e.clone(),
        })
    }

    /// Hash the modulus and the public exponent into a unique digest
    pub fn hash_n_e(n: &Integer, e: &Integer) -> Vec<u8> {
        let mut hasher = Sha256::default();
        hasher.update(n.to_digits(Order::Msf));
        hasher.update(e.to_digits(Order::Msf));
        hasher.finalize().to_vec()
    }
}

impl fmt::Display for RSAPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "RSAPublicKey(n[{}]={:#x}, e={:#x})",
            self.n.significant_bits(),
            self.n,
            self.e,
        )
    }
}

/// RSA public key and private exponent, without prime factors
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RSAPartialPrivateKey {
    /// Modulus
    pub n: Integer,
    /// Public exponent
    pub e: Integer,
    /// Private exponent
    pub d: Integer,
    hash: Vec<u8>,
}

impl RSAPartialPrivateKey {
    pub fn checked_new(n: &Integer, e: &Integer, d: &Integer) -> Option<Self> {
        // Try encrypting/decrypting 2 and 3 in order to test d and e
        let mut m = Integer::from(2);
        m.pow_mod_mut(d, n).expect("m.pow_mod_mut(d, n)");
        m.pow_mod_mut(e, n).expect("m.pow_mod_mut(e, n)");
        if m != 2 {
            return None;
        }
        let mut m = Integer::from(3);
        m.pow_mod_mut(d, n).expect("m.pow_mod_mut(d, n)");
        m.pow_mod_mut(e, n).expect("m.pow_mod_mut(e, n)");
        if m != 3 {
            return None;
        }
        Some(RSAPartialPrivateKey {
            hash: RSAPublicKey::hash_n_e(&n, &e),
            n: n.clone(),
            e: e.clone(),
            d: d.clone(),
        })
    }
}

impl fmt::Display for RSAPartialPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "RSAPartialPrivateKey(n[{}]={:#x}, e={:#x}, d={:#x})",
            self.n.significant_bits(),
            self.n,
            self.e,
            self.d,
        )
    }
}

/// RSA private key
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RSAPrivateKey {
    /// Modulus
    pub n: Integer,
    /// Public exponent
    pub e: Integer,
    /// Private exponent
    pub d: Integer,
    /// First prime factor
    pub p: Integer,
    /// Second prime factor
    pub q: Integer,
    hash: Vec<u8>,
}

impl RSAPrivateKey {
    pub fn checked_new(
        n: &Integer,
        e: &Integer,
        d: &Integer,
        p: &Integer,
        q: &Integer,
    ) -> Option<Self> {
        if p.is_even() || *p < 3 {
            return None;
        }
        if q.is_even() || *q < 3 {
            return None;
        }
        // Check that p * q == n
        if p.clone() * q != *n {
            return None;
        }
        // Check that (e * d) % (p-1) == 1
        // Clone e instead of d, because it is likely to be smaller
        if (e.clone() * d) % (p.clone() - 1) != 1 {
            return None;
        }
        // Check that (e * d) % (q-1) == 1
        if (e.clone() * d) % (q.clone() - 1) != 1 {
            return None;
        }

        // TODO: check e, d consistency
        Some(RSAPrivateKey {
            hash: RSAPublicKey::hash_n_e(&n, &e),
            n: n.clone(),
            e: e.clone(),
            d: d.clone(),
            p: p.clone(),
            q: q.clone(),
        })
    }

    #[cfg(test)]
    pub fn clone_to_pub(&self) -> RSAPublicKey {
        RSAPublicKey {
            hash: self.hash.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    #[cfg(test)]
    pub fn clone_to_partial(&self) -> RSAPartialPrivateKey {
        RSAPartialPrivateKey {
            hash: self.hash.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
            d: self.d.clone(),
        }
    }
}

impl fmt::Display for RSAPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "RSAPrivateKey(n[{}]={:#x}, e={:#x}, d={:#x}, p={:#x}, q={:#x})",
            self.n.significant_bits(),
            self.n,
            self.e,
            self.d,
            self.p,
            self.q
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AsymmetricKey {
    RSAPub(RSAPublicKey),
    RSAPartPriv(RSAPartialPrivateKey),
    RSAPriv(RSAPrivateKey),
}

impl AsymmetricKey {
    pub fn hash(&self) -> &[u8] {
        // Only hash the digest of the key into the hasher
        match self {
            AsymmetricKey::RSAPub(ref key) => &key.hash,
            AsymmetricKey::RSAPartPriv(ref key) => &key.hash,
            AsymmetricKey::RSAPriv(ref key) => &key.hash,
        }
    }

    #[cfg(test)]
    pub fn as_rsa_priv(&self) -> Option<&RSAPrivateKey> {
        match self {
            AsymmetricKey::RSAPub(_) => None,
            AsymmetricKey::RSAPartPriv(_) => None,
            AsymmetricKey::RSAPriv(ref key) => Some(key),
        }
    }

    /// Does self contain more info than the other key?
    ///
    /// For example a private key is better that its matching public key
    pub fn is_better_than(&self, other: &AsymmetricKey) -> bool {
        match (self, other) {
            (AsymmetricKey::RSAPub(ref s_key), AsymmetricKey::RSAPub(ref o_key)) => {
                assert_eq!(s_key, o_key);
                false
            }
            (AsymmetricKey::RSAPriv(ref s_key), AsymmetricKey::RSAPub(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                true
            }
            (AsymmetricKey::RSAPartPriv(ref s_key), AsymmetricKey::RSAPub(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                true
            }
            (AsymmetricKey::RSAPub(ref s_key), AsymmetricKey::RSAPartPriv(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                false
            }
            (AsymmetricKey::RSAPartPriv(ref s_key), AsymmetricKey::RSAPartPriv(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                assert_eq!(s_key.d, o_key.d);
                false
            }
            (AsymmetricKey::RSAPriv(ref s_key), AsymmetricKey::RSAPartPriv(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                assert_eq!(s_key.d, o_key.d);
                true
            }
            (AsymmetricKey::RSAPub(ref s_key), AsymmetricKey::RSAPriv(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                false
            }
            (AsymmetricKey::RSAPartPriv(ref s_key), AsymmetricKey::RSAPriv(ref o_key)) => {
                assert_eq!(s_key.n, o_key.n);
                assert_eq!(s_key.e, o_key.e);
                assert_eq!(s_key.d, o_key.d);
                false
            }
            (AsymmetricKey::RSAPriv(ref s_key), AsymmetricKey::RSAPriv(ref o_key)) => {
                assert_eq!(s_key, o_key);
                false
            } // _ => panic!("Incompatible key types for better comparison: {} vs {}", self, other),
        }
    }
}

impl fmt::Display for AsymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsymmetricKey::RSAPub(ref key) => key.fmt(f),
            AsymmetricKey::RSAPartPriv(ref key) => key.fmt(f),
            AsymmetricKey::RSAPriv(ref key) => key.fmt(f),
        }
    }
}
