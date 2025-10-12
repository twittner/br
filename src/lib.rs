use std::{fs::{self, File}, io::{self, BufReader, BufWriter, Read, Write}, path::Path};

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use aws_lc_rs::{aead::{self, Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN}, cipher::AES_256_KEY_LEN, error::Unspecified};
use bit_vec::BitVec;
use rand::{rngs::OsRng, TryRngCore};
use tinyvec::TinyVec;

const SALT_LEN: usize = 24;
const KEY_LEN: usize = AES_256_KEY_LEN;
const ALGORITHM: &aead::Algorithm = &AES_256_GCM;

/// Create a bit vector from input bytes and split it into `n` bit vectors.
fn split(n: u8, input: &[u8]) -> TinyVec<[BitVec; 3]> {
    let mut parts: TinyVec<[BitVec; 3]> = TinyVec::new();
    for _ in 0 .. n {
        parts.push(BitVec::new());
    }
    for (i, b) in BitVec::from_bytes(input).iter().enumerate() {
        parts[i % n as usize].push(b)
    }
    parts
}

/// Join bit vectors together and restore the byte vector.
///
/// Inverse of `split`.
fn join(inputs: &[BitVec]) -> Result<Vec<u8>, Error> {
    let len = inputs.iter().map(|v| v.len()).sum();
    let mut iter = inputs.iter().map(BitVec::iter).collect::<Vec<_>>();
    let mut output = BitVec::new();
    for i in (0 .. inputs.len()).cycle().take(len) {
        let Some(b) = iter[i].next() else {
            return Err(Error::InputOrder)
        };
        output.push(b)
    }
    Ok(output.to_bytes())
}

/// Generate fresh salt for key derivation.
fn fresh_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.try_fill_bytes(&mut salt).unwrap();
    salt
}

/// Derive key from password and salt.
fn kdf(salt: &[u8], password: &str) -> Result<[u8; KEY_LEN], Error> {
    let params = ParamsBuilder::new()
        .p_cost(32)
        .t_cost(100)
        .m_cost(128 * 1024)
        .build()?;

    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::default(), params)
        .hash_password_into(password.as_bytes(), salt, &mut key)?;

    Ok(key)
}

/// Convert the bit vector to a byte vector.
///
/// Also return the number of excess bits which may be present
/// to fill the last byte.
fn to_bytes(v: &BitVec) -> (Vec<u8>, usize) {
    let n = v.len();
    let b = v.to_bytes();
    let d = b.len() * 8 - n;
    assert!(d < 8);
    (b, d)
}

/// Convert the byte slice to a bit vector and drop `n` bits from the end.
fn from_bytes(b: &[u8], n: usize) -> Result<BitVec, Error> {
    let mut v = BitVec::from_bytes(b);
    if v.len() < n {
        return Err(Error::BitLenTooShort)
    }
    v.truncate(v.len() - n);
    Ok(v)
}

/// The file header of a backup part.
///
/// 3 bits are used as version information and the remaining
/// 5 bits contain the number of fill bits at the end.
fn header(n: usize) -> u8 {
    assert!(n < 8);
    (0b00100000 | n) as u8
}

/// Given a header, return the number of trailing bits to drop.
fn header_to_diff(h: u8) -> usize {
    (h & 0b00011111) as usize
}

/// Read password from stdin.
fn read_password() -> Result<String, Error> {
    print!("password: ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Create an encrpyted backup of `archive` in `target` directory.
///
/// The encrypted archive will be split into `num` parts.
pub fn backup(archive: &Path, num: u8, target: &Path, password: Option<String>) -> Result<(), Error> {
    if !archive.is_file() {
        return Err(Error::Fs(format!("{archive:?} not found")))
    }

    if !target.is_dir() {
        return Err(Error::Fs(format!("{target:?} is not a directory")))
    }

    let Some(archive_name) = archive.file_name() else {
        return Err(Error::Fs(format!("archive {archive:?} has no file name")))
    };

    let password =
        if let Some(p) = password {
            p
        } else {
            read_password()?
        };

    let slt = fresh_salt();
    let key = RandomizedNonceKey::new(ALGORITHM, &kdf(&slt, &password)?)?;

    let mut bytes = fs::read(archive)?;
    let nonce = key.seal_in_place_append_tag(Aad::empty(), &mut bytes)?;
    bytes.extend_from_slice(nonce.as_ref());
    bytes.extend_from_slice(&slt);

    for (i, part) in split(num, &bytes).into_iter().enumerate() {
        let dest = target.join(archive_name).with_extension(format!("{i}"));
        println!("writing {dest:?}");
        let (b, n) = to_bytes(&part);
        let mut w = BufWriter::new(File::create(dest)?);
        w.write_all(&[header(n)])?;
        w.write_all(&b)?
    }

    Ok(())
}

/// Restore a backup by joining the parts and decrypting into `target` file.
pub fn restore<P>(parts: &[P], target: &Path, password: Option<String>) -> Result<(), Error>
where
    P: AsRef<Path>
{
    if target.is_file() {
        return Err(Error::Fs(format!("{target:?} exists")))
    }

    let password =
        if let Some(p) = password {
            p
        } else {
            read_password()?
        };

    let mut v = Vec::new();
    for p in parts {
        let p = p.as_ref();
        println!("reading {p:?}");
        let mut r = BufReader::new(File::open(p)?);
        let mut h = [0];
        r.read_exact(&mut h)?;
        let n = header_to_diff(h[0]);
        let mut b = Vec::new();
        r.read_to_end(&mut b)?;
        v.push(from_bytes(&b, n)?)
    }

    let mut bytes = join(&v)?;
    if bytes.len() < NONCE_LEN + SALT_LEN {
        return Err(Error::InputTooShort)
    }

    let salt = bytes.split_off(bytes.len() - SALT_LEN);
    let nonce: [u8; NONCE_LEN] = bytes.split_off(bytes.len() - NONCE_LEN).try_into().unwrap();
    let key = RandomizedNonceKey::new(ALGORITHM, &kdf(&salt, &password)?)?;
    let Ok(bytes) = key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut bytes) else {
        return Err(Error::Decrypt)
    };

    fs::write(target, bytes)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),

    #[error("file system: {0}")]
    Fs(String),

    #[error("bit length less than bit difference")]
    BitLenTooShort,

    #[error("input too short")]
    InputTooShort,

    #[error("input arrangement error")]
    InputOrder,

    #[error("kdf: {0}")]
    Kdf(#[from] argon2::Error),

    #[error("unspecified crypto error")]
    Crypto(#[from] Unspecified),

    #[error("failed to decrypt")]
    Decrypt
}
