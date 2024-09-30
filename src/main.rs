use std::{ffi::OsStr, path::{Path, PathBuf}};

use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use bit_vec::BitVec;
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use tinyvec::TinyVec;
use walkdir::WalkDir;

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

fn join(inputs: &[BitVec]) -> Result<Vec<u8>> {
    let len = inputs.iter().map(|v| v.len()).sum();
    let mut iter = inputs.iter().map(BitVec::iter).collect::<Vec<_>>();
    let mut output = BitVec::new();
    for i in (0 .. inputs.len()).cycle().take(len) {
        let Some(b) = iter[i].next() else {
            bail!("input arrangement error")
        };
        output.push(b)
    }
    Ok(output.to_bytes())
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[non_exhaustive]
struct Args {
    #[clap(subcommand)]
    command: Command
}

#[derive(Debug, Subcommand)]
enum Command {
    Backup {
        #[arg(short, long)]
        archive: PathBuf,

        #[arg(short, long)]
        target: PathBuf,

        #[arg(short, long)]
        password: String,

        #[arg(short, long, default_value = "3")]
        num: u8
    },
    Restore {
        #[arg(short, long)]
        dir: PathBuf,

        #[arg(short, long)]
        target: PathBuf,

        #[arg(short, long)]
        password: String
    }
}

fn fresh_salt() -> [u8; 24] {
    let mut salt = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn kdf(salt: &[u8], password: &str) -> Result<[u8; 32]> {
    let params = ParamsBuilder::new()
        .p_cost(32)
        .t_cost(100)
        .m_cost(128 * 1024)
        .build()?;

    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::default(), params)
        .hash_password_into(password.as_bytes(), salt, &mut key)?;

    Ok(key)
}

fn parts(root: &Path, name: &OsStr) -> Result<Vec<PathBuf>> {
    let mut parts = WalkDir::new(root)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_entry(move |e| {
            let Some(a) = e.path().file_stem() else {
                return false
            };
            a == name
        })
        .map(|e| e.map(|e| e.into_path()))
        .collect::<Result<Vec<_>, _>>()?;
    parts.sort();
    Ok(parts)
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Backup { archive, target, password, num } => {
            if !target.is_dir() {
                bail!("{target:?} is not a directory")
            }
            let salt = fresh_salt();
            let key = kdf(&salt, &password)?;
            let key = RandomizedNonceKey::new(&AES_256_GCM, &key)?;
            let mut bytes = std::fs::read(&archive)?;
            let nonce = key.seal_in_place_append_tag(Aad::empty(), &mut bytes)?;
            bytes.extend_from_slice(&salt);
            bytes.extend_from_slice(nonce.as_ref());
            for (i, part) in split(num, &bytes).into_iter().enumerate() {
                let dest = target.join(archive.with_extension(format!("{i}")));
                std::fs::write(dest, &part.to_bytes())?
            }
        },
        Command::Restore { dir, target, password } => {
            let Some(name) = target.file_stem() else {
                bail!("{target:?} has no file name")
            };
            let mut v = Vec::new();
            for p in parts(&dir, name)? {
                v.push(BitVec::from_bytes(&std::fs::read(p)?))
            }
            let mut bytes = join(&v)?;
            if bytes.len() < NONCE_LEN + 24 {
                bail!("not enough bytes")
            }
            let nonce: [u8; NONCE_LEN] = bytes.split_off(bytes.len() - NONCE_LEN).try_into().unwrap();
            let salt = bytes.split_off(bytes.len() - 24);
            let key = kdf(&salt, &password)?;
            let key = RandomizedNonceKey::new(&AES_256_GCM, &key)?;
            let bytes = key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut bytes)?;
            std::fs::write(target, bytes)?
        }
    }
    Ok(())
}
