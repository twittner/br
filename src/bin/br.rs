use std::path::PathBuf;

use anyhow::Result;
use br::{backup, restore};
use clap::{Parser, Subcommand};

/// Backup and restore a file archive.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[non_exhaustive]
struct Args {
    #[clap(subcommand)]
    command: Command
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Encrypt a file archive and split it into parts.
    Backup {
        /// The file to backup.
        #[arg(short, long)]
        archive: PathBuf,

        /// The directory to store the backup parts in.
        #[arg(short, long)]
        target: PathBuf,

        /// The password to use for encrypting the file.
        #[arg(short, long)]
        password: Option<String>,

        /// The number of parts to split the backup into.
        #[arg(short, long, default_value = "3")]
        num: u8
    },
    /// Merge backup parts and decrypt the file archive.
    Restore {
        /// The file to restore the backup to.
        #[arg(short, long)]
        target: PathBuf,

        /// The password of the encrypted backup.
        #[arg(short, long)]
        password: Option<String>,

        /// The backup parts.
        #[arg(required = true)]
        parts: Vec<PathBuf>
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Backup { archive, target, password, num } => backup(&archive, num, &target, password)?,
        Command::Restore { parts, target, password } => restore(&parts, &target, password)?
    }
    Ok(())
}
