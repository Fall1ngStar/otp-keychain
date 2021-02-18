use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "otp", about = "Generate TOTP tokens")]
pub struct Cli {
    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(about = "List providers available on the system")]
    List,
    #[structopt(name = "gen", about = "Generate a new TOTP token")]
    Generate {
        #[structopt(help = "Provider to generate token for")]
        provider: String,
    },
    #[structopt(about = "Add a new provider")]
    Add {
        #[structopt(short, long, help = "Base32 secret provided by the service using TOTP")]
        secret: String,
        #[structopt(short, long, help = "Label for the service provider")]
        provider: String,
    },
    #[structopt(about = "Export all providers to standard output")]
    Export,
    #[structopt(about = "Remove a provider from the system")]
    Remove {
        #[structopt(help = "Provider to remove from system")]
        provider: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub secrets: HashMap<String, Secret>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Secret {
    pub token_size: usize,
}

impl std::default::Default for Config {
    fn default() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }
}

impl std::default::Default for Secret {
    fn default() -> Self {
        Self { token_size: 6 }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialsError {
    source: String,
}

impl CredentialsError {
    pub fn new(source: String) -> Self {
        Self { source }
    }
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.source)
    }
}

impl std::error::Error for CredentialsError {}
