use std::time::SystemTime;

use clipboard::ClipboardProvider;
use keyring::Keyring;
use structopt::StructOpt;
use totp_rs::{Algorithm, TOTP};

use cli::{Cli, Command, Config, CredentialsError};

use crate::cli::Secret;

mod cli;

const SERVICE_NAME: &str = "otp-keychain";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type EmptyResult = Result<()>;

fn main() -> EmptyResult {
    let args: Cli = Cli::from_args();
    let mut otp = OTP::new()?;
    match args.cmd {
        Command::List => otp.list_providers(),
        Command::Generate { provider } => otp.generate_totp(provider),
        Command::Add { secret, provider } => otp.add_secret(secret, provider),
        Command::Remove { provider } => otp.remove_provider(provider),
        Command::Export => otp.export(),
    }
}

struct OTP {
    config: Config,
}

impl OTP {
    fn new() -> Result<Self> {
        let config = confy::load(SERVICE_NAME)?;
        Ok(Self { config })
    }

    fn list_providers(&self) -> EmptyResult {
        let config = confy::load::<Config>(SERVICE_NAME)?;
        for key in config.secrets.keys() {
            println!("{}", key)
        }
        Ok(())
    }

    fn add_secret(&mut self, secret: String, provider: String) -> EmptyResult {
        println!("Adding provider '{}' in keychain", provider);
        let keyring = Keyring::new(SERVICE_NAME, &provider);
        match keyring.get_password() {
            Ok(_) => {
                Err(CredentialsError::new("provider already exists in keychain".to_string()).into())
            }
            Err(_) => {
                keyring.set_password(&secret)?;
                self.config.secrets.insert(provider, Secret::default());
                Ok(confy::store(SERVICE_NAME, &self.config)?)
            }
        }
    }

    fn generate_totp(&self, provider: String) -> EmptyResult {
        let secret_config = self
            .config
            .secrets
            .get(&provider)
            .ok_or(CredentialsError::new(
                "provider not found in config".to_string(),
            ))?;
        let keyring = Keyring::new(SERVICE_NAME, &provider);
        match keyring.get_password() {
            Ok(base32_secret) => {
                let bytes_secret =
                    base32::decode(base32::Alphabet::RFC4648 { padding: false }, &base32_secret);
                let totp = TOTP::new(
                    Algorithm::SHA1,
                    secret_config.token_size,
                    0,
                    30,
                    bytes_secret.unwrap(),
                );
                let time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs();
                let remaining = 30 - (time - (time / 30) * 30);
                let token = totp.generate(time);
                println!("{} ({:2} sec)", token, remaining);

                let mut clip = clipboard::ClipboardContext::new()?;
                Ok(clip.set_contents(token)?)
            }
            Err(err) => Err(err.into()),
        }
    }

    fn remove_provider(&mut self, provider: String) -> EmptyResult {
        match self.config.secrets.get(&provider) {
            None => {
                return Err(
                    CredentialsError::new("provider not found in config".to_string()).into(),
                )
            }
            Some(_) => {}
        };
        let keyring = Keyring::new(SERVICE_NAME, &provider);
        match keyring.get_password() {
            Err(err) => Err(err.into()),
            Ok(_) => {
                keyring.delete_password()?;
                self.config.secrets.remove(&provider).unwrap();
                Ok(confy::store(SERVICE_NAME, &self.config)?)
            }
        }
    }

    fn export(&self) -> EmptyResult {
        for provider in self.config.secrets.keys() {
            let keyring = Keyring::new(SERVICE_NAME, provider);
            let secret = keyring.get_password()?;
            println!("{}: {}", provider, secret);
        }
        Ok(())
    }
}
