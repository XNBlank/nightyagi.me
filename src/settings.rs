use config::{Config, ConfigError, Environment, File};
use serde::{Serialize, Deserialize};
use std::sync::RwLock;

#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    pub recaptcha_private: String,
    pub recaptcha_site_key: String,
    pub contact_email: String,
    pub contact_from: String,
    pub contact_from_nicename: String
}

lazy_static! {
    static ref SETTINGS: RwLock<Settings> = RwLock::new(match Settings::init() {
        Ok(c) => c,
        Err(e) => panic!("{}", e),
    });
}

impl Settings {
    fn init() -> Result<Self, ConfigError> {
        let mut s = Config::new();

        s.merge(File::with_name("config.toml"))?;

        s.merge(Environment::with_prefix("NYSETTINGS").separator("__"))?;

        s.try_into()
    }

    pub fn get() -> Self {
        SETTINGS.read().unwrap().to_owned()
    }
}