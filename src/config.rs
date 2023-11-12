use serde::Deserialize;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub transport: Transport,
    pub database: crate::database::Config,
}

#[derive(Debug, Deserialize)]
pub enum Transport {
    Tcp(crate::tcp::Config),
    Http(crate::http::Config),
}

pub fn load_config_from_file(file_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let config: Config = ron::de::from_str(&contents)?;
    Ok(config)
}
