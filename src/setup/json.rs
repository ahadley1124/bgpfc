use std::fs::File;
use std::io::{BufReader, Write};

use crate::structs::{self, Configuration};
use std::collections::HashMap;

static CONFIG_FILE: &str = "config.json";
static DEFAULT_CONFIG: &str = r#"
{
    "my_asn": 65500,
    "hold_time": 300,
    "bgp_id": "24.144.176.54",
    "networks": [
        {
            "prefix": "44.32.199.0",
            "mask": 24,
            "next_hop": "127.0.0.1",
            "as_path": [65500],
            "internal": true,
            "local_pref": 100
        }
    ]
}
"#;

pub fn open_config_file(file_path: &str) -> Result<serde_json::Value, serde_json::Error> {
    let file = File::open(file_path).expect("Unable to open config file");
    let reader = BufReader::new(file);
    let config: serde_json::Value = serde_json::from_reader(reader)?;
    Ok(config)
}

pub fn parse_config(config: &serde_json::Value) -> Result<structs::Configuration, &'static str> {
    let my_asn = config["my_asn"].as_u64().ok_or("Invalid my_asn")? as u16;
    let hold_time = config["hold_time"].as_u64().ok_or("Invalid hold_time")? as u16;
    let bgp_id = config["bgp_id"].as_str().ok_or("Invalid bgp_id")?;
    let networks = config["networks"].as_array().ok_or("Invalid networks")?;

    let mut network_list = Vec::new();
    for network in networks {
        let prefix = network["prefix"].as_str().ok_or("Invalid prefix")?;
        let mask = network["mask"].as_u64().ok_or("Invalid mask")? as u8;
        let next_hop = network["next_hop"].as_str().ok_or("Invalid next_hop")?;
        let as_path = network["as_path"]
            .as_array()
            .ok_or("Invalid as_path")?
            .iter()
            .filter_map(|x| x.as_u64())
            .map(|x| x as u8)
            .fold(HashMap::new(), |mut acc, asn| {
            *acc.entry(asn).or_insert(0) += 1;
            acc
            });
        let internal = network["internal"].as_bool().unwrap_or(false);
        let local_pref = network["local_pref"].as_u64().unwrap_or(100) as u32;

        network_list.push(structs::Networks {
            prefix: prefix.parse().map_err(|_| "Invalid prefix format")?,
            mask,
            next_hop: next_hop.parse().map_err(|_| "Invalid next_hop format")?,
            as_path,
            internal,
            local_pref,
            rpki_valid: Some(true), // Default value, can be modified later
            rpki_partial_valid: None, // Default value, can be modified later
            rpki_invalid: None, // Default value, can be modified later
        });
    }

    Ok(structs::Configuration {
        my_asn,
        hold_time,
        bgp_id: bgp_id.parse().map_err(|_| "Invalid bgp_id format")?,
        networks: network_list,
    })
}

pub fn write_default_config(config_path: &str) {
    if std::path::Path::new(&config_path).exists() {
        println!("Config file already exists. Not overwriting.");
        return;
    }
    let mut file = File::create(&config_path).expect("Unable to create config file");
    file.write_all(DEFAULT_CONFIG.as_bytes())
        .expect("Unable to write default config");
}

pub fn main() -> Result<Configuration, &'static str> {
    let appdata_dir = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/my_bgp_app", appdata_dir);
    std::fs::create_dir_all(&config_dir).expect("Unable to create config directory");
    let config_path = format!("{}/{}", config_dir, CONFIG_FILE);

    // Check if the config file exists
    if !std::path::Path::new(&config_path).exists() {
        println!("Config file not found. Creating default config.");
        write_default_config(&config_path);
    }

    // Open and parse the config file
    match open_config_file(&config_path) {
        Ok(config) => {
            match parse_config(&config) {
                Ok(parsed_config) => {
                    println!("Parsed configuration: {:?}", parsed_config);
                    Ok(parsed_config)
                }
                Err(e) => {
                    eprintln!("Error parsing config: {}", e);
                    Err("Failed to parse configuration")
                }
            }
        }
        Err(e) => {
            eprintln!("Error opening config file: {}", e);
            Err("Failed to open configuration file")
        }
    }
}