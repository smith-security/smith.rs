extern crate smith_ssh;

use clap::{App, AppSettings, Arg};
use smith_ssh::data::{AuthorityPublicKeys, Environment};
use smith_ssh::api::Api;
use smith_ssh::configuration::Configuration;
use std::fs::File;
use std::io::Write;

fn main() {
    let matches = App::new("smith-host")
	.version(&smith_ssh::version::smith_version()[..])
	.about("Fetch certificate-authority public keys for smith managed hosts.")
	.setting(AppSettings::ArgRequiredElseHelp)
	.arg(Arg::with_name("ENVIRONMENT")
	     .short("e")
	     .long("environment")
	     .help("The environment to fetch public keys for.")
	     .env("SMITH_ENVIRONMENT")
             .value_name("ENVIRONMENT")
	     .required(true))
	.arg(Arg::with_name("FILE")
             .help("Output path for certificate authority public keys file.")
	     .required(false))
	.get_matches();

    let environment = matches.value_of("ENVIRONMENT").unwrap_or_else(|| {
        eprintln!("Problem parsing arguments, no ENVIRONMENT specified.");
        std::process::exit(1);
    });

    let file = matches.value_of("FILE");

    if cfg!(feature = "cli-test") {
        println!("SMITH_CLI_ENVIRONMENT='{}'", environment);
        if let Some(file) = file {
            println!("SMITH_CLI_CA_OUTPUT='{}'", file);
        }
        std::process::exit(0)
    }

    let configuration = Configuration::from_env();
    let mut api = Api::new(configuration);
    match api.keys(&Environment { name: environment.to_string() } ) {
        Ok(AuthorityPublicKeys { keys }) => {
            match file {
                None => {
                    for key in keys.iter() {
                        println!("{}", key);
                    }
                },
                Some(file) => {
                    let mut file = File::create(file).unwrap_or_else(|e| {
                        eprintln!("Could not create file to write certificate-authority keys: {}", e);
                        std::process::exit(1);
                    });
                    for key in keys.iter() {
                        file.write_all(format!("{}\n", &key).as_bytes()).unwrap_or_else(|e| {
                            eprintln!("Could not write key to specified file: {}", e);
                            std::process::exit(1);
                        });
                    }
                },
            }
        },
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1)
        },
    }
}
