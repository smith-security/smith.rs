extern crate smith;

use clap::{App, AppSettings, Arg};
use smith::data::{AuthorityPublicKeys, Environment};
use smith::api::Api;
use smith::configuration::Configuration;


fn main() {
    let matches = App::new("smith-host")
	.version(&smith::version::smith_version()[..])
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
    // FIX handle file case.
    match api.keys(Environment { name: environment.to_string() } ) {
        Ok(AuthorityPublicKeys { keys }) => {
            for key in keys.iter() {
                println!("{}", key);
            }
            std::process::exit(0)
        },
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1)
        },
    }
}
