extern crate clap;
extern crate openssl;
extern crate smith_ssh;
extern crate whoami;

use clap::{App, AppSettings, Arg};

use exec::Command;

use smith_ssh::agent::Agent;
use smith_ssh::api::Api;
use smith_ssh::keys;
use smith_ssh::configuration::Configuration;
use smith_ssh::data::{Environment, Principal, PublicKey};

use openssl::rsa::Rsa;


fn main() {
    let matches = App::new("smith")
	.version(&smith_ssh::version::smith_version()[..])
	.about("Request short-lived certificate from smith.")
	.setting(AppSettings::ArgRequiredElseHelp)
	.arg(Arg::with_name("DEBUG")
	     .short("d")
	     .long("debug")
	     .help("Obtain verbose error messages.")
	     .required(false))
	.arg(Arg::with_name("ENVIRONMENT")
	     .short("e")
	     .long("environment")
	     .help("The environment to fetch public keys for.")
	     .env("SMITH_ENVIRONMENT")
             .value_name("ENVIRONMENT")
	     .required(true))
	.arg(Arg::with_name("PRINCIPAL")
	     .short("p")
	     .long("principal")
	     .help("The principal to issue the key for.")
	     .env("SMITH_PRINCIPAL")
             .value_name("PRINCIPAL")
	     .required(false))
	.arg(Arg::from_usage("<CMD>... 'The command to run with configured ssh-agent.'")
	     .required(false))
	.get_matches();

    let environment = matches.value_of("ENVIRONMENT").unwrap_or_else(|| {
        eprintln!("Problem parsing arguments, no ENVIRONMENT specified.");
        std::process::exit(1);
    });
    let environment = Environment { name: environment.to_string() };
    let principal = matches.value_of("PRINCIPAL").map(|p| p.to_string()).unwrap_or(whoami::username());
    let principal = Principal { name: principal.to_string() };

    let command = matches.values_of("CMD");
    let debug = matches.occurrences_of("DEBUG") > 0;

    if cfg!(feature = "cli-test") {
        println!("SMITH_CLI_ENVIRONMENT='{}'", environment.name);
        println!("SMITH_CLI_PRINCIPAL='{}'", principal.name);
        if let Some(command) = command {
            let command = command.into_iter().collect::<Vec<&str>>().join(" ");
            println!("SMITH_CLI_COMMAND='{}'", command);
        }
        std::process::exit(0)
    }
    let mut agent = Agent::connect().unwrap_or_else(|| {
        eprintln!("Could not connect to ssh-agent.");
        std::process::exit(1);
    });
    let configuration = Configuration::from_env();
    let mut api = Api::new(configuration);
    let keys = Rsa::generate(4096).unwrap_or_else(|e| {
        eprintln!("Could not generate an RSA key pair: {}", e);
        if debug {
            eprintln!("DEBUG: {:?}", e);
        }
        std::process::exit(1);
    });
    let encoded = keys::encode_ssh(&keys, "comment");
    let public = PublicKey { encoded };
    let certificate = api.issue(&environment, &public, &vec![principal], &None).unwrap_or_else(|e| {
        eprintln!("Could not issue a certificate: {}", e);
        if debug {
            eprintln!("DEBUG: {:?}", e);
        }
        std::process::exit(1);
    });
    agent.add_certificate(&keys, &certificate).unwrap_or_else(|e| {
        eprintln!("Could not add certificate to agent: {}", e);
        if debug {
            eprintln!("DEBUG: {:?}", e);
        }
        std::process::exit(1);
    });
    if let Some(command) = command {
        let command = command.into_iter().collect::<Vec<&str>>();
        let result = Command::new(&command[0]).args(&command[1..]).exec();
        eprintln!("Could not execute command: {}", result);
        std::process::exit(1)
    }
}
