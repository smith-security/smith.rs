extern crate clap;
extern crate smith;
extern crate whoami;

use clap::{App, AppSettings, Arg};

fn main() {
    let matches = App::new("smith")
	.version(&smith::version::smith_version()[..])
	.about("Request short-lived certificate from smith.")
	.setting(AppSettings::ArgRequiredElseHelp)
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

    let principal = matches.value_of("PRINCIPAL").map(|p| p.to_string()).unwrap_or(whoami::username());

    let cmd = matches.values_of("CMD");

    if cfg!(feature = "cli-test") {
        println!("SMITH_CLI_ENVIRONMENT='{}'", environment);
        println!("SMITH_CLI_PRINCIPAL='{}'", principal);
        if let Some(cmd) = cmd {
            let cmd = cmd.into_iter().collect::<Vec<&str>>().join(" ");
            println!("SMITH_CLI_COMMAND='{}'", cmd);
        }
        std::process::exit(0)
    }

    eprintln!("Not implemented yet.");
    std::process::exit(1)
}
