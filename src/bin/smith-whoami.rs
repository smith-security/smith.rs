extern crate clap;
extern crate smith_ssh;
extern crate whoami;

use clap::App;

use smith_ssh::data::UserInfo;
use smith_ssh::api::Api;
use smith_ssh::configuration::Configuration;

fn main() {
    let _matches = App::new("smith-whoami")
	.version(&smith_ssh::version::smith_version()[..])
	.about("Request user id from server, useful for verifying authentication.")
	.get_matches();

    let configuration = Configuration::from_env();
    let mut api = Api::new(configuration);
    match api.whoami() {
        Ok(UserInfo { user_id }) => {
            println!("id = {}", user_id);
            std::process::exit(0)
        },
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1)
        },
    }
}
