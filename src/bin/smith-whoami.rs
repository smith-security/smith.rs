extern crate clap;
extern crate smith;
extern crate whoami;

use clap::App;

use smith::data::UserInfo;
use smith::api::Api;
use smith::configuration::Configuration;

fn main() {
    let _matches = App::new("smith-whoami")
	.version(&smith::version::smith_version()[..])
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
