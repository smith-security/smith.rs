use crate::codec;

use openssl::rsa::Rsa;
use openssl::pkey::Private;

use std::io::Cursor;

pub fn encode_ssh(key: &Rsa<Private>, comment: &str) -> String {
    let mut buffer = Cursor::new(vec![0 as u8; 20]);
    codec::encode_string(&mut buffer, "ssh-rsa").expect("e.1");
    codec::encode_bignum(&mut buffer, &key.e()).expect("e.2");
    codec::encode_bignum(&mut buffer, &key.n()).expect("e.3");
    let encoded = base64::encode(&buffer.into_inner());
    format!("ssh-rsa {} {}", encoded, comment)
}
