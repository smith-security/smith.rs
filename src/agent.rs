use std::env;
use std::os::unix::net::UnixStream;
use std::io::prelude::*;

pub enum ProtocolError {
    InvalidResponseHeader(Vec<u8>),
}

pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    pub fn send(&self, message: Message, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        panic!("todo")
    }
}

pub enum Message {
    AddIdentityMessage,
}

impl Message {
    pub fn to_u8(&self) -> u8 {
        match self {
            Message::AddIdentityMessage => 17,
        }
    }

    pub fn packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut result = vec![self.to_u8()];
        result.append(&mut payload.to_vec());
        result
    }
}


pub enum Reply {
    FailureReply,
    SuccessReply,
    ExtensionFailureReply,
    IdentitiesAnswerReply,
    SignResponseReply,
}

impl Reply {
    pub fn to_u8(&self) -> u8 {
        match self {
            Reply::FailureReply => 5,
            Reply::SuccessReply => 6,
            Reply::ExtensionFailureReply => 28,
            Reply::IdentitiesAnswerReply => 12,
            Reply::SignResponseReply => 14,
        }
    }
}

pub fn connect() -> Option<Agent> {
    let path = env::var("SSH_AUTH_SOCK").ok()?;
    UnixStream::connect(path).ok().map(|stream| Agent { stream })
}
