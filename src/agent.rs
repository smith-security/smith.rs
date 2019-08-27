use crate::codec;
use crate::data::Certificate;
use byteorder::{ByteOrder, BigEndian};
use std::env;
use std::os::unix::net::UnixStream;
use std::io::prelude::*;
use std::io::Cursor;
use openssl::rsa::Rsa;
use openssl::pkey::Private;

#[derive(Debug)]
pub enum ProtocolError {
    IoError(std::io::Error),
    UnknownResponse(u8),
    InvalidResponse(Vec<u8>),
    UnexpectedReply(Reply),
    InvalidCertificate,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::IoError(err) =>
                write!(f, "IO Error / {:?}", err),
            ProtocolError::UnknownResponse(_response) =>
                write!(f, "Unknown response from SSH agent, ensure you are running an openssh based agent."),
            ProtocolError::InvalidResponse(_response) =>
                write!(f, "Invalid response from SSH agent, ensure you are running an openssh based agent."),
            ProtocolError::UnexpectedReply(_reply) =>
                write!(f, "Agent failed to add key and/or certificate to SSH agent, ensure you are running an openssh based agent, note that gnome-keyring does not support certificates."),
            ProtocolError::InvalidCertificate =>
                write!(f, "The server returned an invalid or incomplete certificate."),
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(err: std::io::Error) -> ProtocolError {
        ProtocolError::IoError(err)
    }
}

pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    pub fn connect() -> Option<Agent> {
        let path = env::var("SSH_AUTH_SOCK").ok()?;
        UnixStream::connect(path).ok().map(|stream| Agent { stream })
    }

    pub fn send(&mut self, message: Message, payload: &[u8]) -> Result<Reply, ProtocolError> {
        let packet = message.packet(payload);
        self.stream.write_all(&packet)?;
        let mut result_size = [0; 4];
        self.stream.read_exact(&mut result_size)?;
        let size = BigEndian::read_u32(&result_size);
        let mut result = vec![0; size as usize];
        self.stream.read_exact(&mut result)?;
        Reply::from_bytes(&result)
    }

    pub fn add_private_key(&mut self, key: &Rsa<Private>, comment: &Option<String>) -> Result<(), ProtocolError> {
        let buffer: Vec<u8> = vec![];
        let mut buffer = Cursor::new(buffer);
        codec::encode_string(&mut buffer, "ssh-rsa")?;
        codec::encode_bignum(&mut buffer, key.n())?;
        codec::encode_bignum(&mut buffer, key.e())?;
        codec::encode_bignum(&mut buffer, key.d())?;
        codec::encode_bignum(&mut buffer, key.iqmp().expect("iqmp"))?;
        codec::encode_bignum(&mut buffer, key.p().expect("p"))?;
        codec::encode_bignum(&mut buffer, key.q().expect("q"))?;
        // FUTURE: Better default comment.
        codec::encode_string(&mut buffer, comment.as_ref().unwrap_or(&"foo".to_string()))?;
        let reply = self.send(Message::AddIdentityMessage, &buffer.into_inner())?;
        if reply != Reply::SuccessReply {
            return Err(ProtocolError::UnexpectedReply(reply));
        }
        Ok(())
    }

    pub fn add_certificate(&mut self, key: &Rsa<Private>, certificate: &Certificate) -> Result<(), ProtocolError> {
        let certificate = certificate.deconstruct().ok_or(ProtocolError::InvalidCertificate)?;
        self.add_private_key(key, &certificate.comment)?;
        let mut buffer = Cursor::new(vec![0 as u8; 100]);
        codec::encode_string(&mut buffer, &certificate.key_type)?;
        codec::encode_bytes(&mut buffer, &certificate.blob)?;
        codec::encode_bignum(&mut buffer, key.d())?;
        codec::encode_bignum(&mut buffer, key.iqmp().ok_or(ProtocolError::InvalidCertificate)?)?;
        codec::encode_bignum(&mut buffer, key.p().ok_or(ProtocolError::InvalidCertificate)?)?;
        codec::encode_bignum(&mut buffer, key.q().ok_or(ProtocolError::InvalidCertificate)?)?;
        // FUTURE: Better default comment.
        codec::encode_string(&mut buffer, &certificate.comment.unwrap_or("smith".to_string()))?;
        let reply = self.send(Message::AddIdentityMessage, &buffer.into_inner())?;
        if reply != Reply::SuccessReply {
            return Err(ProtocolError::UnexpectedReply(reply));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
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
        let size = payload.len() + 1;
        let mut data = [0; 4];
        BigEndian::write_u32(&mut data, size as u32);
        let mut data = data.to_vec();
        data.append(&mut vec![self.to_u8()]);
        data.append(&mut payload.to_vec());
        data
    }
}

#[derive(Debug, PartialEq, Clone)]
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

    pub fn from_u8(byte: u8) -> Result<Reply, ProtocolError> {
        match byte {
            5 => Ok(Reply::FailureReply),
            6 => Ok(Reply::SuccessReply),
            28 => Ok(Reply::ExtensionFailureReply),
            12 => Ok(Reply::IdentitiesAnswerReply),
            14 => Ok(Reply::SignResponseReply),
            _ => Err(ProtocolError::UnknownResponse(byte)),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Reply, ProtocolError> {
        if bytes.len() != 1 {
            return Err(ProtocolError::InvalidResponse(bytes.to_vec()));
        }
        Reply::from_u8(bytes[0])
    }
}
