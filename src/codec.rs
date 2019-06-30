use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::io::{Error, Read, Write};
use num_bigint::BigUint;

pub fn encode_bytes<A: Write + WriteBytesExt>(writer: &mut A, v: &[u8]) -> Result<(), Error> {
    encode_uint32(writer, v.len() as u32)?;
    writer.write_all(v)
}

pub fn decode_bytes<A: Read + ReadBytesExt>(reader: &mut A) -> Result<Vec<u8>, Error> {
    let length = decode_uint32(reader)? as usize;
    let mut buffer = vec![0; length];
    reader.read_exact(&mut buffer);
    Ok(buffer)
}

pub fn encode_uint32<A: Write + WriteBytesExt>(writer: &mut A, v: u32) -> Result<(), Error> {
    writer.write_u32::<BigEndian>(v)
}

pub fn decode_uint32<A: Read + ReadBytesExt>(reader: &mut A) -> Result<u32, Error> {
    reader.read_u32::<BigEndian>()
}

pub fn encode_uint64<A: Write + WriteBytesExt>(writer: &mut A, v: u64) -> Result<(), Error> {
    writer.write_u64::<BigEndian>(v)
}

pub fn decode_uint64<A: Read + ReadBytesExt>(reader: &mut A) -> Result<u64, Error> {
    reader.read_u64::<BigEndian>()
}

pub fn encode_biguint<A: Write + WriteBytesExt>(writer: &mut A, v: BigUint) -> Result<(), Error> {
    encode_bytes(writer, &v.to_bytes_be())
}

pub fn decode_biguint<A: Read + ReadBytesExt>(reader: &mut A) -> Result<BigUint, Error> {
    let bytes = decode_bytes(reader)?;
    Ok(BigUint::from_bytes_be(&bytes))
}
