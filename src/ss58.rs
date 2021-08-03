use crate::hashing::blake2_256;
use crate::hashing::sha2_256;
use base58::*;
use ripemd160::{Digest, Ripemd160};

// Max format for simple account
const SIMPLE_ACCOUNT_FORMAT_MAX_VAL: u16 = 63;
// Format maximum value
const FORMAT_MAX_VAL: u16 = 16383;
// Reserved formats
const RESERVED_FORMATS: &'static [u32] = &[46, 47];

// Data length in bytes
const DATA_BYTE_LEN: usize = 32;

// Checksum length in bytes
const CHECKSUM_LEN: usize = 2;
// Checksum prefix
const CHECKSUM_PREFIX: &[u8; 7] = b"SS58PRE";

type PKH = [u8; 32];

fn checksum(data: &[u8]) -> [u8; 32] {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(CHECKSUM_PREFIX);
    buffer.extend_from_slice(data);
    blake2_256(data)
}

// Converting Pubkey to Pubkey Hash
fn to_pkh(compressed_pubkey: &[u8]) -> Option<String> {
    let sha256 = sha2_256(compressed_pubkey);
    // create a RIPEMD-160 hasher instance
    let mut hasher = Ripemd160::new();

    // process input message
    hasher.update(&sha256[..]);
    let hash160 = hasher.finalize();

    // Generate an address
    Some(hex::encode(hash160.as_slice()))
}

/// SS58 encoder. It provides methods for encoding to SS58 format.
fn encode(compressed_pubkey: &[u8], ss58_format: u16) -> Option<String> {
    // We mask out the upper two bits of the ident - SS58 Prefix currently only supports 14-bits
    let ident: u16 = u16::from(ss58_format) & 0b0011_1111_1111_1111;

    let mut v = match ident {
        0..=63 => vec![ident as u8],
        64..=16_383 => {
            // upper six bits of the lower byte(!)
            let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
            // lower two bits of the lower byte in the high pos,
            // lower bits of the upper byte in the low pos
            let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
            vec![first | 0b01000000, second]
        }
        _ => {
            if cfg!(test) {
                println!("masked out the upper two bits; qed");
            }
            return None;
        }
    };
    v.extend(compressed_pubkey);
    let r = ss58hash(&v);
    v.extend(&r.as_bytes()[0..2]);
    Some(v.as_slice().to_base58())
}

const PREFIX: &[u8] = b"SS58PRE";

// #[cfg(feature = "std")]
fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
    let mut context = blake2_rfc::blake2b::Blake2b::new(64);
    context.update(PREFIX);
    context.update(data);
    context.finalize()
}

// Decode bytes from a SS58 string.
fn decode(data_str: &str) -> Option<(u16, Vec<u8>)> {
    // Decode string
    let dec_bytes = data_str.from_base58().ok()?;

    let (prefix_len, ident) = match dec_bytes[0] {
        0..=63 => (1, dec_bytes[0] as u16),
        64..=127 => {
            // weird bit manipulation owing to the combination of LE encoding and missing two bits
            // from the left.
            // d[0] d[1] are: 01aaaaaa bbcccccc
            // they make the LE-encoded 16-bit value: aaaaaabb 00cccccc
            // so the lower byte is formed of aaaaaabb and the higher byte is 00cccccc
            let lower = (dec_bytes[0] << 2) | (dec_bytes[1] >> 6);
            let upper = dec_bytes[1] & 0b00111111;
            (2, (lower as u16) | ((upper as u16) << 8))
        }
        _ => return None,
    };
    if dec_bytes.len() != prefix_len + DATA_BYTE_LEN + CHECKSUM_LEN {
        if cfg!(test) {
            println!("Bad length {}", dec_bytes.len());
        }
        return None;
    }

    // Check format
    for i in RESERVED_FORMATS {
        if *i == ident.into() {
            if cfg!(test) {
                println!("Invalid SS58 format {}", i);
            }
            return None;
        }
    }

    let hash = ss58hash(&dec_bytes[0..DATA_BYTE_LEN + prefix_len]);
    let checksum = &hash.as_bytes()[0..CHECKSUM_LEN];
    if dec_bytes[DATA_BYTE_LEN + prefix_len..DATA_BYTE_LEN + prefix_len + CHECKSUM_LEN] != *checksum
    {
        // Invalid checksum.
        if cfg!(test) {
            println!("Invalid checksum");
        }
        return None;
    }
    let res: Vec<u8> = Vec::from(&dec_bytes[prefix_len..DATA_BYTE_LEN + prefix_len]);
    Some((ident, res))
}

#[cfg(test)]
mod tests {
    use std::ops::{BitAnd, BitOr};

    #[test]
    fn check_ss58() {
        // Default variables that I took from this page:
        // https://substrate.dev/docs/en/knowledgebase/advanced/ss58-address-format
        let compressed_pubkey = [
            0x46, 0xeb, 0xdd, 0xef, 0x8c, 0xd9, 0xbb, 0x16, 0x7d, 0xc3, 0x08, 0x78, 0xd7, 0x11,
            0x3b, 0x7e, 0x16, 0x8e, 0x6f, 0x06, 0x46, 0xbe, 0xff, 0xd7, 0x7d, 0x69, 0xd3, 0x9b,
            0xad, 0x76, 0xb4, 0x7a,
        ];
        let ss58_address = "12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU";

        // Check decode function from ss58 address to Compressed Pubkey
        let (format, data) = super::decode(ss58_address).unwrap();
        assert_eq!(hex::encode(data), hex::encode(compressed_pubkey));

        // Check decoding function from the Compressed Pubkey to ss58 address
        let addr = super::encode(&compressed_pubkey, format).unwrap();
        println!("{:?}", addr);
        assert_eq!(addr, ss58_address);
    }

    #[test]
    fn check_ss58_to_PKH() {
        let compressed_pubkey = [
            0x02, 0xb4, 0x63, 0x2d, 0x08, 0x48, 0x5f, 0xf1, 0xdf, 0x2d, 0xb5, 0x5b, 0x9d, 0xaf,
            0xd2, 0x33, 0x47, 0xd1, 0xc4, 0x7a, 0x45, 0x70, 0x72, 0xa1, 0xe8, 0x7b, 0xe2, 0x68,
            0x96, 0x54, 0x9a, 0x87, 0x37,
        ];
        let pkh = "93ce48570b55c42c2af816aeaba06cfee1224fae";
        let pkh_data = super::to_pkh(&compressed_pubkey).unwrap();
        assert_eq!(pkh, pkh_data);
    }
}
