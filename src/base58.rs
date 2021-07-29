use crate::hashing::sha2_256;
use std::ops::Div;

// Base58 radix
const RADIX: i32 = 58;
// Checksum length in bytes
const CHECKSUM_BYTE_LEN: usize = 4;

// Alphabets
pub enum Base58Alphabets {
    Bitcoin,
    //Ripple,
    // Perhaps, add another one for the Mintlayer
}

impl Base58Alphabets {
    pub fn to_alphabet(&self) -> &[u8] {
        match self {
            bitcoin => "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".as_bytes(),
            // ripple => "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz".as_bytes(),
        }
    }
}

fn checksum(data_bytes: &[u8]) -> Vec<u8> {
    // Compute Base58 checksum.
    //     Args:
    //     data_bytes (bytes): Data bytes
    // Returns:
    //     bytes: Computed checksum

    let buffer = sha2_256(&sha2_256(data_bytes));
    Vec::from(&buffer[/* buffer.len() */ 32 - CHECKSUM_BYTE_LEN..])
}

pub fn encode(data_bytes: &[u8], some_alphabet: Base58Alphabets) -> Option<String> {
    // Encode bytes into a Base58 string.
    //     Args:
    //         data_bytes (bytes)                  : Data bytes
    //         alph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
    //     Returns:
    //         str: Encoded string
    //     Raises:
    //         TypeError: If alphabet index is not a Base58Alphabets enumerative

    // Get alphabet
    let alphabet = some_alphabet.to_alphabet();

    // Convert bytes to integer
    let mut buffer: [u8; 2] = [0; 2];
    buffer[0] = data_bytes[0];
    buffer[1] = data_bytes[1];

    let val = u16::from_be_bytes(buffer);
    // ConvUtils.BytesToInteger(data_bytes)

    // Algorithm implementation
    let mut enc: Vec<char> = Vec::new();
    while val > 0 {
        let r#mod = val % RADIX as u16;
        enc.insert(0, *alphabet.get(r#mod as usize)? as char);
    }

    // Get number of leading zeros
    let mut n = data_bytes.len()
        - data_bytes
            .into_iter()
            .skip_while(|x| **x == b"\0"[0])
            .collect::<Vec<&u8>>()
            .len();

    // Add padding
    let mut buffer: String = alphabet[0].to_string().repeat(n);
    buffer.push_str(&enc.into_iter().collect::<String>());
    Some(buffer)
}

fn check_encode(data_bytes: &[u8], some_alphabet: Base58Alphabets) -> Option<String> {
    // Encode bytes into Base58 string with checksum.
    //     Args:
    //         data_bytes (bytes)                  : Data bytes
    //         alph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
    //     Returns:
    //         str: Encoded string with checksum
    //     Raises:
    //         TypeError: If alphabet index is not a Base58Alphabets enumerative

    // Append checksum and encode all together

    let mut buffer = Vec::from(data_bytes);
    buffer.extend_from_slice(checksum(data_bytes).as_slice());
    encode(&buffer, some_alphabet)
}

pub fn decode(data_str: &str, some_alphabet: Base58Alphabets) -> Option<Vec<u8>> {
    // Decode bytes from a Base58 string.
    //         Args:
    //             data_str (str)                      : Data string
    //             alph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
    //         Returns:
    //             bytes: Decoded bytes
    //         Raises:
    //             TypeError: If alphabet index is not a Base58Alphabets enumerative

    // Get alphabet
    let alphabet = some_alphabet.to_alphabet();

    // Convert string to integer
    let mut val: i32 = 0;
    let mut i = 0;
    let reverse = data_str.chars().rev().collect::<String>();
    for c in reverse.bytes() {
        match alphabet.binary_search(&c) {
            Ok(x) => val += x as i32 * RADIX.pow(i),
            Err(_) => return None,
        }
        i += 1;
    }
    let mut r#mod: u8;
    let mut dec: Vec<u8> = Vec::new();
    while val > 0 {
        val = val.div(2_i32.pow(8));
        r#mod = (val % 2_i32.pow(8)) as u8; // To do: check it
        dec.push(r#mod);
    }

    // Get padding length
    let data_len = data_str
        .clone()
        .trim_start_matches(alphabet[0] as char)
        .len();
    let pad_len = data_str.len() - data_len;

    // Add padding
    let base = b'\0'.to_string().repeat(pad_len);
    dec.reverse();
    let result = (base + &String::from_utf8_lossy(dec.as_slice()));
    let result = result.as_bytes().to_vec();
    Some(result)
}

fn check_decode(data_str: &str, some_alphabet: Base58Alphabets) -> Option<Vec<u8>> {
    // Decode bytes from a Base58 string with checksum.
    // Args:
    //     data_str (str)                      : Data string
    //     alph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
    // Returns:
    //     bytes: Decoded bytes (checksum removed)
    // Raises:
    //     ValueError: If the string is not a valid Base58 format
    //     TypeError: If alphabet index is not a Base58Alphabets enumerative
    //     Base58ChecksumError: If checksum is not valid

    // Decode string
    let dec_bytes = decode(data_str, some_alphabet)?;

    //  Get data and checksum bytes
    let data_bytes = &dec_bytes[..dec_bytes.len() - CHECKSUM_BYTE_LEN];
    let checksum_bytes = &dec_bytes[dec_bytes.len() - CHECKSUM_BYTE_LEN..];

    // Compute checksum
    let comp_checksum = checksum(&data_bytes);

    // Verify checksum
    if checksum_bytes != comp_checksum {
        if cfg!(test) {
            println!(
                "Invalid checksum (expected {:?}, got {:?})",
                comp_checksum, checksum_bytes
            );
        }
        return None;
    }
    Some(data_bytes.to_vec())
}
