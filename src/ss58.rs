use crate::hashing::blake2_256;
use std::convert::TryInto;
use std::ops::{BitAnd, BitOr};

// Max format for simple account
const SIMPLE_ACCOUNT_FORMAT_MAX_VAL: u16 = 63;
// Format maximum value
const FORMAT_MAX_VAL: u16 = 16383;
// Reserved formats
const RESERVED_FORMATS: &'static [u32] = &[46, 47];

// Data length in bytes
const DATA_BYTE_LEN: usize = 32;

// Checksum length in bytes
const CHECKSUM_BYTE_LEN: i32 = 2;
// Checksum prefix
const CHECKSUM_PREFIX: &[u8; 7] = b"SS58PRE";

fn check_sum(data: &[u8]) -> [u8; 32] {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(CHECKSUM_PREFIX);
    buffer.extend_from_slice(data);
    blake2_256(data)
}

/// SS58 encoder. It provides methods for encoding to SS58 format.
fn encode(data_bytes: &[u8], ss58_format: u16) -> Option<String> {
    // Encode bytes into a SS58 string.
    //     Args:
    //         data_bytes (bytes): Data bytes (32-byte length)
    //         ss58_format (int) : SS58 format
    //     Returns:
    //         str: SS58 encoded string
    //     Raises:
    //         ValueError: If parameters are not valid

    // Check parameters
    if data_bytes.len() != DATA_BYTE_LEN {
        if cfg!(test) {
            println!("Invalid data length {}", data_bytes.len());
        }
        return None;
    }
    if ss58_format > FORMAT_MAX_VAL.into() {
        if cfg!(test) {
            println!("Invalid SS58 format {}", ss58_format);
        }
        return None;
    }

    for i in RESERVED_FORMATS {
        if *i == ss58_format.into() {
            if cfg!(test) {
                println!("Invalid SS58 format {}", ss58_format);
            }
            return None;
        }
    }

    let ss58_format_bytes: [u8; 2] = if ss58_format <= SIMPLE_ACCOUNT_FORMAT_MAX_VAL {
        // Simple account
        ss58_format.to_be_bytes()
    } else {
        // Full address
        // 0b00HHHHHH_MMLLLLLL -> (0b01LLLLLL, 0bHHHHHHMM)
        [
            ss58_format
                .bitand(0x00FC)
                .rotate_right(2)
                .bitor(0x0040)
                .try_into()
                .unwrap(),
            ss58_format
                .rotate_right(8)
                .bitor(ss58_format.bitand(0x0003).rotate_left(6))
                .try_into()
                .unwrap(),
        ]
    };

    // Get payload
    let mut payload = Vec::from(ss58_format_bytes);
    payload.extend_from_slice(&data_bytes);
    // Compute checksum
    let checksum = check_sum(&*payload);
    // Encode
    payload.extend_from_slice(&checksum);
    encode(&payload, ss58_format)
}

#[cfg(test)]
mod tests {
    use std::ops::{BitAnd, BitOr};

    #[test]
    fn check_encode_ss58() {
        let compressed_pubkey = [
            0x18, 0x26, 0xD3, 0xED, 0xB1, 0xAE, 0x8E, 0x7E, 0xB7, 0xDB, 0xF0, 0xF1, 0x44, 0xE1,
            0xFF, 0x3F, 0x39, 0xBD, 0x5B, 0x8D, 0xA2, 0x57, 0x3C, 0xEB, 0x8A, 0xA0, 0x1E, 0x91,
            0x86, 0x90, 0xBD, 0x8F,
        ];
        let addr = super::encode(&compressed_pubkey, 63);
        assert_ne!(addr, None);
        println!("{:?}", addr);
    }

    #[test]
    fn check_bit_operations_encode() {
        // You can check whatever you want in Python concole:
        // ((ss58_format & 0x00FC) >> 2) | 0x0040, (ss58_format >> 8) | ((ss58_format & 0x0003) << 6)

        struct TestData {
            ss58_format: u16,
            output: [u8; 2],
        }

        let test_vec = vec![
            TestData {
                ss58_format: 64,
                output: [80, 0],
            },
            TestData {
                ss58_format: 250,
                output: [126, 128],
            },
        ];

        for test in test_vec {
            let result: [u8; 2] = [
                test.ss58_format
                    .bitand(0x00FC)
                    .rotate_right(2)
                    .bitor(0x0040) as u8,
                test.ss58_format
                    .rotate_right(8)
                    .bitor(test.ss58_format.bitand(0x0003).rotate_left(6)) as u8,
            ];
            assert_eq!(result, test.output);
        }
    }
}
