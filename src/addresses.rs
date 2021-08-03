use crate::consts::*;
use crate::hashing::sha2_256;
use base58::*;
use bech32_no_std::{self, FromBase32, ToBase32};
use blake2_rfc::blake2b::Blake2bResult;
use ripemd160::{Digest, Ripemd160};

// Bech32 types
pub enum PrefixBech32 {
    P2WPKH,
    P2WSH,
    P2WPKHTestnet,
    P2WSHTestnet,
}

// Legacy types
pub enum PrefixP2PWKH {
    P2pkh,
    P2sh,
    P2pkhTestnet,
    P2shTestnet,
}

impl PrefixP2PWKH {
    pub fn to_byte(&self) -> u8 {
        match self {
            // 1address - For standard bitcoin addresses
            PrefixP2PWKH::P2pkh => 0x00u8,
            // 3address - For sending to an address that requires multiple signatures (multisig)
            PrefixP2PWKH::P2sh => 0x05u8,
            // (m/n)address
            PrefixP2PWKH::P2pkhTestnet => 0x6Fu8,
            // 2address
            PrefixP2PWKH::P2shTestnet => 0xC4u8,
        }
    }
}

pub trait AddressHelper {
    // The public key is a hashed (sha256 -> Ripemd160) version of your public key.
    fn as_hash160(&self) -> Vec<u8>;

    // For taken a checksum usually need a doubled sha256
    fn as_doubled_sha256(&self) -> Vec<u8>;

    fn as_legacy_checksum(&self) -> Vec<u8>;

    fn to_legacy(&self, r#type: PrefixP2PWKH) -> String;

    fn to_bech32(&self, r#type: PrefixBech32) -> Option<String>;

    fn pubkey_to_pkh(&self) -> Option<String>;

    // Ss58 Helper
    fn as_ss58hash(&self) -> blake2_rfc::blake2b::Blake2bResult;

    fn to_ss58(&self, ss58_format: u16) -> Option<String>;
}

impl AddressHelper for [u8] {
    fn as_hash160(&self) -> Vec<u8> {
        let sha256 = sha2_256(self);

        // create a RIPEMD-160 hasher instance
        let mut hasher = Ripemd160::new();

        // process input message
        hasher.update(&sha256[..]);
        let hash160 = hasher.finalize();

        hash160.to_vec()
    }

    fn as_doubled_sha256(&self) -> Vec<u8> {
        let sha256 = sha2_256(self);
        let sha256 = sha2_256(&sha256);
        Vec::from(&sha256[..])
    }

    fn as_legacy_checksum(&self) -> Vec<u8> {
        Vec::from(&self.as_doubled_sha256()[0..4])
    }

    fn to_legacy(&self, r#type: PrefixP2PWKH) -> String {
        // create a RIPEMD-160 hasher instance
        let mut body = self.as_hash160();

        body.insert(0, r#type.to_byte());
        let checksum = body.as_slice().as_legacy_checksum();
        body.extend(checksum);

        body.to_base58()
    }

    fn to_bech32(&self, r#type: PrefixBech32) -> Option<String> {
        // There are many steps involved in it.
        // hash160(publickey) which is ripemd160(sha256(publickey)).
        // After that add 0 Uint8 to the output of bech32 words.
        // Then using bech32 encode it with the prefix bc for bitcoin.

        let mut body = self.as_hash160();

        let hrp = match r#type {
            PrefixBech32::P2WPKH | PrefixBech32::P2WSH => "bc",
            PrefixBech32::P2WPKHTestnet | PrefixBech32::P2WSHTestnet => "bt",
        };

        match bech32_no_std::encode(hrp, body.as_slice().to_base32()) {
            Ok(data) => {
                let mut data = data.replacen("bc1", "bc1q", 1);
                // Need to check checksum
                data.truncate(data.len() - 12);
                Some(data)
            }
            Err(_) => None,
        }
    }

    fn pubkey_to_pkh(&self) -> Option<String> {
        let hash160 = self.as_hash160();
        Some(hex::encode(hash160.as_slice()))
    }

    fn as_ss58hash(&self) -> Blake2bResult {
        // Checksum prefix
        const CHECKSUM_PREFIX: &[u8; 7] = b"SS58PRE";

        let mut context = blake2_rfc::blake2b::Blake2b::new(64);
        context.update(CHECKSUM_PREFIX);
        context.update(self);
        context.finalize()
    }

    fn to_ss58(&self, ss58_format: u16) -> Option<String> {
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
        v.extend(self);
        let r = &v.as_ss58hash();
        v.extend(&r.as_bytes()[0..2]);
        Some(v.to_base58())
    }
}

trait FromSs58 {
    fn from_ss58(&self) -> Option<(u16, Vec<u8>)>;
}

impl FromSs58 for &str {
    fn from_ss58(&self) -> Option<(u16, Vec<u8>)> {
        // Decode string
        let dec_bytes = self.from_base58().ok()?;

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
        if dec_bytes.len() != prefix_len + SS58_DATA_BYTE_LEN + SS58_CHECKSUM_LEN {
            if cfg!(test) {
                println!("Bad length {}", dec_bytes.len());
            }
            return None;
        }

        // Check format
        for i in SS58_RESERVED_FORMATS {
            if *i == ident.into() {
                if cfg!(test) {
                    println!("Invalid SS58 format {}", i);
                }
                return None;
            }
        }

        let hash = &dec_bytes[0..SS58_DATA_BYTE_LEN + prefix_len].as_ss58hash();
        let checksum = &hash.as_bytes()[0..SS58_CHECKSUM_LEN];
        if dec_bytes
            [SS58_DATA_BYTE_LEN + prefix_len..SS58_DATA_BYTE_LEN + prefix_len + SS58_CHECKSUM_LEN]
            != *checksum
        {
            // Invalid checksum.
            if cfg!(test) {
                println!("Invalid checksum");
            }
            return None;
        }
        let res: Vec<u8> = Vec::from(&dec_bytes[prefix_len..SS58_DATA_BYTE_LEN + prefix_len]);
        Some((ident, res))
    }
}

pub fn bech32_to_pkh(addr: &str) -> Option<String> {
    if addr.len() < BECH32_P2WPKH.len() {
        return None;
    }
    Some(addr[4..addr.len() - 6].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::*;
    use bech32_no_std::ToBase32;

    #[test]
    fn bech32_checksum() {
        let test_data = [
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ];
        let test_double_hashed_data: [u8; 32] = [
            0x05, 0xc4, 0xde, 0x7c, 0x10, 0x69, 0xe9, 0xde, 0x70, 0x3e, 0xfd, 0x17, 0x2e, 0x58,
            0xc1, 0x91, 0x9f, 0x48, 0xae, 0x03, 0x91, 0x02, 0x77, 0xa4, 0x9c, 0x9a, 0xfd, 0x7d,
            0xed, 0x58, 0xbb, 0xeb,
        ];
        let test_checksum: [u8; 4] = [0x05, 0xc4, 0xde, 0x7c];

        // Double sha256 test
        let hash = test_data.as_doubled_sha256();
        assert_eq!(&test_double_hashed_data[..], hash.as_slice());

        // Checksum test
        let checksum = test_data.as_legacy_checksum();
        assert_eq!(&test_checksum[..], checksum.as_slice());
    }

    #[test]
    fn bech32_hash160() {
        let test_pubkey = [
            0x02u8, 0xb4, 0x63, 0x2d, 0x08, 0x48, 0x5f, 0xf1, 0xdf, 0x2d, 0xb5, 0x5b, 0x9d, 0xaf,
            0xd2, 0x33, 0x47, 0xd1, 0xc4, 0x7a, 0x45, 0x70, 0x72, 0xa1, 0xe8, 0x7b, 0xe2, 0x68,
            0x96, 0x54, 0x9a, 0x87, 0x37,
        ];

        let test_hash160 = [
            0x93u8, 0xce, 0x48, 0x57, 0x0b, 0x55, 0xc4, 0x2c, 0x2a, 0xf8, 0x16, 0xae, 0xab, 0xa0,
            0x6c, 0xfe, 0xe1, 0x22, 0x4f, 0xae,
        ];

        let hash160 = test_pubkey.as_hash160();

        assert_eq!(&test_hash160, hash160.as_slice());
    }

    #[test]
    fn bech32_to_pkh() {
        assert_eq!(
            super::bech32_to_pkh(BECH32_P2WPKH).unwrap(),
            "2wzdwh9znl8jz306ncgagapmaevkqt68"
        );
    }

    #[test]
    fn legacy_encode_address() {
        // 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        // bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

        println!("{}", hex::encode(&COMPRESSED_PUBKEY));
        let address = &COMPRESSED_PUBKEY.to_legacy(PrefixP2PWKH::P2pkh);
        assert_ne!(address, ""); // NEED TO CHANGE THE TEST DATA
    }

    #[test]
    fn bech32_encode_address() {
        println!("{}", hex::encode(&COMPRESSED_PUBKEY));
        let address = &COMPRESSED_PUBKEY.to_bech32(PrefixBech32::P2WPKH).unwrap();
        assert_eq!(address, BECH32_P2WPKH);
    }

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
        let (format, data) = ss58_address.from_ss58().unwrap();
        assert_eq!(hex::encode(data), hex::encode(compressed_pubkey));

        // Check decoding function from the Compressed Pubkey to ss58 address
        let addr = &compressed_pubkey.to_ss58(format).unwrap();
        println!("ss58 address from pubkey {:?}", addr);
        assert_eq!(addr, ss58_address);
    }

    #[test]
    fn check_ss58_to_pkh() {
        let compressed_pubkey = [
            0x02, 0xb4, 0x63, 0x2d, 0x08, 0x48, 0x5f, 0xf1, 0xdf, 0x2d, 0xb5, 0x5b, 0x9d, 0xaf,
            0xd2, 0x33, 0x47, 0xd1, 0xc4, 0x7a, 0x45, 0x70, 0x72, 0xa1, 0xe8, 0x7b, 0xe2, 0x68,
            0x96, 0x54, 0x9a, 0x87, 0x37,
        ];
        let pkh = "93ce48570b55c42c2af816aeaba06cfee1224fae";
        let pkh_data = compressed_pubkey.pubkey_to_pkh().unwrap();
        assert_eq!(pkh, pkh_data);
    }
}
