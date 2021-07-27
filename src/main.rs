use bech32_no_std::u5;
use bech32_no_std::{self, FromBase32, ToBase32};
use std::borrow::Cow;
use std::marker::PhantomData;

// That trait allow to convert between addr, pubkey and seed phrase
trait AddressFormat {
    type PubkeyFormat;
    type AddrFormat;

    fn new(addr: &str) -> Self;

    fn addr_to_pubkey(addr: Cow<&str>) -> Self::PubkeyFormat;

    fn pubkey_to_addr(pubkey: Self::PubkeyFormat) -> Self::AddrFormat;
}

struct AddressConvertor<'a, TIn: AddressFormat, TOut: AddressFormat> {
    phantom_in: PhantomData<&'a TIn>,
    phantom_out: PhantomData<&'a TOut>,
}

impl <TIn: AddressFormat, TOut: AddressFormat>AddressConvertor<'_, TIn, TOut> {

    pub fn convert(address: TIn) -> TOut {
        unimplemented!()
    }
}

#[derive(Debug)]
struct Bech32 {
    addr: String,
    pubkey: <Bech32 as AddressFormat>::PubkeyFormat,
}

impl AddressFormat for Bech32 {
    type PubkeyFormat = [u8; 32];
    type AddrFormat = Ss58;

    fn new(addr: &str) -> Self {
        Self {
            addr: String::from(addr),
            pubkey: [0; 32],
        }
    }


    fn addr_to_pubkey(addr: Cow<&str>) -> Self::PubkeyFormat {
        unimplemented!()
    }

    fn pubkey_to_addr(pubkey: Self::PubkeyFormat) -> Self::AddrFormat {
        unimplemented!()
    }

    // fn seed_to_addr ...
}

#[derive(Debug)]
struct Ss58 {
    addr: String,
    pubkey: <Ss58 as AddressFormat>::PubkeyFormat,
}

impl AddressFormat for Ss58 {
    type PubkeyFormat = [u8; 32];
    type AddrFormat = Bech32;

    fn new(addr: &str) -> Self {
        Self {
            addr: String::from(addr),
            pubkey: [0; 32],
        }
    }

    fn addr_to_pubkey(addr: Cow<&str>) -> Self::PubkeyFormat {
        unimplemented!()
    }

    fn pubkey_to_addr(pubkey: Self::PubkeyFormat) -> Self::AddrFormat {
        unimplemented!()
    }
}


// Below consts related to the same PRIVKEY
const BECH32_P2WPKH: &'static str = "bc1q2wzdwh9znl8jz306ncgagapmaevkqt68g25klg";
const BECH32_P2WSH: &'static str =
    "bc1qnrsum0njvrk92rm4kf46a2rv5yqwgccxgg4vkqv9pwczhz5wtltszfqyuy";
const BECH32_SHA256: &'static str =
    "A51066EDD669F9BC2400361A6DFAC289C91E359AAC144CA30C3A27387D695603";
const COMPRESSED_PRIVKEY: &'static str = "L58kXqwx8JUWoVm4EuaX9bFeCSYWcwiuTKCFvxoFsE4p7GoorRDC";
pub const DEV_PHRASE: &str =
    "umbrella concert repeat fit elevator slogan one oven guess story derive thank wave unfair found spare decline law desert tunnel saddle universe enable absent";
const COMPRESSED_PUBKEY: [u8; 33] = [ // subkey inspect --public
    0x03, /* Padding */ 0x18, 0x26, 0xD3, 0xED, 0xB1, 0xAE, 0x8E, 0x7E, 0xB7, 0xDB, 0xF0,
    0xF1, 0x44, 0xE1, 0xFF, 0x3F, 0x39, 0xBD, 0x5B, 0x8D, 0xA2, 0x57, 0x3C, 0xEB, 0x8A, 0xA0,
    0x1E, 0x91, 0x86, 0x90, 0xBD, 0x8F,
];
const DATA_U5: [u8; 33] = [
    0, /* Padding */
    10, 14, 02, 13, 14, 23, 05, 02, 19, 31, 07, 18, 02, 17, 15, 26, 19, 24, 08, 29, 08, 29, 01,
    27, 29, 25, 12, 22, 00, 11, 26, 07,
];

fn main() {

    let addr: Bech32 = AddressConvertor::<'_, Ss58, Bech32>::convert(Ss58::new("addr"));
    println!("{:?}", addr);
}


#[cfg(test)]
mod tests {
    //use sp_core::ed25519::Pair;
    //use sp_core::sr25519::Pair;
    use bech32_no_std::u5;
    use bech32_no_std::{self, FromBase32, ToBase32};
use bitcoin_hashes::{ripemd160, sha256, Hash, HashEngine};
    use sp_core::ecdsa::Pair;
    use sp_core::Pair;
    //use std::convert::TryFrom;
    //use crate::{crypto::{DEV_PHRASE, set_default_ss58_version}, keccak_256};

    // Below consts related to the same PRIVKEY
    const BECH32_P2WPKH: &'static str = "bc1q2wzdwh9znl8jz306ncgagapmaevkqt68g25klg";
    const BECH32_P2WSH: &'static str =
        "bc1qnrsum0njvrk92rm4kf46a2rv5yqwgccxgg4vkqv9pwczhz5wtltszfqyuy";
    const BECH32_SHA256: &'static str =
        "A51066EDD669F9BC2400361A6DFAC289C91E359AAC144CA30C3A27387D695603";
    const COMPRESSED_PRIVKEY: &'static str = "L58kXqwx8JUWoVm4EuaX9bFeCSYWcwiuTKCFvxoFsE4p7GoorRDC";
    pub const DEV_PHRASE: &str =
        "umbrella concert repeat fit elevator slogan one oven guess story derive thank wave unfair found spare decline law desert tunnel saddle universe enable absent";
    const COMPRESSED_PUBKEY: [u8; 33] = [
        0x03, /* Padding */ 0x18, 0x26, 0xD3, 0xED, 0xB1, 0xAE, 0x8E, 0x7E, 0xB7, 0xDB, 0xF0,
        0xF1, 0x44, 0xE1, 0xFF, 0x3F, 0x39, 0xBD, 0x5B, 0x8D, 0xA2, 0x57, 0x3C, 0xEB, 0x8A, 0xA0,
        0x1E, 0x91, 0x86, 0x90, 0xBD, 0x8F,
    ];
    const DATA_U5: [u8; 33] = [
        0, /* Padding */
        10, 14, 02, 13, 14, 23, 05, 02, 19, 31, 07, 18, 02, 17, 15, 26, 19, 24, 08, 29, 08, 29, 01,
        27, 29, 25, 12, 22, 00, 11, 26, 07,
    ];

    #[test]
    fn make_an_account() {
        let mnemonic = "sample split bamboo west visual approve brain fox arch impact relief smile";
    }

    // Test of correct decode Bech32 P2WPKH to data
    #[test]
    fn bech32_valid_address() {
        let data_u5: Vec<u5> = Vec::from(&DATA_U5[..])
            .into_iter()
            .map(|x| u5::try_from_u8(x).unwrap())
            .collect();

        let (hrp, data) = bech32_no_std::decode(BECH32_P2WPKH).unwrap();
        dbg!(&data
            .clone()
            .into_iter()
            .map(|x| x.to_u8())
            .collect::<Vec<u8>>());

        assert_eq!(hrp, "bc");
        assert_eq!(&data, &data_u5);
    }

    #[test]
    fn bech32_pubkey_to_addr() {
        // There are many steps involved in it.
        // hash160(publickey) which is ripemd160(sha256(publickey)).
        // After that add 0 Uint8 to the output of bech32 words.
        // Then using bech32 encode it with the prefix bc for bitcoin.

        let _compressed_pubkey: Vec<u8> = vec![
            0x03, 0x18, 0x26, 0xD3, 0xED, 0xB1, 0xAE, 0x8E, 0x7E, 0xB7, 0xDB, 0xF0, 0xF1, 0x44,
            0xE1, 0xFF, 0x3F, 0x39, 0xBD, 0x5B, 0x8D, 0xA2, 0x57, 0x3C, 0xEB, 0x8A, 0xA0, 0x1E,
            0x91, 0x86, 0x90, 0xBD, 0x8F,
        ];
        let sha256 = sp_core::hashing::sha2_256(&COMPRESSED_PUBKEY[..]);
        let mut engine = sha256::HashEngine::default();
        engine.input(&COMPRESSED_PUBKEY[..]);
        let mut hash: sha256 = Hash::from_engine(engine);
        assert_eq!(&sha256, &hash.to_string());
    }

    #[test]
    fn bech32_soft_known_pair_should_work() {
        // let pair: sp_core::ecdsa::Pair =
        //     sp_core::ecdsa::Pair::from_string(&format!("{}/Alice", DEV_PHRASE), None).unwrap();
        // known address of DEV_PHRASE with 1.1
        //let known =
        //    hex_literal::hex!("d6c71059dbbe9ad2b0ed3f289738b800836eb425544ce694825285b958ca755e");
        //assert_eq!(pair.public().to_raw_vec(), known);

        //let pub_key: Vec<u8> = pair.public().to_raw_vec();
        //dbg!(pub_key);
    }
}
