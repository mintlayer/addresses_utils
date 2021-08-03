// Reserved formats
pub const SS58_RESERVED_FORMATS: &'static [u32] = &[46, 47];
// Data length in bytes
pub const SS58_DATA_BYTE_LEN: usize = 32;
// Checksum length in bytes
pub const SS58_CHECKSUM_LEN: usize = 2;

// Below consts related to the same PRIVKEY

pub const BECH32_P2WPKH: &'static str = "bc1q2wzdwh9znl8jz306ncgagapmaevkqt68g25klg";
pub const BECH32_P2WSH: &'static str =
    "bc1qnrsum0njvrk92rm4kf46a2rv5yqwgccxgg4vkqv9pwczhz5wtltszfqyuy";
pub const BECH32_SHA256: &'static str =
    "A51066EDD669F9BC2400361A6DFAC289C91E359AAC144CA30C3A27387D695603";
pub const COMPRESSED_PRIVKEY: &'static str = "L58kXqwx8JUWoVm4EuaX9bFeCSYWcwiuTKCFvxoFsE4p7GoorRDC";
pub const DEV_PHRASE: &str =
    "umbrella concert repeat fit elevator slogan one oven guess story derive thank wave unfair found spare decline law desert tunnel saddle universe enable absent";
pub const COMPRESSED_PUBKEY: [u8; 33] = [
    // subkey inspect --public
    0x03, /* Padding */ 0x18, 0x26, 0xD3, 0xED, 0xB1, 0xAE, 0x8E, 0x7E, 0xB7, 0xDB, 0xF0, 0xF1,
    0x44, 0xE1, 0xFF, 0x3F, 0x39, 0xBD, 0x5B, 0x8D, 0xA2, 0x57, 0x3C, 0xEB, 0x8A, 0xA0, 0x1E, 0x91,
    0x86, 0x90, 0xBD, 0x8F,
];
pub const DATA_U5: [u8; 33] = [
    0, /* Padding */
    10, 14, 02, 13, 14, 23, 05, 02, 19, 31, 07, 18, 02, 17, 15, 26, 19, 24, 08, 29, 08, 29, 01, 27,
    29, 25, 12, 22, 00, 11, 26, 07,
];
