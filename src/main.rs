mod addresses;
#[allow(dead_code)]
mod consts;
#[allow(dead_code)]
mod hashing;

use addresses::*;
use consts::*;

fn main() {
    println!(
        "{:-<79}+\n| Have a look at addresses.rs{: <50}|\n{:-<79}+",
        "+", " ", "+"
    );

    println!(
        "The example public key is 0x{}\n",
        hex::encode(&COMPRESSED_PUBKEY)
    );

    let p2wpkh_address = &COMPRESSED_PUBKEY.to_bech32(PrefixBech32::P2WPKH).unwrap();
    println!(
        "Let's take from the public key a P2WPKH address: {}",
        &p2wpkh_address
    );

    let ss58_address = &COMPRESSED_PUBKEY[1..].to_ss58(0).unwrap();
    println!(
        "Let's take from the public key a ss58 address: {}",
        ss58_address
    );

    let p2wpkh_pkh = p2wpkh_address.as_str().bech32_as_pkh().unwrap();
    println!(
        "Let's take pubkey hash from the p2wpkh address: {}",
        &p2wpkh_pkh
    );

    let ss58_pkh = ss58_address.as_str().ss58_as_pkh().unwrap();
    println!(
        "Let's take pubkey hash from the ss58 address: {}",
        &ss58_pkh
    );

    println!("{:-<80}", "-");

    if p2wpkh_pkh == ss58_pkh.as_str() {
        println!("Pubkey hash is equal for the different address types");
    } else {
        println!("ERROR! Pubkey hash isn't equal");
    }
}
