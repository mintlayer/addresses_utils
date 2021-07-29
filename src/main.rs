mod base58;
#[allow(dead_code)]
mod bech32;
#[allow(dead_code)]
mod consts;
#[allow(dead_code)]
mod hashing;
#[allow(dead_code)]
mod ss58;

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

impl<TIn: AddressFormat, TOut: AddressFormat> AddressConvertor<'_, TIn, TOut> {
    pub fn convert(_address: TIn) -> TOut {
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

    fn addr_to_pubkey(_addr: Cow<&str>) -> Self::PubkeyFormat {
        unimplemented!()
    }

    fn pubkey_to_addr(_pubkey: Self::PubkeyFormat) -> Self::AddrFormat {
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

    fn addr_to_pubkey(_addr: Cow<&str>) -> Self::PubkeyFormat {
        unimplemented!()
    }

    fn pubkey_to_addr(_pubkey: Self::PubkeyFormat) -> Self::AddrFormat {
        unimplemented!()
    }
}

fn main() {
    let addr: Bech32 = AddressConvertor::<'_, Ss58, Bech32>::convert(Ss58::new("addr"));
    println!("{:?}", addr);
}
