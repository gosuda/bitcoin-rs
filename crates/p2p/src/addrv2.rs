use bitcoin::consensus::encode;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};

/// BIP155 address network kind.
pub type AddressV2 = AddrV2;
/// BIP155 address message entry.
pub type NetAddressV2 = AddrV2Message;

/// Encode one BIP155 address entry.
pub fn encode_address(address: &NetAddressV2) -> Vec<u8> {
    encode::serialize(address)
}

/// Decode one BIP155 address entry.
pub fn decode_address(bytes: &[u8]) -> Result<NetAddressV2, encode::Error> {
    encode::deserialize(bytes)
}
