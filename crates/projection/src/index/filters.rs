/// A BIP158 basic filter as the segment tail records it: the GCS body, its
/// double-SHA256 hash, and the chained filter header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicFilter {
    pub filter: Vec<u8>,
    pub hash: [u8; 32],
    pub header: [u8; 32],
}
