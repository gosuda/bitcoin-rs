use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_primitives::BlockHash;

pub(crate) struct BlockBodies {
    pub(crate) bodies: Vec<(u32, BlockHash, Vec<u8>)>,
}

impl BlockBodySource for BlockBodies {
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.bodies
            .iter()
            .find(|(candidate_height, candidate_hash, _)| {
                *candidate_height == height && *candidate_hash == hash
            })
            .map(|(_, _, body)| body.clone())
    }
}
