use ethers_core::types::H256;
use sha2::{Digest, Sha256};

use crate::sha256::vanilla::param::RATE;

/// Fixed length format for one SHA-256 512-bit input block.
/// This closely matches [crate::sha256::component::circuit::shard::LoadedSha256Block].
#[derive(Clone, Debug)]
pub struct Sha256IngestionFormat {
    pub bytes_per_block: [u8; RATE],
    /// In the last block of a full SHA-256 hash, this will be the length in bytes of the input.
    /// Otherwise 0. (Contrast with keccak where the length is in the FIRST block.)
    pub byte_len_placeholder: usize,
    /// Is this the last block of a full SHA-256 hash? Note that the last block includes input padding.
    pub is_final: bool,
    /// If `is_final = true`, the output of the full SHA-256 hash, split into two 128-bit chunks.
    /// Otherwise `sha256([])` in hi-lo form.
    pub hash_lo: u128,
    pub hash_hi: u128,
}

impl Default for Sha256IngestionFormat {
    fn default() -> Self {
        Self::new([0; RATE], 0, true, H256(sha256_digest(&[])))
    }
}

impl Sha256IngestionFormat {
    fn new(
        bytes_per_block: [u8; RATE],
        byte_len_placeholder: usize,
        is_final: bool,
        hash: H256,
    ) -> Self {
        let hash_lo = u128::from_be_bytes(hash[16..].try_into().unwrap());
        let hash_hi = u128::from_be_bytes(hash[..16].try_into().unwrap());
        Self { bytes_per_block, byte_len_placeholder, is_final, hash_lo, hash_hi }
    }
}

fn sha256_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// We take all `requests` as a deduplicated ordered list.
/// We split each input into `Sha256IngestionFormat` chunks, one for each 512-bit SHA-256 block
/// needed to compute `sha256(input)`.
/// We then resize so there are exactly `capacity` total chunks.
///
/// Very similar to [crate::sha256::component::encode::encode_native_input] except we do not do
/// the encoding part (that will be done in circuit, not natively).
///
/// Returns `Err(true_capacity)` if `true_capacity > capacity`, where `true_capacity` is the
/// number of SHA-256 blocks needed to compute all requests.
pub fn format_requests_for_ingestion<B>(
    requests: impl IntoIterator<Item = (B, Option<H256>)>,
    capacity: usize,
) -> Result<Vec<Sha256IngestionFormat>, usize>
where
    B: AsRef<[u8]>,
{
    let mut ingestions = Vec::with_capacity(capacity);
    for (input, hash) in requests {
        let input = input.as_ref();
        let hash = hash.unwrap_or_else(|| H256(sha256_digest(input)));
        let len = input.len();
        for (_, chunk) in input.chunks(RATE).enumerate() {
            let mut bytes_per_block = [0u8; RATE];
            bytes_per_block[..chunk.len()].copy_from_slice(chunk);
            // byte_len_placeholder starts as 0; the last block's will be updated below.
            ingestions.push(Sha256IngestionFormat::new(
                bytes_per_block,
                0,
                false,
                H256::zero(),
            ));
        }
        // If the input is empty, get_num_sha2_blocks(0) = 1, so we still need one block.
        // The loop above runs 0 times for empty input, so push an empty block.
        if input.is_empty() {
            ingestions.push(Sha256IngestionFormat::new([0; RATE], 0, false, H256::zero()));
        }
        // Mark the last block as final and set its length placeholder and hash.
        let last_mut = ingestions.last_mut().unwrap();
        last_mut.is_final = true;
        last_mut.byte_len_placeholder = len;
        last_mut.hash_hi = u128::from_be_bytes(hash[..16].try_into().unwrap());
        last_mut.hash_lo = u128::from_be_bytes(hash[16..].try_into().unwrap());
    }
    log::info!("Actual number of SHA-256 blocks used = {}", ingestions.len());
    if ingestions.len() > capacity {
        Err(ingestions.len())
    } else {
        ingestions.resize_with(capacity, Default::default);
        Ok(ingestions)
    }
}
