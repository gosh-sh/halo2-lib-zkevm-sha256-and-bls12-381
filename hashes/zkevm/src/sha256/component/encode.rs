use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    poseidon::hasher::{PoseidonCompactChunkInput, PoseidonHasher},
    safe_types::{FixLenBytesVec, SafeByte, SafeTypeChip, VarLenBytesVec},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use num_bigint::BigUint;
use snark_verifier::loader::native::NativeLoader;

use crate::{
    sha256::vanilla::{param::*, util::get_num_sha2_blocks},
    util::eth_types::Field,
};

use super::param::*;

// For reference, when F is bn254::Fr:
// NUM_BITS_PER_WORD = 32  (SHA-256 uses 32-bit words, vs 64-bit for keccak)
// num_word_per_witness = 7
// num_witness_per_sha256_block = 3
// num_poseidon_absorb_per_sha256_block = 2

/// Module to encode raw inputs into lookup keys for looking up SHA-256 results. The encoding is
/// designed to be efficient in component circuits.

/// Encode a native input bytes into its corresponding lookup key. This function can be considered as the spec of the encoding.
///
/// Unlike keccak where the length placeholder is placed in the **first** block (using decreasing
/// `bytes_left`), for SHA-256 the length placeholder is placed in the **last** (final) block.
/// This matches the vanilla circuit where `length` is cumulative and equals the total input length
/// only at the final block.
pub fn encode_native_input<F: Field>(bytes: &[u8]) -> F {
    assert!(NUM_BITS_PER_WORD <= u128::BITS as usize);
    let multipliers: Vec<F> = get_words_to_witness_multipliers::<F>();
    let num_word_per_witness = num_word_per_witness::<F>();
    let len = bytes.len();
    let num_blocks = get_num_sha2_blocks(len);

    // Divide the bytes input into SHA-256 words (each word has NUM_BYTES_PER_WORD = 4 bytes).
    let mut words = bytes
        .chunks(NUM_BYTES_PER_WORD)
        .map(|chunk| {
            let mut padded_chunk = [0; u128::BITS as usize / NUM_BITS_PER_BYTE];
            padded_chunk[..chunk.len()].copy_from_slice(chunk);
            u128::from_le_bytes(padded_chunk)
        })
        .collect_vec();
    // Pad words to fill exactly num_blocks * NUM_WORDS_TO_ABSORB slots.
    words.resize(num_blocks * NUM_WORDS_TO_ABSORB, 0);

    // 1. Split SHA-256 words into blocks (each block has NUM_WORDS_TO_ABSORB = 16 words).
    // 2. Append an extra word at the beginning of each block. In the LAST block, this word is the
    //    byte length of the input. Otherwise 0.
    //    (Contrast with keccak where the length goes in the FIRST block using bytes_left.)
    let words_per_block = words
        .chunks(NUM_WORDS_TO_ABSORB)
        .enumerate()
        .map(|(i, chunk)| {
            let mut padded_chunk = [0u128; NUM_WORDS_TO_ABSORB + 1];
            padded_chunk[0] = if i == num_blocks - 1 { len as u128 } else { 0 };
            padded_chunk[1..(chunk.len() + 1)].copy_from_slice(chunk);
            padded_chunk
        })
        .collect_vec();
    // Compress every num_word_per_witness words into a witness.
    let witnesses_per_block = words_per_block
        .iter()
        .map(|chunk| {
            chunk
                .chunks(num_word_per_witness)
                .map(|c| {
                    c.iter().zip(multipliers.iter()).fold(F::ZERO, |acc, (word, multiplier)| {
                        acc + F::from_u128(*word) * multiplier
                    })
                })
                .collect_vec()
        })
        .collect_vec();
    // Absorb witnesses block by block.
    let mut native_poseidon_sponge =
        snark_verifier::util::hash::Poseidon::<F, F, POSEIDON_T, POSEIDON_RATE>::new::<
            POSEIDON_R_F,
            POSEIDON_R_P,
            POSEIDON_SECURE_MDS,
        >(&NativeLoader);
    for witnesses in witnesses_per_block {
        for absorbing in witnesses.chunks(POSEIDON_RATE) {
            // Pad 0s to make sure absorb.len() == RATE, so witnesses of different blocks are
            // never mixed in a single absorb round.
            let mut padded_absorb = [F::ZERO; POSEIDON_RATE];
            padded_absorb[..absorbing.len()].copy_from_slice(absorbing);
            native_poseidon_sponge.update(&padded_absorb);
        }
    }
    native_poseidon_sponge.squeeze()
}

/// Encode a VarLenBytesVec into its corresponding lookup key.
pub fn encode_var_len_bytes_vec<F: Field>(
    ctx: &mut Context<F>,
    range_chip: &impl RangeInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    bytes: &VarLenBytesVec<F>,
) -> AssignedValue<F> {
    let max_len = bytes.max_len();
    let max_num_sha2_blocks = get_num_sha2_blocks(max_len);
    // num_blocks = (len + 8) / RATE + 1
    // block index of final block = num_blocks - 1 = (len + 8) / RATE
    let num_bits = bit_length((max_len + NUM_BYTES_PADDING_LENGTH) as u64);
    let len_plus_padding = range_chip
        .gate()
        .add(ctx, *bytes.len(), Constant(F::from(NUM_BYTES_PADDING_LENGTH as u64)));
    let (block_idx_of_final, _) =
        range_chip.div_mod(ctx, len_plus_padding, BigUint::from(RATE), num_bits);
    // f_indicator[i] = 1 iff block i is the final block
    let f_indicator =
        range_chip.gate().idx_to_indicator(ctx, block_idx_of_final, max_num_sha2_blocks);

    let bytes = bytes.ensure_0_padding(ctx, range_chip.gate());
    // For each block i: length placeholder = len * f_indicator[i]
    // (non-zero only for the final block, where it equals total input length)
    let len_per_block = f_indicator
        .iter()
        .map(|indicator| range_chip.gate().mul(ctx, *bytes.len(), *indicator))
        .collect_vec();
    let chunk_input_per_block =
        format_input(ctx, range_chip.gate(), bytes.bytes(), &len_per_block);

    let chunk_inputs = chunk_input_per_block
        .into_iter()
        .zip(&f_indicator)
        .map(|(chunk_input, is_final)| {
            let is_final = SafeTypeChip::unsafe_to_bool(*is_final);
            PoseidonCompactChunkInput::new(chunk_input, is_final)
        })
        .collect_vec();

    let compact_outputs =
        initialized_hasher.hash_compact_chunk_inputs(ctx, range_chip.gate(), &chunk_inputs);
    range_chip.gate().select_by_indicator(
        ctx,
        compact_outputs.into_iter().map(|o| *o.hash()),
        f_indicator,
    )
}

/// Encode a FixLenBytesVec into its corresponding lookup key.
pub fn encode_fix_len_bytes_vec<F: Field>(
    ctx: &mut Context<F>,
    gate_chip: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    bytes: &FixLenBytesVec<F>,
) -> AssignedValue<F> {
    let num_blocks = get_num_sha2_blocks(bytes.len());
    let zero_const = ctx.load_zero();
    let len_witness = ctx.load_constant(F::from(bytes.len() as u64));
    // Length placeholder is non-zero only for the final block (index num_blocks - 1).
    let mut len_per_block = vec![zero_const; num_blocks];
    len_per_block[num_blocks - 1] = len_witness;

    let chunk_input_per_block = format_input(ctx, gate_chip, bytes.bytes(), &len_per_block);
    let flatten_inputs = chunk_input_per_block
        .into_iter()
        .flat_map(|chunk_input| chunk_input.into_iter().flatten())
        .collect_vec();

    initialized_hasher.hash_fix_len_array(ctx, gate_chip, &flatten_inputs)
}

/// Number of SHA-256 words packed into each Poseidon witness field element.
/// When `F` is `bn254::Fr`, this is 7.
pub const fn num_word_per_witness<F: Field>() -> usize {
    (F::CAPACITY as usize) / NUM_BITS_PER_WORD
}

/// Number of witnesses to represent inputs in a SHA-256 block.
///
/// Each block has NUM_WORDS_TO_ABSORB + 1 words (including the length placeholder).
/// When `F` is `bn254::Fr`, this is 3.
pub const fn num_witness_per_sha256_block<F: Field>() -> usize {
    // ceil((NUM_WORDS_TO_ABSORB + 1) / num_word_per_witness)
    NUM_WORDS_TO_ABSORB / num_word_per_witness::<F>() + 1
}

/// Number of Poseidon absorb rounds per SHA-256 block.
///
/// When `F` is `bn254::Fr`, with POSEIDON_RATE = 2, this is 2.
pub const fn num_poseidon_absorb_per_sha256_block<F: Field>() -> usize {
    // ceil(num_witness_per_sha256_block / POSEIDON_RATE)
    (num_witness_per_sha256_block::<F>() - 1) / POSEIDON_RATE + 1
}

pub(crate) fn get_words_to_witness_multipliers<F: Field>() -> Vec<F> {
    let num_word_per_witness = num_word_per_witness::<F>();
    let mut multiplier_f = F::ONE;
    let mut multipliers = Vec::with_capacity(num_word_per_witness);
    multipliers.push(multiplier_f);
    // Each SHA-256 word is NUM_BITS_PER_WORD = 32 bits, so base = 2^32.
    let base_f = F::from_u128(1u128 << NUM_BITS_PER_WORD);
    for _ in 1..num_word_per_witness {
        multiplier_f *= base_f;
        multipliers.push(multiplier_f);
    }
    multipliers
}

pub(crate) fn get_bytes_to_words_multipliers<F: Field>() -> Vec<F> {
    let mut multiplier_f = F::ONE;
    let mut multipliers = Vec::with_capacity(NUM_BYTES_PER_WORD);
    multipliers.push(multiplier_f);
    let base_f = F::from_u128(1 << NUM_BITS_PER_BYTE);
    for _ in 1..NUM_BYTES_PER_WORD {
        multiplier_f *= base_f;
        multipliers.push(multiplier_f);
    }
    multipliers
}

/// Format raw input bytes into the Poseidon absorb structure for SHA-256 component encoding.
///
/// `len_per_block[i]` is the length placeholder for block `i` — should be `total_len` for the
/// final block, and 0 for all others.
///
/// Returns `Vec<Vec<[AssignedValue<F>; POSEIDON_RATE]>>` — one inner vec per SHA-256 block,
/// each inner vec has `num_poseidon_absorb_per_sha256_block` absorb chunks.
fn format_input<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[SafeByte<F>],
    len_per_block: &[AssignedValue<F>],
) -> Vec<Vec<[AssignedValue<F>; POSEIDON_RATE]>> {
    let zero_const = ctx.load_zero();
    let bytes_to_words_multipliers_val =
        get_bytes_to_words_multipliers::<F>().into_iter().map(|m| Constant(m)).collect_vec();
    let words_to_witness_multipliers_val =
        get_words_to_witness_multipliers::<F>().into_iter().map(|m| Constant(m)).collect_vec();

    // Pack bytes into 4-byte LE SHA-256 words.
    let words = bytes
        .chunks(NUM_BYTES_PER_WORD)
        .map(|c| {
            let len = c.len();
            let multipliers = bytes_to_words_multipliers_val[..len].to_vec();
            gate.inner_product(ctx, c.iter().map(|sb| *sb.as_ref()), multipliers)
        })
        .collect_vec();

    // Group words into blocks of NUM_WORDS_TO_ABSORB, prepend length placeholder per block.
    let num_blocks = len_per_block.len();
    let words_per_block = words
        .chunks(NUM_WORDS_TO_ABSORB)
        .enumerate()
        .map(|(i, words_in_block)| {
            let mut buffer = [zero_const; NUM_WORDS_TO_ABSORB + 1];
            buffer[0] = len_per_block[i];
            buffer[1..words_in_block.len() + 1].copy_from_slice(words_in_block);
            buffer
        })
        .chain(
            // If bytes don't fill all blocks (e.g. max_len not a multiple of RATE), pad with
            // empty blocks. len_per_block drives the number of blocks.
            (words.chunks(NUM_WORDS_TO_ABSORB).count()..num_blocks).map(|i| {
                let mut buffer = [zero_const; NUM_WORDS_TO_ABSORB + 1];
                buffer[0] = len_per_block[i];
                buffer
            }),
        )
        .collect_vec();

    let witnesses_per_block = words_per_block
        .iter()
        .map(|words| {
            words
                .chunks(num_word_per_witness::<F>())
                .map(|c| {
                    gate.inner_product(ctx, c.to_vec(), words_to_witness_multipliers_val.clone())
                })
                .collect_vec()
        })
        .collect_vec();

    witnesses_per_block
        .iter()
        .map(|witnesses| {
            witnesses
                .chunks(POSEIDON_RATE)
                .map(|c| {
                    let mut buffer = [zero_const; POSEIDON_RATE];
                    buffer[..c.len()].copy_from_slice(c);
                    buffer
                })
                .collect_vec()
        })
        .collect_vec()
}
