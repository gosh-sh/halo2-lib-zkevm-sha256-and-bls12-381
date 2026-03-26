use crate::sha256::component::output::{
    dummy_circuit_output, input_to_circuit_outputs, multi_inputs_to_circuit_outputs,
    Sha256CircuitOutput,
};
use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use itertools::Itertools;
use lazy_static::lazy_static;

lazy_static! {
    // sha256([]) = e3b0c44298fc1c14...
    static ref OUTPUT_EMPTY: Sha256CircuitOutput<Fr> = dummy_circuit_output::<Fr>();

    // sha256([0x00]) = 6e340b9cffb37a98...
    static ref OUTPUT_0: Sha256CircuitOutput<Fr> =
        input_to_circuit_outputs::<Fr>(&[0]).pop().unwrap();

    // sha256(0..55) = 463eb28e72f82e0a... (single block)
    static ref OUTPUT_0_55: Sha256CircuitOutput<Fr> =
        input_to_circuit_outputs::<Fr>(&(0u8..55).collect_vec()).pop().unwrap();

    // sha256(0..56) = da2ae4d6b36748f2... (2 blocks)
    static ref OUTPUT_0_56: Sha256CircuitOutput<Fr> =
        input_to_circuit_outputs::<Fr>(&(0u8..56).collect_vec()).pop().unwrap();

    // sha256(0..200) = 1901da1c9f699b48... (4 blocks)
    static ref OUTPUT_0_200: Sha256CircuitOutput<Fr> =
        input_to_circuit_outputs::<Fr>(&(0u8..200).collect_vec()).pop().unwrap();
}

#[test]
fn test_dummy_circuit_output() {
    let Sha256CircuitOutput { hash_lo, hash_hi, .. } = *OUTPUT_EMPTY;
    // sha256([]) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(hash_hi, Fr::from_u128(0xe3b0c44298fc1c149afbf4c8996fb924));
    assert_eq!(hash_lo, Fr::from_u128(0x27ae41e4649b934ca495991b7852b855));
}

#[test]
fn test_input_to_circuit_outputs_empty() {
    let result = input_to_circuit_outputs::<Fr>(&[]);
    // Empty input: 1 block
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], *OUTPUT_EMPTY);
}

#[test]
fn test_input_to_circuit_outputs_single_byte() {
    let result = input_to_circuit_outputs::<Fr>(&[0]);
    // 1 byte: 1 block
    assert_eq!(result.len(), 1);
    // sha256([0x00]) = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
    assert_eq!(result[0].hash_hi, Fr::from_u128(0x6e340b9cffb37a989ca544e6bb780a2c));
    assert_eq!(result[0].hash_lo, Fr::from_u128(0x78901d3fb33738768511a30617afa01d));
    assert_eq!(result[0], *OUTPUT_0);
}

#[test]
fn test_input_to_circuit_outputs_single_block_full() {
    // 55 bytes is the maximum for a single SHA-256 block (55 + 1 + 8 = 64 bytes)
    let result = input_to_circuit_outputs::<Fr>(&(0u8..55).collect_vec());
    assert_eq!(result.len(), 1);
    // sha256(0..55) = 463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59
    assert_eq!(result[0].hash_hi, Fr::from_u128(0x463eb28e72f82e0a96c0a4cc53690c57));
    assert_eq!(result[0].hash_lo, Fr::from_u128(0x1281131f672aa229e0d45ae59b598b59));
    assert_eq!(result[0], *OUTPUT_0_55);
}

#[test]
fn test_input_to_circuit_outputs_two_blocks() {
    // 56 bytes requires 2 blocks (56 + 1 + 8 > 64)
    let result = input_to_circuit_outputs::<Fr>(&(0u8..56).collect_vec());
    assert_eq!(result.len(), 2);
    // First block is a dummy (non-final) output = padding with sha256([])
    assert_eq!(result[0], *OUTPUT_EMPTY);
    // Second block has the real hash
    // sha256(0..56) = da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562
    assert_eq!(result[1].hash_hi, Fr::from_u128(0xda2ae4d6b36748f2a318f23e7ab1dfdf));
    assert_eq!(result[1].hash_lo, Fr::from_u128(0x45acdc9d049bd80e59de82a60895f562));
    assert_eq!(result[1], *OUTPUT_0_56);
}

#[test]
fn test_input_to_circuit_outputs_multi_block() {
    // 200 bytes: get_num_sha2_blocks(200) = (200+8)/64 + 1 = 3 + 1 = 4 blocks
    let result = input_to_circuit_outputs::<Fr>(&(0u8..200).collect_vec());
    assert_eq!(result.len(), 4);
    // First 3 blocks are dummy outputs
    assert_eq!(result[0], *OUTPUT_EMPTY);
    assert_eq!(result[1], *OUTPUT_EMPTY);
    assert_eq!(result[2], *OUTPUT_EMPTY);
    // Last block has the real hash
    // sha256(0..200) = 1901da1c9f699b48f6b2636e65cbf73abf99d0441ef67f5c540a42f7051dec6f
    assert_eq!(result[3].hash_hi, Fr::from_u128(0x1901da1c9f699b48f6b2636e65cbf73a));
    assert_eq!(result[3].hash_lo, Fr::from_u128(0xbf99d0441ef67f5c540a42f7051dec6f));
    assert_eq!(result[3], *OUTPUT_0_200);
}

#[test]
fn test_multi_input_to_circuit_outputs() {
    let results = multi_inputs_to_circuit_outputs::<Fr>(
        &[
            (0u8..55).collect_vec(),
            (0u8..200).collect_vec(),
            vec![],
            vec![0],
            (0u8..56).collect_vec(),
        ],
        15,
    );
    assert_eq!(results.len(), 15);
    // 55-byte input: 1 block → index 0
    assert_eq!(results[0], *OUTPUT_0_55);
    // 200-byte input: 4 blocks → indices 1..4 (3 dummy + 1 real)
    assert_eq!(results[1], *OUTPUT_EMPTY);
    assert_eq!(results[2], *OUTPUT_EMPTY);
    assert_eq!(results[3], *OUTPUT_EMPTY);
    assert_eq!(results[4], *OUTPUT_0_200);
    // empty input: 1 block → index 5
    assert_eq!(results[5], *OUTPUT_EMPTY);
    // single-byte input: 1 block → index 6
    assert_eq!(results[6], *OUTPUT_0);
    // 56-byte input: 2 blocks → indices 7..8 (1 dummy + 1 real)
    assert_eq!(results[7], *OUTPUT_EMPTY);
    assert_eq!(results[8], *OUTPUT_0_56);
    // Padding: indices 9..14
    for i in 9..15 {
        assert_eq!(results[i], *OUTPUT_EMPTY);
    }
}

#[test]
#[should_panic]
fn test_multi_input_to_circuit_outputs_exceed_capacity() {
    let _ = multi_inputs_to_circuit_outputs::<Fr>(
        &[
            (0u8..55).collect_vec(),
            (0u8..200).collect_vec(),
            vec![],
            vec![0],
            (0u8..56).collect_vec(),
        ],
        2,
    );
}
