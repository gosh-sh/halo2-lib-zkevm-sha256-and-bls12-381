use std::cell::RefCell;

use crate::{
    sha256::{
        component::{
            encode::{
                get_words_to_witness_multipliers, num_poseidon_absorb_per_sha256_block,
                num_word_per_witness,
            },
            output::{dummy_circuit_output, Sha256CircuitOutput},
            param::*,
        },
        vanilla::{
            columns::Sha256CircuitConfig,
            param::{NUM_WORDS_TO_ABSORB, SHA256_NUM_ROWS},
            util::get_num_sha2_blocks,
            witness::AssignedSha256Block,
        },
    },
    util::eth_types::Field,
};
use getset::{CopyGetters, Getters};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        flex_gate::MultiPhaseThreadBreakPoints,
        GateChip, GateInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    poseidon::hasher::{
        spec::OptimizedPoseidonSpec, PoseidonCompactChunkInput, PoseidonCompactOutput,
        PoseidonHasher,
    },
    safe_types::{SafeBool, SafeTypeChip},
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;

/// SHA-256 Component Shard Circuit
#[derive(Getters)]
pub struct Sha256ComponentShardCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,

    /// Parameters of this circuit. The same parameters always construct the same circuit.
    #[getset(get = "pub")]
    params: Sha256ComponentShardCircuitParams,

    base_circuit_builder: RefCell<BaseCircuitBuilder<F>>,
    hasher: RefCell<PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>>,
    gate_chip: GateChip<F>,
}

/// Parameters of Sha256ComponentShardCircuit.
///
/// Unlike keccak, SHA-256 has no configurable circuit parameters (fixed column structure),
/// so there is no `sha256_circuit_params` field.
#[derive(Default, Clone, CopyGetters)]
pub struct Sha256ComponentShardCircuitParams {
    /// This circuit has 2^k rows.
    #[getset(get_copy = "pub")]
    k: usize,
    // Number of unusable rows withheld by Halo2.
    #[getset(get_copy = "pub")]
    num_unusable_row: usize,
    /// Max SHA-256 blocks this circuit can accept. The circuit can at most process `capacity`
    /// inputs with < RATE bytes, or a single input with `capacity * RATE - 1` bytes.
    #[getset(get_copy = "pub")]
    capacity: usize,
    // If true, publish raw outputs. Otherwise, publish Poseidon commitment of raw outputs.
    #[getset(get_copy = "pub")]
    publish_raw_outputs: bool,

    // Derived parameters of the base circuit.
    pub base_circuit_params: BaseCircuitParams,
}

impl Sha256ComponentShardCircuitParams {
    /// Create a new Sha256ComponentShardCircuitParams.
    pub fn new(
        k: usize,
        num_unusable_row: usize,
        capacity: usize,
        publish_raw_outputs: bool,
    ) -> Self {
        assert!(1 << k > num_unusable_row, "Number of unusable rows must be less than 2^k");
        let max_rows = (1 << k) - num_unusable_row;
        assert!(
            capacity * SHA256_NUM_ROWS <= max_rows,
            "Capacity exceeds available rows: {} * {} = {} > {}",
            capacity,
            SHA256_NUM_ROWS,
            capacity * SHA256_NUM_ROWS,
            max_rows
        );
        let base_circuit_params = BaseCircuitParams {
            k,
            lookup_bits: None,
            num_instance_columns: if publish_raw_outputs {
                OUTPUT_NUM_COL_RAW
            } else {
                OUTPUT_NUM_COL_COMMIT
            },
            ..Default::default()
        };
        Self { k, num_unusable_row, capacity, publish_raw_outputs, base_circuit_params }
    }
}

/// Circuit::Config for SHA-256 Component Shard Circuit.
#[derive(Clone)]
pub struct Sha256ComponentShardConfig<F: Field> {
    pub base_circuit_config: BaseConfig<F>,
    pub sha256_circuit_config: Sha256CircuitConfig<F>,
}

impl<F: Field> Circuit<F> for Sha256ComponentShardCircuit<F> {
    type Config = Sha256ComponentShardConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Sha256ComponentShardCircuitParams;

    fn params(&self) -> Self::Params {
        self.params.clone()
    }

    /// Creates a new instance of the [Sha256ComponentShardCircuit] without witnesses by setting
    /// the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`Sha256ComponentShardCircuitParams`]
    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        params: Self::Params,
    ) -> Self::Config {
        // SHA-256 takes no configurable params — fixed column structure.
        let sha256_circuit_config = Sha256CircuitConfig::new(meta);
        let base_circuit_params = params.base_circuit_params;
        // BaseCircuitBuilder::configure_with_params must be called last to get the correct
        // unusable_rows.
        let base_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_params.clone());
        Self::Config { base_circuit_config, sha256_circuit_config }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("You must use configure_with_params");
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // SHA-256 uses only custom gates — no load_aux_tables needed (unlike keccak).
        let mut sha256_assigned_blocks: Vec<AssignedSha256Block<'_, F>> = Vec::default();
        layouter.assign_region(
            || "sha256 circuit",
            |mut region| {
                sha256_assigned_blocks = config.sha256_circuit_config.multi_sha256(
                    &mut region,
                    self.inputs.clone(),
                    Some(self.params.capacity),
                );
                Ok(())
            },
        )?;

        // Base circuit witness generation.
        let loaded_sha256_blocks = self.load_sha256_assigned_blocks(sha256_assigned_blocks);
        self.generate_base_circuit_witnesses(&loaded_sha256_blocks);

        self.base_circuit_builder.borrow().synthesize(config.base_circuit_config, layouter)?;

        // Reset the circuit to the initial state so synthesize could be called multiple times.
        self.base_circuit_builder.borrow_mut().clear();
        self.hasher.borrow_mut().clear();
        Ok(())
    }
}

/// Witnesses of a SHA-256 block which are necessary to be loaded into halo2-lib.
#[derive(Clone, Copy, Debug, CopyGetters, Getters)]
pub struct LoadedSha256Block<F: Field> {
    /// `length` at the last input row of this block = cumulative bytes processed so far.
    /// Equals the total input length when `is_final = true`. This is used as the length
    /// placeholder in the Poseidon encoding (multiplied by `is_final`).
    #[getset(get_copy = "pub")]
    pub(crate) length: AssignedValue<F>,
    /// Input words (u32, little-endian bytes) of this block.
    #[getset(get = "pub")]
    pub(crate) word_values: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
    /// Whether this is the last block of a logical input.
    #[getset(get_copy = "pub")]
    pub(crate) is_final: SafeBool<F>,
    /// Low 128 bits of the SHA-256 hash output. Meaningful only when `is_final = true`.
    #[getset(get_copy = "pub")]
    pub(crate) hash_lo: AssignedValue<F>,
    /// High 128 bits of the SHA-256 hash output. Meaningful only when `is_final = true`.
    #[getset(get_copy = "pub")]
    pub(crate) hash_hi: AssignedValue<F>,
}

impl<F: Field> LoadedSha256Block<F> {
    pub fn new(
        length: AssignedValue<F>,
        word_values: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
        is_final: SafeBool<F>,
        hash_lo: AssignedValue<F>,
        hash_hi: AssignedValue<F>,
    ) -> Self {
        Self { length, word_values, is_final, hash_lo, hash_hi }
    }
}

impl<F: Field> Sha256ComponentShardCircuit<F> {
    /// Create a new Sha256ComponentShardCircuit.
    pub fn new(
        inputs: Vec<Vec<u8>>,
        params: Sha256ComponentShardCircuitParams,
        witness_gen_only: bool,
    ) -> Self {
        let input_size =
            inputs.iter().map(|input| get_num_sha2_blocks(input.len())).sum::<usize>();
        assert!(input_size < params.capacity, "Input size exceeds capacity");
        let mut base_circuit_builder = BaseCircuitBuilder::new(witness_gen_only);
        base_circuit_builder.set_params(params.base_circuit_params.clone());
        Self {
            inputs,
            params,
            base_circuit_builder: RefCell::new(base_circuit_builder),
            hasher: RefCell::new(create_hasher()),
            gate_chip: GateChip::new(),
        }
    }

    /// Get break points of BaseCircuitBuilder.
    pub fn base_circuit_break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.base_circuit_builder.borrow().break_points()
    }

    /// Set break points of BaseCircuitBuilder.
    pub fn set_base_circuit_break_points(&self, break_points: MultiPhaseThreadBreakPoints) {
        self.base_circuit_builder.borrow_mut().set_break_points(break_points);
    }

    pub fn update_base_circuit_params(&mut self, params: &BaseCircuitParams) {
        self.params.base_circuit_params = params.clone();
        self.base_circuit_builder.borrow_mut().set_params(params.clone());
    }

    /// Simulate witness generation of the base circuit to determine BaseCircuitParams because the
    /// number of columns of the base circuit can only be known after witness generation.
    pub fn calculate_base_circuit_params(
        params: &Sha256ComponentShardCircuitParams,
    ) -> BaseCircuitParams {
        // Create a simulation circuit to calculate base circuit parameters.
        let simulation_circuit = Self::new(vec![], params.clone(), false);
        let loaded_sha256_blocks = simulation_circuit.mock_load_sha256_assigned_blocks();
        simulation_circuit.generate_base_circuit_witnesses(&loaded_sha256_blocks);

        let base_circuit_params = simulation_circuit
            .base_circuit_builder
            .borrow_mut()
            .calculate_params(Some(params.num_unusable_row));
        // prevent drop warnings
        simulation_circuit.base_circuit_builder.borrow_mut().clear();

        base_circuit_params
    }

    /// Mock loading SHA-256 assigned blocks from the SHA-256 circuit. This function doesn't
    /// create any witnesses/constraints.
    fn mock_load_sha256_assigned_blocks(&self) -> Vec<LoadedSha256Block<F>> {
        let base_circuit_builder = self.base_circuit_builder.borrow();
        let mut copy_manager = base_circuit_builder.core().copy_manager.lock().unwrap();
        (0..self.params.capacity)
            .map(|_| LoadedSha256Block {
                length: copy_manager.mock_external_assigned(F::ZERO),
                word_values: core::array::from_fn(|_| {
                    copy_manager.mock_external_assigned(F::ZERO)
                }),
                is_final: SafeTypeChip::unsafe_to_bool(
                    copy_manager.mock_external_assigned(F::ZERO),
                ),
                hash_lo: copy_manager.mock_external_assigned(F::ZERO),
                hash_hi: copy_manager.mock_external_assigned(F::ZERO),
            })
            .collect_vec()
    }

    /// Load needed witnesses into halo2-lib from SHA-256 assigned blocks. This function doesn't
    /// create any witnesses/constraints.
    fn load_sha256_assigned_blocks(
        &self,
        assigned_blocks: Vec<AssignedSha256Block<'_, F>>,
    ) -> Vec<LoadedSha256Block<F>> {
        let base_circuit_builder = self.base_circuit_builder.borrow();
        let mut copy_manager = base_circuit_builder.core().copy_manager.lock().unwrap();
        assigned_blocks
            .into_iter()
            .map(|block| {
                let length =
                    copy_manager.load_external_assigned(block.length().clone());
                let word_values = core::array::from_fn(|i| {
                    copy_manager.load_external_assigned(block.word_values()[i].clone())
                });
                let is_final = SafeTypeChip::unsafe_to_bool(
                    copy_manager.load_external_assigned(block.is_final().clone()),
                );
                let hash_lo =
                    copy_manager.load_external_assigned(block.output().lo().clone());
                let hash_hi =
                    copy_manager.load_external_assigned(block.output().hi().clone());
                LoadedSha256Block { length, word_values, is_final, hash_lo, hash_hi }
            })
            .collect()
    }

    /// Generate witnesses of the base circuit.
    fn generate_base_circuit_witnesses(&self, loaded_sha256_blocks: &[LoadedSha256Block<F>]) {
        let gate = &self.gate_chip;
        let circuit_final_outputs = {
            let mut base_circuit_builder_mut = self.base_circuit_builder.borrow_mut();
            let ctx = base_circuit_builder_mut.main(0);
            let mut hasher = self.hasher.borrow_mut();
            hasher.initialize_consts(ctx, gate);

            let lookup_key_per_block =
                encode_inputs_from_sha256_blocks(ctx, gate, &hasher, loaded_sha256_blocks);
            Self::generate_circuit_final_outputs(
                ctx,
                gate,
                &lookup_key_per_block,
                loaded_sha256_blocks,
            )
        };
        self.publish_outputs(&circuit_final_outputs);
    }

    /// Combine lookup keys and SHA-256 results to generate final outputs of the circuit.
    pub fn generate_circuit_final_outputs(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        lookup_key_per_block: &[PoseidonCompactOutput<F>],
        loaded_sha256_blocks: &[LoadedSha256Block<F>],
    ) -> Vec<Sha256CircuitOutput<AssignedValue<F>>> {
        let Sha256CircuitOutput {
            key: dummy_key_val,
            hash_lo: dummy_sha256_val_lo,
            hash_hi: dummy_sha256_val_hi,
        } = dummy_circuit_output::<F>();

        // Dummy row for blocks with is_final = false. The corresponding logical input is empty.
        let dummy_key_witness = ctx.load_constant(dummy_key_val);
        let dummy_sha256_lo_witness = ctx.load_constant(dummy_sha256_val_lo);
        let dummy_sha256_hi_witness = ctx.load_constant(dummy_sha256_val_hi);

        let mut circuit_final_outputs = Vec::with_capacity(loaded_sha256_blocks.len());
        for (compact_output, loaded_block) in
            lookup_key_per_block.iter().zip_eq(loaded_sha256_blocks)
        {
            let is_final = AssignedValue::from(loaded_block.is_final);
            let key = gate.select(ctx, *compact_output.hash(), dummy_key_witness, is_final);
            let hash_lo =
                gate.select(ctx, loaded_block.hash_lo, dummy_sha256_lo_witness, is_final);
            let hash_hi =
                gate.select(ctx, loaded_block.hash_hi, dummy_sha256_hi_witness, is_final);
            circuit_final_outputs.push(Sha256CircuitOutput { key, hash_lo, hash_hi });
        }
        circuit_final_outputs
    }

    /// Publish outputs of the circuit as public instances.
    fn publish_outputs(&self, outputs: &[Sha256CircuitOutput<AssignedValue<F>>]) {
        // The length of outputs should always equal to params.capacity.
        assert_eq!(outputs.len(), self.params.capacity);
        if !self.params.publish_raw_outputs {
            let gate = &self.gate_chip;
            let mut base_circuit_builder_mut = self.base_circuit_builder.borrow_mut();
            let ctx = base_circuit_builder_mut.main(0);

            let output_commitment = self.hasher.borrow().hash_fix_len_array(
                ctx,
                gate,
                &outputs
                    .iter()
                    .flat_map(|output| [output.key, output.hash_lo, output.hash_hi])
                    .collect_vec(),
            );

            let assigned_instances = &mut base_circuit_builder_mut.assigned_instances;
            // The commitment should be in the first row.
            assert!(assigned_instances[OUTPUT_COL_IDX_COMMIT].is_empty());
            assigned_instances[OUTPUT_COL_IDX_COMMIT].push(output_commitment);
        } else {
            let assigned_instances =
                &mut self.base_circuit_builder.borrow_mut().assigned_instances;

            // Outputs should be at the top of instance columns.
            assert!(assigned_instances[OUTPUT_COL_IDX_KEY].is_empty());
            assert!(assigned_instances[OUTPUT_COL_IDX_HASH_LO].is_empty());
            assert!(assigned_instances[OUTPUT_COL_IDX_HASH_HI].is_empty());
            for output in outputs {
                assigned_instances[OUTPUT_COL_IDX_KEY].push(output.key);
                assigned_instances[OUTPUT_COL_IDX_HASH_LO].push(output.hash_lo);
                assigned_instances[OUTPUT_COL_IDX_HASH_HI].push(output.hash_hi);
            }
        }
    }
}

pub(crate) fn create_hasher<F: Field>() -> PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE> {
    let spec = OptimizedPoseidonSpec::<F, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_R_F,
        POSEIDON_R_P,
        POSEIDON_SECURE_MDS,
    >();
    PoseidonHasher::<F, POSEIDON_T, POSEIDON_RATE>::new(spec)
}

/// Encode raw inputs from SHA-256 circuit witnesses into lookup keys.
///
/// Each element in the return value corresponds to a SHA-256 block. If is_final = true, this
/// element is the lookup key of the corresponding logical input.
///
/// Key difference from keccak: the length placeholder is `length * is_final` (non-zero only for
/// the LAST block of each input), whereas keccak uses `bytes_left * last_is_final` (non-zero
/// only for the FIRST block).
pub fn encode_inputs_from_sha256_blocks<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    loaded_sha256_blocks: &[LoadedSha256Block<F>],
) -> Vec<PoseidonCompactOutput<F>> {
    // Circuit parameters
    let num_poseidon_absorb_per_block = num_poseidon_absorb_per_sha256_block::<F>();
    let num_word_per_witness = num_word_per_witness::<F>();
    let num_witness_per_block = POSEIDON_RATE * num_poseidon_absorb_per_block;

    // Constant witnesses
    let zero_const = ctx.load_zero();
    let multipliers_val = get_words_to_witness_multipliers::<F>()
        .into_iter()
        .map(|multiplier| Constant(multiplier))
        .collect_vec();

    let mut compact_chunk_inputs = Vec::with_capacity(loaded_sha256_blocks.len());
    for loaded_block in loaded_sha256_blocks {
        let is_final = loaded_block.is_final;
        let mut poseidon_absorb_data = Vec::with_capacity(num_witness_per_block);

        // Length placeholder: `length * is_final`.
        // For the final block: equals total input length (since length = cumulative bytes processed).
        // For non-final blocks: 0.
        let len_placeholder =
            gate.mul(ctx, loaded_block.length, AssignedValue::from(is_final));

        // First group: [len_placeholder, word_values[0], word_values[1], ...]
        let mut words = Vec::with_capacity(num_word_per_witness);
        words.push(len_placeholder);
        words.extend_from_slice(&loaded_block.word_values);

        // Pack every num_word_per_witness words into a single witness field element.
        for words_chunk in words.chunks(num_word_per_witness) {
            let mut padded = words_chunk.to_vec();
            padded.resize(num_word_per_witness, zero_const);
            let witness = gate.inner_product(ctx, padded, multipliers_val.clone());
            poseidon_absorb_data.push(witness);
        }
        // Pad to make poseidon_absorb_data.len() % POSEIDON_RATE == 0.
        poseidon_absorb_data.resize(num_witness_per_block, zero_const);
        let compact_inputs: Vec<_> = poseidon_absorb_data
            .chunks_exact(POSEIDON_RATE)
            .map(|chunk| chunk.to_vec().try_into().unwrap())
            .collect_vec();
        debug_assert_eq!(compact_inputs.len(), num_poseidon_absorb_per_block);
        compact_chunk_inputs.push(PoseidonCompactChunkInput::new(compact_inputs, is_final));
    }

    initialized_hasher.hash_compact_chunk_inputs(ctx, gate, &compact_chunk_inputs)
}
