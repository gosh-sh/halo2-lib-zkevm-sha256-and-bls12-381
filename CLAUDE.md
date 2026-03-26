# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Fork of [axiom-crypto/halo2-lib](https://github.com/axiom-crypto/halo2-lib) extended with SHA-256 and Keccak hash circuits from the zkEVM project. Published as the `zkevm-hashes` crate.

**Workspace members:** `halo2-base`, `halo2-ecc`, `hashes/zkevm`

## Toolchain

Pinned to **nightly-2023-08-12** via `rust-toolchain`. The codebase uses nightly features (`generic_const_exprs`, `stmt_expr_attributes`, `trait_alias`, `associated_type_defaults`).

## Build & Test Commands

All commands run from the workspace root unless noted otherwise.

```bash
cargo build                                       # build all workspace members
cargo fmt --all -- --check                        # lint check
cargo clippy --all --all-targets -- -D warnings   # clippy
```

### halo2-base tests

```bash
cargo test -p halo2-base -- --nocapture test_gates
cargo test -p halo2-base -- --nocapture test_range
cargo test -p halo2-base                          # all halo2-base tests
```

### halo2-ecc tests

```bash
# MockProver tests (skip benchmarks, they are slow)
cargo test -p halo2-ecc --lib -- --skip bench

# Individual MockProver tests
cargo test -p halo2-ecc -- --nocapture test_fp
cargo test -p halo2-ecc -- --nocapture test_secp256k1_ecdsa
cargo test -p halo2-ecc -- --nocapture test_pairing

# Real prover benchmarks (release mode required)
cargo test -p halo2-ecc --release -- --nocapture bench_secp256k1_ecdsa
cargo test -p halo2-ecc --release -- --nocapture bench_pairing
cargo test -p halo2-ecc --release -- --nocapture bench_msm

# Criterion benchmarks
cargo bench -p halo2-ecc --bench msm
cargo bench -p halo2-ecc --bench fp_mul
```

### zkevm-hashes tests (SHA-256 & Keccak)

```bash
# SHA-256 — MockProver
cargo test -p zkevm-hashes bit_sha256_simple

# SHA-256 — real prover (generates SRS, slow)
cargo test -p zkevm-hashes bit_sha256_prover::k_10

# Keccak — MockProver
cargo test -p zkevm-hashes packed_multi_keccak_simple
cargo test -p zkevm-hashes test_vanilla_keccak_kat_vectors

# Keccak — real prover
cargo test -p zkevm-hashes packed_multi_keccak_prover::k_14
```

### halo2-base benchmarks

```bash
cargo bench -p halo2-base --bench mul
cargo bench -p halo2-base --bench inner_product
```

## CI

Defined in `.github/workflows/ci.yml`:
1. `cargo build`
2. halo2-base: `cargo test` (from `halo2-base/`)
3. halo2-ecc: `cargo test --lib -- --skip bench` (MockProver), then release-mode bench tests with `.t.config` files swapped in
4. zkevm: `packed_multi_keccak_prover::k_14`, `bit_sha256_prover::k_10`, `test_vanilla_keccak_kat_vectors`

For CI benchmarks, `.t.config` files (smaller configs) are renamed over the main `.config` files before running.

## Architecture

### halo2-base

eDSL abstracting over halo2's low-level API. Key types:

- `BaseCircuitBuilder` — top-level circuit builder
- `SinglePhaseCoreManager` / `MultiPhaseCoreManager` — manage witness generation threads
- `CopyConstraintManager` — global virtual cell references
- `LookupAnyManager` — lookup argument handler
- `GateInstructions` / `RangeInstructions` — primary circuit programming traits
- `GateChip` / `RangeChip` — concrete implementations

### halo2-ecc

Elliptic curve cryptography circuits built on halo2-base:

- `bigint` — ZK-optimized big integer arithmetic
- `fields` (fp, fp2, fp12) — prime/extension field operations
- `ecc` — EC add, scalar mul, MSM, ECDSA
- `bn254` — optimal Ate pairing for BN254
- `secp256k1` — secp256k1 specializations

Circuit configurations are read from `.config` files in `configs/` directories. Tests auto-suggest optimal configs when values are too large.

### zkevm-hashes (`hashes/zkevm`)

Two independent hash circuit implementations:

**SHA-256 (`sha256::vanilla`):**
- Custom-gate-only design (no lookup tables), ~130 fixed columns
- Not configurable (unlike Keccak)
- 72 rows per 512-bit input block (4 start + 64 rounds + 4 end)
- `Sha256CircuitConfig` — circuit config and constraint builder
- `witness::generate_witnesses_multi_sha256` — witness generation entry point
- Output in `ShaTable`: `is_enabled`, `length`, `word_value`, `output` (hi-lo 128-bit pair)

**Keccak (`keccak::vanilla`):**
- Lookup-table-based implementation, configurable column count via `rows_per_round`
- `KeccakCircuitConfig` + `KeccakConfigParams { k, rows_per_round }` — configurable circuit
- `witness::multi_keccak` — witness generation entry point
- Output in `KeccakTable`: `is_enabled`, `bytes_left`, `word_value`, `output` (hi-lo 128-bit pair)

**Keccak component (`keccak::component`):**
- Higher-level circuit built on halo2-lib's `BaseCircuitBuilder`
- `KeccakComponentShardCircuit` — standalone Keccak shard circuit with Poseidon-based lookup key encoding
- Designed for scalability: app circuits read Keccak results from component circuits

### Shared utilities (`util/`)

- `constraint_builder` — `BaseConstraintBuilder` for declarative constraint building
- `eth_types` — `Field` trait alias
- `expression` — helper expression combinators (`and`, `not`, `select`, `sum`, `from_bytes`)
- `word` — `Word` type for hi-lo 256-bit representation (two 128-bit limbs)

## Dependency Patching

The workspace `Cargo.toml` patches `halo2-base` and `halo2-ecc` from `axiom-crypto/halo2-lib.git` to local paths at `../halo2-lib/halo2-base` and `../halo2-lib/halo2-ecc`. This means the sibling `halo2-lib` directory must exist for builds.

## Feature Flags

- Default: `halo2-axiom`, `display`, `test-utils` (halo2-base); `jemallocator` (halo2-ecc)
- Exactly one of `halo2-axiom` or `halo2-pse` must be enabled (compile error otherwise)
- `asm` — x86 assembly acceleration for field operations
- `jemallocator` / `mimalloc` — alternate memory allocators
- `display` — print circuit statistics (column counts, etc.)

## Build Notes

- Dev profile uses `opt-level = 3` — debug builds are slow to compile but fast to run
- `RAYON_NUM_THREADS` controls parallelism
- `JEMALLOC_SYS_WITH_MALLOC_CONF` tunes jemalloc behavior
- Trusted setup (`params/` dir) is auto-generated with a known seed if missing — not production-safe
