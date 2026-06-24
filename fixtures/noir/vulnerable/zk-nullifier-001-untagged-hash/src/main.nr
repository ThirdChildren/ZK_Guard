// Fixture for rule: ZK-NULLIFIER-001 (untagged-hash variant)
//
// `compute_nullifier` hashes `secret` and `leaf_index` together with no
// action/circuit/app-specific domain tag. The same `(secret, leaf_index)`
// pair could double as a valid nullifier in a different circuit or
// deployment that hashes the same two inputs for an unrelated purpose.
//
// Expected scanner result: ZK-NULLIFIER-001 fires once (the value is a
// hash call, but lacks an apparent domain tag).
fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_2([secret, leaf_index])
}

fn main(secret: Field, leaf_index: Field) -> pub Field {
    compute_nullifier(secret, leaf_index)
}
