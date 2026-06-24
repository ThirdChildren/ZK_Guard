// Fixture for rule: ZK-NULLIFIER-001
//
// `compute_nullifier` mixes a fixed, named domain constant
// (`NULLIFIER_DOMAIN`) into the hash alongside `secret` and `leaf_index`,
// so the resulting nullifier cannot collide with a hash of the same two
// inputs computed for a different purpose or in a different circuit.
//
// Expected scanner result: ZK-NULLIFIER-001 does not fire.
global NULLIFIER_DOMAIN: Field = 0x4e554c4c;

fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_3([NULLIFIER_DOMAIN, secret, leaf_index])
}

fn main(secret: Field, leaf_index: Field) -> pub Field {
    compute_nullifier(secret, leaf_index)
}
