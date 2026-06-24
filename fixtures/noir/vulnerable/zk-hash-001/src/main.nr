// Fixture for rule: ZK-HASH-001
//
// `leaf_commitment` and `nullifier_hash` both call the same hash function
// shape, `hash_2([x, y])`, with no domain/context tag argument
// distinguishing one commitment purpose from the other. If the same
// `(secret, leaf_index)` pair were ever passed to both functions, the two
// "different" commitments would produce the identical hash output,
// undermining the uniqueness guarantee each commitment is supposed to
// provide.
//
// Expected scanner result: ZK-HASH-001 fires twice (once per call site),
// both at `medium` confidence since each call corroborates the other via
// the matching 2-argument arity.
fn leaf_commitment(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_2([secret, leaf_index])
}

fn nullifier_hash(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_2([secret, leaf_index])
}

fn main(secret: Field, leaf_index: Field) -> pub Field {
    leaf_commitment(secret, leaf_index)
}
