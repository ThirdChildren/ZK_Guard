// Fixture for rule: ZK-HASH-001
//
// Same two commitment functions as the vulnerable fixture, but each now
// prefixes its hash inputs with a distinct, named domain constant
// (`LEAF_DOMAIN` / `NULLIFIER_DOMAIN`). Even if `secret`/`leaf_index` are
// reused between the two functions, the differing domain tag guarantees
// the two hash outputs can never collide.
//
// Expected scanner result: ZK-HASH-001 does not fire.
global LEAF_DOMAIN: Field = 0x4c454146;
global NULLIFIER_DOMAIN: Field = 0x4e554c4c;

fn leaf_commitment(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_3([LEAF_DOMAIN, secret, leaf_index])
}

fn nullifier_hash(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_3([NULLIFIER_DOMAIN, secret, leaf_index])
}

fn main(secret: Field, leaf_index: Field) -> pub Field {
    leaf_commitment(secret, leaf_index)
}
