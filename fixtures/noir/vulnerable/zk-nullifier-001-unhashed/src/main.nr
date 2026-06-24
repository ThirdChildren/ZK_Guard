// Fixture for rule: ZK-NULLIFIER-001 (unhashed-reuse variant)
//
// `nullifier` is bound directly to the raw `secret` input with no hashing
// or domain separation at all. Per the taxonomy, reusing an unhashed input
// directly as a nullifier is a stronger structural signal than a missing
// tag on an otherwise-hashed value: there is no protocol-specific binding
// distinguishing this "nullifier" from the bare secret it was derived from
// in a single step.
//
// Expected scanner result: ZK-NULLIFIER-001 fires once, unconditionally
// (the value is not the output of a hash at all).
fn main(secret: Field) -> pub Field {
    let nullifier = secret;
    nullifier
}
