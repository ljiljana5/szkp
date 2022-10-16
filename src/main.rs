use ark_bls12_377::G1Affine as CurvePoint;
use ark_ec::{AffineCurve, ProjectiveCurve}; // Commitment
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand, UniformRand, Zero};
use blake2::{Blake2b512, Digest};

type Scalar = <CurvePoint as AffineCurve>::ScalarField; // Secrets, challenges and blinders

/// Proof structure
#[derive(Default, Debug)]
pub struct Proof {
    /// Commitment to secret value
    v_com: CurvePoint,
    /// Commitment to random value
    r_com: CurvePoint,
    // Proof value
    pi: Scalar,
}

fn prove(secret: Scalar) -> Proof {
    let r = Scalar::rand(&mut rand::rngs::OsRng);
    let r_com = CurvePoint::prime_subgroup_generator().mul(r).into_affine();
    let v_com = CurvePoint::prime_subgroup_generator()
        .mul(secret)
        .into_affine();

    println!("r={}", r);

    let alpha = get_hash(r_com, v_com);

    let pi = secret + alpha * r;
    Proof { v_com, r_com, pi }
}

fn to_bytes(point: CurvePoint) -> Vec<u8> {
    let mut bytes = vec![];
    point.serialize(&mut bytes).expect("Failed to serialize");
    bytes
}

fn from_bytes(bytes: &[u8]) -> Scalar {
    println!("size={}", bytes.len());
    // let bytes = [0u8;32];
    Scalar::deserialize(&bytes[..]).expect("Failed to deserialize")
}

fn get_hash(p: CurvePoint, q: CurvePoint) -> Scalar {
    let mut context = Blake2b512::new();
    context.update(to_bytes(p));
    context.update(to_bytes(q));
    let mut bytes = context.finalize();
    bytes[31] = 0;
    let alpha = from_bytes(&bytes[..32]);
    alpha
}

fn verify(proof: Proof) -> bool {
    let actual: CurvePoint = CurvePoint::prime_subgroup_generator()
        .mul(proof.pi)
        .into_affine();
    let alpha: Scalar = get_hash(proof.r_com, proof.v_com);
    let mult = proof.r_com.mul(alpha).into_affine();
    let expected: CurvePoint = proof.v_com + mult;
    actual == expected
}

fn main() {
    let proof = prove(Scalar::zero());
    println!("Hello, world! {:?}", proof);

    assert!(verify(proof) == true);
}
