//! Port of the det1024 tests in falcon/falcon_test.go.

#[path = "kats/det1024.rs"]
mod kats;

use falcon_det_rs::det1024::*;
use falcon_det_rs::ErrorKind;
use rand::{Rng, RngCore};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rng().fill_bytes(&mut v);
    v
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SHAKE256 of `input`, squeezed to `out_len` bytes.
fn shake256(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut out = vec![0u8; out_len];
    hasher.finalize_xof().read(&mut out);
    out
}

#[test]
fn kats() {
    for (msg_len, want) in kats::KATS.iter().enumerate() {
        let msg = shake256(format!("msg-{msg_len:04}").as_bytes(), msg_len);
        let (_, priv_key) = generate_key(format!("key-{msg_len:04}").as_bytes()).unwrap();
        let sig = priv_key.sign_compressed(&msg).unwrap();
        assert_eq!(to_hex(&sig), *want, "kat {msg_len}");
    }
}

#[test]
fn falcon() {
    let mut rng = rand::rng();
    for _ in 0..64 {
        let seed = random_bytes(64);
        let (pub_key, priv_key) = generate_key(&seed).unwrap();

        let msg = random_bytes(500);
        let sig = priv_key.sign_compressed(&msg).unwrap();
        pub_key.verify(&sig, &msg).unwrap();

        assert_eq!(sig.salt_version(), CURRENT_SALT_VERSION);

        let mut bad_msg = msg.clone();
        bad_msg[rng.random_range(0..msg.len())] ^= 1 << rng.random_range(0..8);
        assert!(pub_key.verify(&sig, &bad_msg).is_err());

        let mut bad_pub = pub_key.clone();
        bad_pub.0[rng.random_range(0..PUBLIC_KEY_SIZE)] ^= 1 << rng.random_range(0..8);
        assert!(bad_pub.verify(&sig, &msg).is_err());

        let sig_ct = sig.convert_to_ct().unwrap();
        pub_key.verify_ct_signature(&sig_ct, &msg).unwrap();

        let h = pub_key.coefficients().unwrap();
        let c = hash_to_point_coefficients(&msg, sig_ct.salt_version());
        let s2 = sig_ct.s2_coefficients().unwrap();
        s1_coefficients(&h, &c, &s2).unwrap();
    }
}

#[test]
fn compressed_signature_sizes() {
    let (pub_key, priv_key) = generate_key(&random_bytes(64)).unwrap();
    let msg = random_bytes(500);
    let sig = priv_key.sign_compressed(&msg).unwrap();

    let mut sig2 = [0u8; SIGNATURE_MAX_SIZE + 1];
    sig2[..sig.len()].copy_from_slice(&sig);
    let err = pub_key.verify(&sig2, &msg).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Verify);
    assert_eq!(err.code(), Some(-4));
}

#[test]
fn sign_empty_message() {
    let (pub_key, priv_key) = generate_key(&random_bytes(64)).unwrap();
    let sig = priv_key.sign_compressed(&[]).unwrap();
    pub_key.verify(&sig, &[]).unwrap();

    let sig_ct = sig.convert_to_ct().unwrap();
    pub_key.verify_ct_signature(&sig_ct, &[]).unwrap();
}

#[test]
fn generate_keys_different_seed() {
    let seed = random_bytes(64);
    let seed2 = random_bytes(64);
    assert_ne!(seed, seed2);

    let (pub1, sk1) = generate_key(&seed).unwrap();
    let (pub2, sk2) = generate_key(&seed2).unwrap();
    assert_ne!(pub1, pub2);
    assert_ne!(sk1, sk2);
}

#[test]
fn generate_key_is_deterministic() {
    let seed = random_bytes(64);
    let (pub1, sk1) = generate_key(&seed).unwrap();
    let (pub2, sk2) = generate_key(&seed).unwrap();
    assert_eq!(pub1, pub2);
    assert_eq!(sk1, sk2);
}

#[test]
fn empty_signature() {
    let (pub_key, _) = generate_key(&random_bytes(64)).unwrap();
    let msg = random_bytes(500);
    let err = pub_key.verify(&[], &msg).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Verify);
    assert_eq!(err.code(), None);
}

#[test]
fn empty_seed() {
    generate_key(&[]).unwrap();
}

#[test]
fn salt_versions() {
    assert_eq!(CTSignature::default().salt_version(), 0);
    assert_eq!(CompressedSignature::default().salt_version(), 0);
    assert_eq!(CompressedSignature(vec![0]).salt_version(), 0);
}

#[test]
fn malformed_signatures() {
    let (pub_key, priv_key) = generate_key(&random_bytes(64)).unwrap();
    let msg = random_bytes(64);
    let sig = priv_key.sign_compressed(&msg).unwrap();

    // A signature shorter than the 2-byte header and salt-version prefix must be rejected.
    for short in [&sig[..0], &sig[..1]] {
        assert!(pub_key.verify(short, &msg).is_err());
        assert!(CompressedSignature::from(short).convert_to_ct().is_err());
    }

    // A valid signature with trailing bytes appended must be rejected.
    let mut trailing = sig.clone();
    trailing.0.push(0);
    assert!(pub_key.verify(&trailing, &msg).is_err());
    assert!(trailing.convert_to_ct().is_err());
}
