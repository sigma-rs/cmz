use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;

CMZ! { Basic<RistrettoPoint> :
    attr1,
    attr2
}

CMZ14Protocol! { basic_proto,
A: Basic {
    attr1: H,
    attr2: H,
}, , }

#[test]
fn test_basic() {
    let mut rng = rand::thread_rng();
    cmz_group_init(RistrettoPoint::hash_from_bytes::<Sha512>(
        b"CMZ Generator A",
    ));

    let (privkey, pubkey) = Basic::cmz14_gen_keys(&mut rng);

    // Serialize and deserialize
    let privkey_bytes = bincode::serialize(&privkey).unwrap();
    let pubkey_bytes = bincode::serialize(&pubkey).unwrap();

    let privkey_serde = bincode::deserialize::<CMZPrivkey<RistrettoPoint>>(&privkey_bytes).unwrap();
    let pubkey_serde = bincode::deserialize::<CMZPubkey<RistrettoPoint>>(&pubkey_bytes).unwrap();

    assert!(privkey == privkey_serde);
    assert!(pubkey == pubkey_serde);

    let mut basic_cred = Basic::using_privkey(&privkey_serde);

    let basic_cred_bytes = bincode::serialize(&basic_cred).unwrap();

    println!("{:#?}", basic_cred);

    println!("{:#?}", basic_cred_bytes);

    basic_cred.attr1 = Some(Scalar::ZERO);
    basic_cred.attr2 = Some(Scalar::ONE);

    let (req, state) = basic_proto::prepare(&mut rng, b"test_basic", &basic_cred).unwrap();
    println!("{req:#?}");
    println!("{state:#?}");
}
