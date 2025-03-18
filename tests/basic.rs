use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use group::Group;
use rand_core::RngCore;
use sha2::Sha512;

CMZ! { Basic<RistrettoPoint> :
    attr1,
    attr2
}

#[test]
fn test_basic() {
    let mut rng = rand::thread_rng();
    cmz_group_init(RistrettoPoint::hash_from_bytes::<Sha512>(
        b"CMZ Generator A",
    ));
    let mut basic_cred = Basic::default();

    println!("{:#?}", basic_cred);

    let (privkey, pubkey) = Basic::gen_keys(&mut rng);
    basic_cred.set_privkey(&privkey);

    println!("{:#?}", basic_cred);
}
