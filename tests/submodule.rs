#![allow(non_snake_case)]

use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;

pub mod cred {
    use super::*;

    CMZ! { Basic<RistrettoPoint>: x, y, z }
}

pub mod submod {
    use super::cred::Basic;
    use super::*;

    CMZ14Protocol! { issue_proto,
        ,
        N: Basic { x: J, y: H, z: I },
    }

    CMZ14Protocol! { basic_proto,
        A: Basic { x: H, y: R, z: I },
        N: Basic { x: J, y: H, z: I },
    }

    #[test]
    fn test_submodule() -> Result<(), CMZError> {
        let mut rng = rand::thread_rng();
        cmz_group_init(RistrettoPoint::hash_from_bytes::<Sha512>(
            b"CMZ Generator A",
        ));

        let (privkey, pubkey) = Basic::cmz14_gen_keys(&mut rng);

        let mut basic_iss = Basic::using_pubkey(&pubkey);

        basic_iss.x = Some(Scalar::ZERO);
        basic_iss.y = Some(Scalar::ONE);
        basic_iss.z = Some(Scalar::ONE);
        let (ireq, istate) = issue_proto::prepare(&mut rng, b"issue_proto", basic_iss).unwrap();

        let (ireply, _) = issue_proto::handle(
            &mut rng,
            b"issue_proto",
            ireq,
            |N: &mut Basic| {
                N.set_privkey(&privkey);
                N.z = Some(Scalar::ONE);
                Ok(())
            },
            |_N: &Basic| Ok(()),
        )?;
        let basic_cred = match istate.finalize(ireply) {
            Ok(c) => c,
            Err((err, _)) => return Err(err),
        };

        let mut basic_new = Basic::using_pubkey(&pubkey);
        basic_new.y = Some(2u128.into());
        basic_new.z = Some(3u128.into());

        let (req, state) =
            basic_proto::prepare(&mut rng, b"basic_proto", &basic_cred, basic_new).unwrap();

        let (reply, _) = basic_proto::handle(
            &mut rng,
            b"basic_proto",
            req,
            |A: &mut Basic, N: &mut Basic| {
                A.set_privkey(&privkey);
                A.z = Some(Scalar::ONE);
                N.set_privkey(&privkey);
                N.z = Some(3u128.into());
                Ok(())
            },
            |_A: &Basic, _N: &Basic| Ok(()),
        )?;
        let res = state.finalize(reply);
        match res {
            Ok(_) => Ok(()),
            Err((err, _state)) => Err(err),
        }
    }
}
