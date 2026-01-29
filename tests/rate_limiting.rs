#![allow(non_snake_case)]

use chrono::Utc;
use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use std::collections::HashSet;

type G = RistrettoPoint;

CMZ! { Cred: key }
CMZ! { PresNum: pres_num }

muCMZProtocol! { issue_cred,
    ,
    N: Cred { key: J },
}

muCMZProtocol! { pres_cred<max_pres, @Epoch_base, @VRF_output>,
    [ C: Cred { key: H },
      P?: PresNum { pres_num: H } ],
    ,
    Epoch_base = (C.key + P.pres_num)*VRF_output,
    (0..max_pres).contains(P.pres_num),
}

struct RateLimitClient {
    presnum_pubkey: CMZPubkey<G>,
    cred: Cred,
}

impl RateLimitClient {
    pub fn new(rng: &mut (impl CryptoRng + RngCore), cred: &Cred) -> Self {
        let (_, presnum_pubkey) = PresNum::mucmz_gen_keys(rng);
        Self {
            presnum_pubkey,
            cred: cred.clone(),
        }
    }

    pub fn pres(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        epoch: &[u8],
        pres_num: u32,
    ) -> Result<Vec<u8>, CMZError> {
        let mut P = PresNum::using_pubkey(&self.presnum_pubkey);
        P.pres_num = Some(pres_num.into());
        P.fake_MAC(rng);
        let Epoch_base = RistrettoPoint::hash_from_bytes::<Sha512>(epoch);
        let VRF_output = (self.cred.key.unwrap() + P.pres_num.unwrap()).invert() * Epoch_base;
        let params = pres_cred::Params {
            max_pres: 5u32.into(),
            Epoch_base,
            VRF_output,
        };
        let (request, _) = pres_cred::prepare(rng, b"pres_cred", &self.cred, &P, &params)?;
        let mut msg: Vec<u8> = Vec::new();
        msg.extend(VRF_output.to_bytes());
        msg.extend(request.as_bytes());

        Ok(msg)
    }
}

struct RateLimitServer {
    privkey: CMZPrivkey<G>,
    presnum_privkey: CMZPrivkey<G>,
    seen_tags: HashSet<[u8; 32]>,
}

impl RateLimitServer {
    pub fn new(rng: &mut (impl CryptoRng + RngCore), privkey: &CMZPrivkey<G>) -> Self {
        let (presnum_privkey, _) = PresNum::mucmz_gen_keys(rng);
        Self {
            privkey: privkey.clone(),
            presnum_privkey,
            seen_tags: HashSet::new(),
        }
    }

    pub fn check(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        epoch: &[u8],
        msg: &[u8],
    ) -> Result<(), CMZError> {
        let Epoch_base = RistrettoPoint::hash_from_bytes::<Sha512>(epoch);
        // Separate the message into the VRF output and the request
        let VRF_output = G::from_bytes(&msg[..32].try_into().unwrap()).unwrap();

        let request = pres_cred::Request::try_from(&msg[32..]).unwrap();
        let res = pres_cred::handle(
            rng,
            b"pres_cred",
            request,
            |C: &mut Cred, P: &mut PresNum| {
                let params = pres_cred::Params {
                    max_pres: 5u32.into(),
                    Epoch_base,
                    VRF_output,
                };
                C.set_privkey(&self.privkey);
                P.set_privkey(&self.presnum_privkey);
                Ok(params)
            },
            |_C: &Cred, _P: &PresNum| {
                if !self.seen_tags.insert(VRF_output.to_bytes()) {
                    print!("(duplicate tag seen) ");
                    Err(CMZError::CliProofFailed)
                } else {
                    Ok(())
                }
            },
        );
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[test]
fn test_rate_limiting() -> Result<(), CMZError> {
    let mut rng = rand::thread_rng();
    cmz_group_init(RistrettoPoint::hash_from_bytes::<Sha512>(
        b"CMZ Generator A",
    ));

    let (privkey, pubkey) = Cred::mucmz_gen_keys(&mut rng);

    // Issue the credential
    let (request, state) =
        issue_cred::prepare(&mut rng, b"issue_cred", Cred::using_pubkey(&pubkey))?;
    let (reply, _) = issue_cred::handle(
        &mut rng,
        b"issue_cred",
        request,
        |C: &mut Cred| {
            C.set_privkey(&privkey);
            Ok(())
        },
        |_C: &Cred| Ok(()),
    )?;
    let res = state.finalize(reply);
    let cred = match res {
        Ok(c) => c,
        Err((err, _state)) => Err(err)?,
    };

    let mut client = RateLimitClient::new(&mut rng, &cred);
    let mut server = RateLimitServer::new(&mut rng, &privkey);

    let today = Utc::now().date_naive().format("Epoch %Y-%m-%d").to_string();

    let mut run_test = |pres_num: u32, should_succeed: bool| {
        print!("Presenting {pres_num}: ");
        let msg = client.pres(&mut rng, today.as_bytes(), pres_num).unwrap();
        let res = server.check(&mut rng, today.as_bytes(), &msg);
        match res {
            Ok(_) => {
                if should_succeed {
                    println!("success");
                } else {
                    println!("succeeded but should have failed!");
                    res.unwrap_err();
                }
            }
            Err(_) => {
                if should_succeed {
                    println!("fail!");
                    res.unwrap();
                } else {
                    println!("failed as expected");
                }
            }
        }
    };

    run_test(3, true);
    run_test(4, true);
    run_test(2, true);
    // Should fail, because we've presented #3 already
    run_test(3, false);
    // Should fail, because 5 is out of range of (0..5) = {0,1,2,3,4}
    run_test(5, false);
    run_test(0, true);
    run_test(1, true);

    Ok(())
}
