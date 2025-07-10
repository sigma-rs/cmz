// We want Scalars to be lowercase letters, and Points and credentials
// to be capital letters
#![allow(non_snake_case)]

use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;

CMZ! { Wallet: randid, balance }
CMZ! { Item: serialno, price }

// Define two versions of each protocol and test: one for CMZ14 and one for µCMZ

macro_rules! protos_def {
    ($proto_macro:tt, $wallet_issue:ident, $item_issue:ident,
    $wallet_spend:ident, $wallet_spend_with_fee:ident,
    $gen_keys:ident, $test_wallet: ident) => {
        $proto_macro! { $wallet_issue,
          ,
          W: Wallet { randid: J, balance: S },
        }

        $proto_macro! { $item_issue,
          ,
          I: Item { serialno: S, price: S },
        }

        $proto_macro! { $wallet_spend,
          [ W: Wallet { randid: R, balance: H },
            I: Item { serialno: H, price: H } ],
          N: Wallet { randid: J, balance: H },
          (0..=100000000).contains(N.balance),
          W.balance = N.balance + I.price
        }

        $proto_macro! { $wallet_spend_with_fee<fee>,
          [ W: Wallet { randid: R, balance: H },
            I: Item { serialno: H, price: H } ],
          N: Wallet { randid: J, balance: H },
          (0..=100000000).contains(N.balance),
          W.balance = N.balance + I.price + fee
        }

        #[test]
        fn $test_wallet() -> Result<(), CMZError> {
            // The issuer runs this on its own to create an Item credential for a
            // particular item (specified by a serial number) with a given price.
            fn issue_item(
                rng: &mut (impl CryptoRng + RngCore),
                serialno: u128,
                price: u128,
                privkey: &CMZPrivkey<G>,
                public: &CMZPubkey<G>,
            ) -> Result<Item, CMZError> {
                let (request, state) =
                    $item_issue::prepare(&mut *rng, b"issue_item", Item::using_pubkey(public))?;
                let (reply, _) = $item_issue::handle(
                    &mut *rng,
                    b"issue_item",
                    request,
                    |I: &mut Item| {
                        I.set_privkey(privkey);
                        I.serialno = Some(serialno.into());
                        I.price = Some(price.into());
                        Ok(())
                    },
                    |_I: &Item| Ok(()),
                )?;
                let res = state.finalize(reply);
                match res {
                    Ok(c) => Ok(c),
                    Err((err, _state)) => Err(err),
                }
            }

            // The issuer runs this on its own to create an initial wallet loaded
            // with funds, to sent to a client.  The issuer will presumably charge
            // the client out of band for this loaded wallet.
            fn issue_wallet(
                rng: &mut (impl CryptoRng + RngCore),
                balance: u128,
                privkey: &CMZPrivkey<G>,
                public: &CMZPubkey<G>,
            ) -> Result<Wallet, CMZError> {
                let (request, state) = $wallet_issue::prepare(
                    &mut *rng,
                    b"issue_wallet",
                    Wallet::using_pubkey(public),
                )?;
                let (reply, _) = $wallet_issue::handle(
                    &mut *rng,
                    b"issue_wallet",
                    request,
                    |W: &mut Wallet| {
                        W.set_privkey(privkey);
                        W.balance = Some(balance.into());
                        Ok(())
                    },
                    |_W: &Wallet| Ok(()),
                )?;
                let res = state.finalize(reply);
                match res {
                    Ok(c) => Ok(c),
                    Err((err, _state)) => Err(err),
                }
            }

            // Initialization
            let mut rng = rand::thread_rng();
            cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

            // Issuer: generate private and public keys for each type of
            // credential.  (The client gets a copy of the public keys.)
            let (wallet_priv, wallet_pub) = Wallet::$gen_keys(&mut rng);
            let (item_priv, item_pub) = Item::$gen_keys(&mut rng);

            // The issuer makes some Item credentials for various items by just
            // executing the issuing protocol with itself
            let ebook_item = issue_item(&mut rng, 100, 2995, &item_priv, &item_pub)?;
            let album_item = issue_item(&mut rng, 200, 995, &item_priv, &item_pub)?;

            // The verify_MAC function is only usable for debugging, since the
            // client will not have the private key and the issuer will
            // typically not have the complete credential.  But we'll use it
            // here to check that the credentials we get back are correct.
            ebook_item.verify_MAC(&item_priv).unwrap();
            album_item.verify_MAC(&item_priv).unwrap();

            // In exchange for out of band funds, the issuer generates a loaded
            // wallet and sends it to the client.
            let initial_wallet = issue_wallet(&mut rng, 10000, &wallet_priv, &wallet_pub)?;

            initial_wallet.verify_MAC(&wallet_priv).unwrap();

            // Buy an item (no fee version)

            // client actions
            let mut N = Wallet::using_pubkey(&wallet_pub);
            N.balance = Some(initial_wallet.balance.unwrap() - ebook_item.price.unwrap());
            let (request, state) =
                $wallet_spend::prepare(&mut rng, b"test_wallet", &initial_wallet, &ebook_item, N)?;
            let reqbytes = request.as_bytes();

            // issuer actions
            let recvreq = $wallet_spend::Request::try_from(&reqbytes[..]).unwrap();
            let (reply, (_W_issuer, _I_issuer, _N_issuer)) = $wallet_spend::handle(
                &mut rng,
                b"test_wallet",
                recvreq,
                |W: &mut Wallet, I: &mut Item, N: &mut Wallet| {
                    W.set_privkey(&wallet_priv);
                    I.set_privkey(&item_priv);
                    N.set_privkey(&wallet_priv);
                    Ok(())
                },
                // This callback should test that W.randid has never been seen
                // before, but it doesn't currently do that.
                |_W: &Wallet, _I: &Item, _N: &Wallet| Ok(()),
            )?;
            let replybytes = reply.as_bytes();

            // client actions
            let recvreply = $wallet_spend::Reply::try_from(&replybytes[..]).unwrap();
            let W_issued = state.finalize(recvreply).unwrap();

            W_issued.verify_MAC(&wallet_priv).unwrap();

            // The version of the protocol parameterized by a fee.  The client
            // and issue must agree on the params.
            let params = $wallet_spend_with_fee::Params { fee: 5u128.into() };

            // client actions
            let mut N_fee = Wallet::using_pubkey(&wallet_pub);

            N_fee.balance =
                Some(W_issued.balance.unwrap() - album_item.price.unwrap() - params.fee);

            let (request_fee, state_fee) = $wallet_spend_with_fee::prepare(
                &mut rng,
                b"test_wallet_fee",
                &W_issued,
                &album_item,
                N_fee,
                &params,
            )?;
            let reqbytes_fee = request_fee.as_bytes();

            // issuer actions
            let recvreq_fee = $wallet_spend_with_fee::Request::try_from(&reqbytes_fee[..]).unwrap();
            let (reply_fee, (_W_fee_issuer, _I_fee_isser, _N_fee_issuer)) =
                $wallet_spend_with_fee::handle(
                    &mut rng,
                    b"test_wallet_fee",
                    recvreq_fee,
                    |W: &mut Wallet, I: &mut Item, N: &mut Wallet| {
                        W.set_privkey(&wallet_priv);
                        I.set_privkey(&item_priv);
                        N.set_privkey(&wallet_priv);
                        Ok($wallet_spend_with_fee::Params { fee: params.fee })
                    },
                    // This callback should test that W.randid has never been seen
                    // before, but it doesn't currently do that.
                    |_W: &Wallet, _I: &Item, _N: &Wallet| Ok(()),
                )?;
            let replybytes_fee = reply_fee.as_bytes();

            // client actions
            let recvreply_fee =
                $wallet_spend_with_fee::Reply::try_from(&replybytes_fee[..]).unwrap();
            let W_issued_fee = state_fee.finalize(recvreply_fee).unwrap();

            W_issued_fee.verify_MAC(&wallet_priv).unwrap();

            Ok(())
        }
    };
}

protos_def! {CMZ14Protocol, cmz14_wallet_issue, cmz14_item_issue, cmz14_wallet_spend,
cmz14_wallet_spend_with_fee, cmz14_gen_keys, test_cmz14_wallet}

protos_def! {muCMZProtocol, mu_wallet_issue, mu_item_issue,
mu_wallet_spend, mu_wallet_spend_with_fee, mucmz_gen_keys, test_mucmz_wallet}
