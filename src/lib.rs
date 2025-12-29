// We really want points to be capital letters and scalars to be
// lowercase letters
#![allow(non_snake_case)]
#![doc = include_str!("../README.md")]

pub use cmz_derive::*;
use core::any::Any;
use ff::{Field, PrimeField};
use generic_static::StaticTypeMap;
use group::prime::PrimeGroup;
use group::{Group, GroupEncoding, WnafBase, WnafScalar};
use lazy_static::lazy_static;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use serde_with::serde_as;
use serde_with::{DeserializeAs, SerializeAs};
use sigma_compiler::*;
pub use sigma_compiler::{self};
use thiserror::Error;

// We need wrappers for group::Group and ff::PrimeField elements to be
// handled by serde
//
// Pattern from https://docs.rs/serde_with/3.12.0/serde_with/guide/serde_as/index.html

mod group_serde;

/// A wrapper for serializing and deserializing a `Scalar`
pub struct SerdeScalar;

impl<F: PrimeField> SerializeAs<F> for SerdeScalar {
    fn serialize_as<S>(value: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        group_serde::serialize_scalar(value, serializer)
    }
}

impl<'de, F: PrimeField> DeserializeAs<'de, F> for SerdeScalar {
    fn deserialize_as<D>(deserializer: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>,
    {
        group_serde::deserialize_scalar(deserializer)
    }
}

/// A wrapper for serializing and deserializing a `Point` (a group
/// element)
pub struct SerdePoint;

impl<G: Group + GroupEncoding> SerializeAs<G> for SerdePoint {
    fn serialize_as<S>(value: &G, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        group_serde::serialize_point(value, serializer)
    }
}

impl<'de, G: Group + GroupEncoding> DeserializeAs<'de, G> for SerdePoint {
    fn deserialize_as<D>(deserializer: D) -> Result<G, D::Error>
    where
        D: Deserializer<'de>,
    {
        group_serde::deserialize_point(deserializer)
    }
}

/// The CMZMac struct represents a MAC on a CMZ credential.
#[serde_as]
#[derive(Copy, Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CMZMac<G: PrimeGroup> {
    #[serde_as(as = "SerdePoint")]
    pub P: G,
    #[serde_as(as = "SerdePoint")]
    pub Q: G,
}

/// The CMZPrivkey struct represents a CMZ private key
#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CMZPrivkey<G: PrimeGroup> {
    // Is this key for µCMZ or classic CMZ14?
    pub muCMZ: bool,
    #[serde_as(as = "SerdeScalar")]
    pub x0: <G as Group>::Scalar,
    // The next field is xr for µCMZ, and serves the role of x0tilde for
    // CMZ14
    #[serde_as(as = "SerdeScalar")]
    pub xr: <G as Group>::Scalar,
    // The elements of x correspond to the attributes of the credential
    #[serde_as(as = "Vec<SerdeScalar>")]
    pub x: Vec<<G as Group>::Scalar>,
}

/// The CMZPubkey struct represents a CMZ public key
#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CMZPubkey<G: PrimeGroup> {
    #[serde_as(as = "Option<SerdePoint>")]
    pub X0: Option<G>,
    // Xr is only used for µCMZ, not CMZ14 (where it will be None)
    #[serde_as(as = "Option<SerdePoint>")]
    pub Xr: Option<G>,
    // The elements of X correspond to the attributes of the credential
    #[serde_as(as = "Vec<SerdePoint>")]
    pub X: Vec<G>,
}

// The size of the WNAF windows.  Larger sizes take more memory, but
// result in faster multiplications.
const WNAF_SIZE: usize = 6;

/// A struct (generic over G) holding the two CMZ bases, and their Wnaf
/// basepoint tables
#[derive(Clone)]
pub struct CMZBasepoints<G: Group> {
    A_: G,
    B_: G,
    A_TABLE: WnafBase<G, WNAF_SIZE>,
    B_TABLE: WnafBase<G, WNAF_SIZE>,
}

impl<G: Group> CMZBasepoints<G> {
    pub fn init(generator_A: G) -> Self {
        let A_ = generator_A;
        let B_ = G::generator();
        let A_TABLE = WnafBase::new(A_);
        let B_TABLE = WnafBase::new(B_);
        CMZBasepoints {
            A_,
            B_,
            A_TABLE,
            B_TABLE,
        }
    }

    pub fn mulA(&self, s: &G::Scalar) -> G {
        let wnaf_s = WnafScalar::<G::Scalar, WNAF_SIZE>::new(s);
        &self.A_TABLE * &wnaf_s
    }

    pub fn mulB(&self, s: &G::Scalar) -> G {
        let wnaf_s = WnafScalar::<G::Scalar, WNAF_SIZE>::new(s);
        &self.B_TABLE * &wnaf_s
    }

    pub fn keypairA(&self, rng: &mut impl RngCore) -> (G::Scalar, G) {
        let x = G::Scalar::random(&mut *rng);
        (x, self.mulA(&x))
    }

    pub fn keypairB(&self, rng: &mut impl RngCore) -> (G::Scalar, G) {
        let x = G::Scalar::random(&mut *rng);
        (x, self.mulB(&x))
    }
    pub fn A(&self) -> G {
        self.A_
    }
    pub fn B(&self) -> G {
        self.B_
    }
}

// What's going on here needs some explanation.  For each group G, we
// want to pre-compute the WnafBase tables in a [`CMZBasepoints`] struct,
// and we want that pre-computed struct to remain globally accessible.
// So ideally, we'd just have a generic static CMZBasepoints<G> struct,
// and instantiate it once for each G that we use.
//
// The tricky bit is that we don't know what group(s) G the programmer
// (the person using this cmz crate) will end up using, and Rust doesn't
// support generic statics.
//
// So what we'd like is a non-generic static _map_ that maps a group
// type G to the precomputed CMZBasepoints<G> struct.  But types aren't
// values that can be mapped by a normal HashMap.  Luckily, there's a
// generic_static crate that provides a StaticTypeMap that has the
// ability to map types to objects.
//
// However, all of those *mapped-to* objects have to all be of the same
// type, whereas we want the type G to map to a struct of type
// CMZBasepoints<G>, which is different for each value of G.
//
// So we make a non-generic trait CMZbp that all instantiations of
// CMZBasepoints<G> implement (for all group types G), and have the
// StaticTypeMap map each type G to a trait object Box<dyn CMZbp>.
//
// Then to read the CMZBasepoints<G> back out, we look up the trait
// object in the StaticTypeMap, yielding a Box<dyn CMZbp>.  We now need
// to downcast this trait object to the concrete type CMZBasepoints<G>,
// for a _specific_ G.  Rust provides downcasting, but only from &dyn Any
// to the original concrete type, not from other things like &dyn CMZbp.
// So first we need to upcast the trait object to &dyn Any, which we do
// with an "as_any()" function in the CMZbp trait, and then downcast the
// result to a CMZBasepoints<G> struct.
//
// The up/down casting pattern is from
// https://stackoverflow.com/questions/33687447/how-to-get-a-reference-to-a-concrete-type-from-a-trait-object

// Static objects have to be Sync + Send, so enforce that as part of the
// CMXBP trait
trait CMZbp: Sync + Send {
    fn as_any(&self) -> &dyn Any;
}

impl<G: Group> CMZbp for CMZBasepoints<G> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The StaticTypeMap mapping group types G to trait objects Box<dyn CMZbp>
lazy_static! {
    static ref basepoints_map: StaticTypeMap<Box<dyn CMZbp>> = StaticTypeMap::new();
}

/// For a given group type `G`, if `bp` is `Some(b)`, then load the
/// mapping from `G` to `b` into the `basepoints_map`.  (If a mapping
/// from `G` already exists, the old one will be kept and the new one
/// ignored.)  Whether `bp` is `Some(b)` or `None`, this function
/// returns the (possibly new) target of the `basepoints_map`, as a
/// `&'static CMZBasepoints<G>`.
fn load_bp<G: Group>(bp: Option<CMZBasepoints<G>>) -> &'static CMZBasepoints<G> {
    match bp {
        Some(b) => basepoints_map.call_once::<Box<dyn CMZbp>, _>(|| Box::new(b.clone())),
        None => {
            basepoints_map.call_once::<Box<dyn CMZbp>, _>(|| panic!("basepoints uninitialized"))
        }
    }
    .as_any()
    .downcast_ref::<CMZBasepoints<G>>()
    .unwrap()
}

/// Initialize the required second generator for a `PrimeGroup`.
///
/// CMZ credentials require two generators, `A` and `B`.  `B` is the
/// "standard" generator.  A can be any other generator (that is, any
/// other non-identity point in a prime-order group), but it is required
/// that no one know the discrete log between `A` and `B`.  So you can't
/// generate `A` by multiplying `B` by some scalar, for example.  If your
/// group has a hash_from_bytes function, then you can use that to generate
/// `A`. For example, if your group is a curve25519 group, you can
///
/// ```
/// use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as B;
/// use curve25519_dalek::ristretto::RistrettoPoint as G;
/// use sha2::Sha512;
/// let A = G::hash_from_bytes::<Sha512>(b"CMZ Generator A");
/// assert_ne!(A, B);
/// ```
///
/// Otherwise, you're possibly on your own to generate an appropriate
/// generator `A`.  Everyone who uses a given credential type with a
/// given group will need to use the same `A`.  You need to call this
/// before doing any operations with a credential.
pub fn cmz_group_init<G: PrimeGroup>(generator_A: G) {
    let bp = CMZBasepoints::<G>::init(generator_A);
    load_bp(Some(bp));
}

/// Get the loaded CMZBasepoints for the given group
pub fn cmz_basepoints<G: PrimeGroup>() -> &'static CMZBasepoints<G> {
    load_bp(None)
}

/// Compute a public key from a private key
pub fn cmz_privkey_to_pubkey<G: PrimeGroup>(privkey: &CMZPrivkey<G>) -> CMZPubkey<G> {
    let bp = load_bp::<G>(None);
    let X0: Option<G> = if privkey.muCMZ {
        Some(bp.mulB(&privkey.x0))
    } else {
        Some(bp.mulA(&privkey.xr) + bp.mulB(&privkey.x0))
    };
    let Xr: Option<G> = if privkey.muCMZ {
        Some(bp.mulA(&privkey.xr))
    } else {
        None
    };
    let X: Vec<G> = privkey.x.iter().map(|x| bp.mulA(x)).collect();
    CMZPubkey { X0, Xr, X }
}

/// The CMZCredential trait implemented by all CMZ credential struct types.
pub trait CMZCredential
where
    Self: Default + Sized,
{
    /// The type of attributes for this credential
    type Scalar: PrimeField;

    /// The type of the coordinates of the MAC for this credential
    type Point: PrimeGroup;

    /// Produce a vector of strings containing the names of the
    /// attributes of this credential.  (The MAC is not included.)
    fn attrs() -> Vec<&'static str>;

    /// The number of attributes in this credential
    fn num_attrs() -> usize;

    /// The attribute number for a given name as a string
    fn attr_num(name: &str) -> usize;

    /// Get a reference to one of the attributes, specified by name as a
    /// string.
    fn attr(&self, name: &str) -> &Option<Self::Scalar>;

    /// Get a mutable reference to one of the attributes, specified by
    /// name as a string.
    fn attr_mut(&mut self, name: &str) -> &mut Option<Self::Scalar>;

    /// Set the public key for this credential.
    fn set_pubkey(&mut self, pubkey: &CMZPubkey<Self::Point>) -> &mut Self;

    /// Get a copy of the public key for this credential.  If the public
    /// key has not yet been set or computed, a pubkey with X0 == None
    /// will be returned.
    fn get_pubkey(&self) -> &CMZPubkey<Self::Point>;

    /// Set the private key for this credential.  The public key will
    /// automatically be computed from the private key.
    fn set_privkey(&mut self, privkey: &CMZPrivkey<Self::Point>) -> &mut Self;

    /// Get a copy of the private key for this credential.  If the
    /// private key has not yet been set, a privkey with an empty x
    /// vector will be returned.
    fn get_privkey(&self) -> &CMZPrivkey<Self::Point>;

    /// Get the element of the privkey x vector associated with the
    /// given field name
    fn privkey_x(&self, name: &str) -> Self::Scalar;

    /// Get the element of the pubkey X vector associated with the given
    /// field name
    fn pubkey_X(&self, name: &str) -> Self::Point;

    /// Generate random private and public keys for this credential
    /// type.  muCMZ should be true if this credential will be issued
    /// with muCMZ protocols (and _not_ classic CMZ14 protocols).
    fn gen_keys(
        rng: &mut impl RngCore,
        muCMZ: bool,
    ) -> (CMZPrivkey<Self::Point>, CMZPubkey<Self::Point>);

    /// Convenience functions for the above
    fn cmz14_gen_keys(rng: &mut impl RngCore) -> (CMZPrivkey<Self::Point>, CMZPubkey<Self::Point>) {
        Self::gen_keys(rng, false)
    }

    fn mucmz_gen_keys(rng: &mut impl RngCore) -> (CMZPrivkey<Self::Point>, CMZPubkey<Self::Point>) {
        Self::gen_keys(rng, true)
    }

    /// Convenience function for creating a new Self, and loading the
    /// given private key (which will also compute the public key).
    fn using_privkey(privkey: &CMZPrivkey<Self::Point>) -> Self {
        let mut slf = Self::default();
        slf.set_privkey(privkey);
        slf
    }

    /// Convenience function for creating a new Self, and loading the
    /// given public key.
    fn using_pubkey(pubkey: &CMZPubkey<Self::Point>) -> Self {
        let mut slf = Self::default();
        slf.set_pubkey(pubkey);
        slf
    }

    /// Create the MAC for this credential, given the private key.
    fn create_MAC(
        &mut self,
        rng: &mut impl RngCore,
        privkey: &CMZPrivkey<Self::Point>,
    ) -> Result<(), ()>;

    /// Compute the coefficient component of the MAC (the Scalar you
    /// would multiply P by to get Q), given the private key.
    fn compute_MAC_coeff(&self, privkey: &CMZPrivkey<Self::Point>) -> Result<Self::Scalar, ()>;

    /// Verify the MAC in this credential, given the private key.  This
    /// is mainly useful for debugging, since the client will not have
    /// the private key and the issuer will typically not have the
    /// complete credential.
    fn verify_MAC(&self, privkey: &CMZPrivkey<Self::Point>) -> Result<(), ()>;

    /// Create a fake MAC for this credential.  This is useful, for
    /// example, when you're doing an OR proof, and in some arms of the
    /// disjunction, the credential does not have to be valid.
    fn fake_MAC(&mut self, rng: &mut impl RngCore);
}

/// The CMZ macro for declaring CMZ credentials.
///
/// Use this macro to declare a CMZ credential struct type.
///
///     use cmz::*;
///     use group::Group;
///     use rand::{CryptoRng, RngCore};
///     use curve25519_dalek::ristretto::RistrettoPoint as Grp;
///     CMZ!{ Name<Grp>: attr1, attr2, attr3 }
///
/// will declare a struct type called `Name`, containing one field for each
/// of the listed attributes.  The attribute fields will be of type
/// `Option<Scalar>`.  It will also automatically add a field called `MAC`
/// of type [`CMZMac`], and an implementation (via the `CMZCred` derive) of
/// the [`CMZCredential`] trait.  The mathematical group used (the field for
/// the values of the attributes and the private key elements, and the group
/// elements for the commitments, MAC components, and public key elements)
/// is `Grp`.  If `Grp` is omitted, the macro will default to using a
/// group called `G`, which you can define, for example, as:
///
///     use curve25519_dalek::ristretto::RistrettoPoint as G;
///
/// or:
///
///     use curve25519_dalek::ristretto::RistrettoPoint;
///     type G = RistrettoPoint;
///
/// The group must implement the trait [`PrimeGroup`](https://docs.rs/group/latest/group/prime/trait.PrimeGroup.html).
#[macro_export]
macro_rules! CMZ {
    ( $name: ident < $G: ident > : $( $id: ident ),+ ) => {
        #[serde_as]
        #[derive(CMZCred,Clone,Debug,Default,serde::Serialize,serde::Deserialize)]
        #[cmzcred_group(group = $G)]
        pub struct $name {
        $(
            #[serde_as(as="Option<SerdeScalar>")]
            pub $id: Option<<$G as Group>::Scalar>,
        )+
            pub MAC: CMZMac<$G>,
            privkey: CMZPrivkey<$G>,
            pubkey: CMZPubkey<$G>,
        }
    };
    ( $name: ident : $( $id: ident ),+ ) => {
        #[serde_as]
        #[derive(CMZCred,Clone,Debug,Default,serde::Serialize,serde::Deserialize)]
        #[cmzcred_group(group = G)]
        pub struct $name {
        $(
            #[serde_as(as="Option<SerdeScalar>")]
            pub $id: Option<<G as Group>::Scalar>,
        )+
            pub MAC: CMZMac<G>,
            privkey: CMZPrivkey<G>,
            pubkey: CMZPubkey<G>,
        }
    };
}

/// The type for errors generated by the prepare, handle, and finalize
/// functions generated by the CMZProtocol family of macros
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum CMZError {
    #[error("Hide attribute {1} of credential {0} was not passed to prepare")]
    HideAttrMissing(&'static str, &'static str),
    #[error("Reveal attribute {1} of credential {0} was not passed to prepare")]
    RevealAttrMissing(&'static str, &'static str),
    #[error("Implicit attribute {1} of credential {0} was not passed to prepare")]
    ImplicitAttrCliMissing(&'static str, &'static str),
    #[error("Implicit attribute {1} of credential {0} was not set by fill_creds")]
    ImplicitAttrIssMissing(&'static str, &'static str),
    #[error("Set attribute {1} of credential {0} was not set by fill_creds")]
    SetAttrMissing(&'static str, &'static str),
    #[error("private key for credential {0} was not set by fill_creds")]
    PrivkeyMissing(&'static str),
    #[error("public key for credential {0} was not passed to prepare")]
    PubkeyMissing(&'static str),
    #[error("credential initialized with wrong protocol")]
    WrongProtocol(&'static str),
    #[error("client proof did not verify")]
    CliProofFailed,
    #[error("issuer proof did not verify")]
    IssProofFailed,
    #[error("unknown CMZ proof error")]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lox_credential_test() {
        use curve25519_dalek::ristretto::RistrettoPoint as G;

        CMZ! { Lox:
            id,
            bucket,
            trust_level,
            level_since,
            invites_remaining,
            blockages
        }

        println!("{:#?}", Lox::attrs());

        let mut L = Lox::default();

        println!("{:#?}", L);

        L.bucket = Some(<G as Group>::Scalar::ONE);

        println!("{:#?}", L);

        println!("{:#?}", L.attr("bucket"));

        *L.attr_mut("id") = Some(<G as Group>::Scalar::ONE);

        println!("{:#?}", L);
    }
}
