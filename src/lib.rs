// We really want points to be capital letters and scalars to be
// lowercase letters
#![allow(non_snake_case)]

use ff::PrimeField;
use group::Group;

/// The CMZMac struct represents a MAC on a CMZ credential.
#[derive(Copy, Clone, Debug, Default)]
pub struct CMZMac<G: Group> {
    pub P: G,
    pub Q: G,
}

/// The CMZCredential trait implemented by all CMZ credential struct types.
pub trait CMZCredential<G: Group> {
    /// The type of attributes for this credential
    type Scalar: PrimeField;

    /// The type of the coordinates of the MAC for this credential
    type Point: Group;

    /// Produce a vector of strings containing the names of the
    /// attributes of this credential.  (The MAC is not included.)
    fn attrs() -> Vec<&'static str>;

    /// The number of attributes in this credential
    fn num_attrs() -> usize;

    /// Get a reference to one of the attributes, specified by name as a
    /// string.
    fn attr(&self, name: &str) -> &Option<Self::Scalar>;

    /// Get a mutable reference to one of the attributes, specified by
    /// name as a string.
    fn attr_mut(&mut self, name: &str) -> &mut Option<Self::Scalar>;
}

/** The CMZ macro for declaring CMZ credentials.

Use this macro to declare a CMZ credential struct type.

`CMZ!{ Name<Group>: attr1, attr2, attr3 }`

will declare a struct type called `Name`, containing one field for each
of the listed attributes.  The attribute fields will be of type
`Option<Scalar>`.  It will also automatically add a field called `MAC`
of type `CMZMac`, and an implementation (via the `CMZCred` derive) of
the `CMZCredential` trait.  The mathematical group used (the field for
the values of the attributes and the group elements for the commitments
and MAC components) is Group (which must satisfy the group::Group
trait).  If "<Group>" is omitted, the macro will default to using a
group called "G", which you can define, for example, as:

use curve25519_dalek::ristretto::RistrettoPoint as G;

or:

use curve25519_dalek::ristretto::RistrettoPoint;
type G = RistrettoPoint;

*/
#[macro_export]
macro_rules! CMZ {
    ( $name: ident < $G: ident > : $( $id: ident ),+ ) => {
        #[derive(CMZCred,Copy,Clone,Debug,Default)]
        #[cmzcred_group(group = $G)]
        pub struct $name {
        $(
            pub $id: Option<<$G as Group>::Scalar>,
        )+
            pub MAC: CMZMac<$G>,
        }
    };
    ( $name: ident : $( $id: ident ),+ ) => {
        #[derive(CMZCred,Copy,Clone,Debug,Default)]
        #[cmzcred_group(group = G)]
        pub struct $name {
        $(
            pub $id: Option<<G as Group>::Scalar>,
        )+
            pub MAC: CMZMac<G>,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmzcred_derive::CMZCred;

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

        let mut L: Lox = Lox::default();

        println!("{:#?}", L);

        L.bucket = Some(<G as Group>::Scalar::ONE);

        println!("{:#?}", L);

        println!("{:#?}", L.attr("bucket"));

        *L.attr_mut("id") = Some(<G as Group>::Scalar::ONE);

        println!("{:#?}", L);
    }
}
