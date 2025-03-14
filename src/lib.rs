// We really want points to be capital letters and scalars to be
// lowercase letters
#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint as Point;
use curve25519_dalek::scalar::Scalar;

/// The CMZMac struct represents a MAC on a CMZ credential.
#[derive(Copy, Clone, Debug, Default)]
pub struct CMZMac {
    pub P: Point,
    pub Q: Point,
}

/// The CMZCredential trail implemented by all CMZ credential struct types.
pub trait CMZCredential {
    /// Produce a vector of strings containing the names of the
    /// attributes of this credential.  (The MAC is not included.)
    fn attrs() -> Vec<&'static str>;

    /// The number of attributes in this credential
    fn num_attrs() -> usize;

    /// Get a reference to one of the attributes, specified by name as a
    /// string.
    fn attr(&self, name: &str) -> &Option<Scalar>;

    /// Get a mutable reference to one of the attributes, specified by
    /// name as a string.
    fn attr_mut(&mut self, name: &str) -> &mut Option<Scalar>;
}

/** The CMZ macro for declaring CMZ credentials.

Use this macro to declare a CMZ credential struct type.

`CMZ!{ Name: attr1, attr2, attr3 }`

will declare a struct type called `Name`, containing one field for each
of the listed attributes.  The attribute fields will be of type
`Option<Scalar>`.  It will also automatically add a field called `MAC`
of type `CMZMac`, and an implementation (via the `CMZCred` derive) of
the `CMZCredential` trait.

*/
#[macro_export]
macro_rules! CMZ {
    ( $name: ident : $( $id: ident ),+ ) => {
        #[derive(CMZCred,Copy,Clone,Debug,Default)]
        pub struct $name {
        $(
            pub $id: Option<Scalar>,
        )+
            pub MAC: CMZMac,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmzcred_derive::CMZCred;

    #[test]
    fn lox_credential_test() {
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

        L.bucket = Some(Scalar::ONE);

        println!("{:#?}", L);

        println!("{:#?}", L.attr("bucket"));

        *L.attr_mut("id") = Some(Scalar::ONE);

        println!("{:#?}", L);
    }
}
