//! serde adaptors for Group + GroupEncoding and for PrimeField
//!
//! Adapted from [elliptic_curve_tools](https://crates.io/crates/elliptic-curve-tool)
//! v0.1.2 by Michael Lodder.
//! Lodder's original can be adapted under the terms of the MIT license:
//!
//! [No explicit copyright line was present in that package's
//! LICENSE-MIT file.]
//!
//! Permission is hereby granted, free of charge, to any
//! person obtaining a copy of this software and associated
//! documentation files (the "Software"), to deal in the
//! Software without restriction, including without
//! limitation the rights to use, copy, modify, merge,
//! publish, distribute, sublicense, and/or sell copies of
//! the Software, and to permit persons to whom the Software
//! is furnished to do so, subject to the following
//! conditions:
//!
//! The above copyright notice and this permission notice
//! shall be included in all copies or substantial portions
//! of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//! ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//! TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//! PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//! SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//! CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//! IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! DEALINGS IN THE SOFTWARE.

use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
use ff::PrimeField;
use group::{Group, GroupEncoding};
use serde::{
    self,
    de::{Error as DError, Visitor},
    Deserializer, Serializer,
};

/// Serialize a group element.
pub fn serialize_point<G, S>(g: &G, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    G: Group + GroupEncoding,
{
    serialize_(g.to_bytes(), s)
}

/// Deserialize a group element.
pub fn deserialize_point<'de, G, D>(d: D) -> Result<G, D::Error>
where
    D: Deserializer<'de>,
    G: Group + GroupEncoding,
{
    let bytes = deserialize_(d)?;
    Option::from(G::from_bytes(&bytes)).ok_or(DError::custom("invalid group element"))
}

/// Serialize a prime field element.
pub fn serialize_scalar<F, S>(f: &F, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    F: PrimeField,
{
    serialize_(f.to_repr(), s)
}

/// Deserialize a prime field element.
pub fn deserialize_scalar<'de, F, D>(d: D) -> Result<F, D::Error>
where
    D: Deserializer<'de>,
    F: PrimeField,
{
    let repr = deserialize_(d)?;
    Option::from(F::from_repr(repr)).ok_or(DError::custom("invalid prime field element"))
}

fn serialize_<B, S>(bytes: B, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: AsRef<[u8]> + AsMut<[u8]> + Default,
{
    if s.is_human_readable() {
        s.serialize_str(&hex::encode(bytes.as_ref()))
    } else {
        s.serialize_bytes(bytes.as_ref())
    }
}

fn deserialize_<'de, B: AsRef<[u8]> + AsMut<[u8]> + Default, D: Deserializer<'de>>(
    d: D,
) -> Result<B, D::Error> {
    if d.is_human_readable() {
        struct StrVisitor<B: AsRef<[u8]> + AsMut<[u8]> + Default>(PhantomData<B>);

        impl<'de, B> Visitor<'de> for StrVisitor<B>
        where
            B: AsRef<[u8]> + AsMut<[u8]> + Default,
        {
            type Value = B;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a {} length hex string", B::default().as_ref().len() * 2)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DError,
            {
                let mut repr = B::default();
                let length = repr.as_ref().len();
                if v.len() != length * 2 {
                    return Err(DError::custom("invalid length"));
                }
                hex::decode_to_slice(v, repr.as_mut())
                    .map_err(|_| DError::custom("invalid input"))?;
                Ok(repr)
            }
        }
        d.deserialize_str(StrVisitor(PhantomData))
    } else {
        struct ByteVisitor<B: AsRef<[u8]> + AsMut<[u8]> + Default>(PhantomData<B>);

        impl<'de, B> Visitor<'de> for ByteVisitor<B>
        where
            B: AsRef<[u8]> + AsMut<[u8]> + Default,
        {
            type Value = B;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a {} byte", B::default().as_ref().len())
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut repr = B::default();
                if v.len() != repr.as_ref().len() {
                    return Err(serde::de::Error::custom("invalid length"));
                }
                repr.as_mut().copy_from_slice(v);
                Ok(repr)
            }
        }

        d.deserialize_bytes(ByteVisitor(PhantomData))
    }
}
