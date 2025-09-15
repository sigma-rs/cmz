// We want the macros like CMZ14Protocol to be camel case
#![allow(non_snake_case)]

/*! The implementation of the CMZCred derive and CMZ protocol macros.

This derive should not be explicitly used by a programmer using a CMZ
credential.  Instead, a CMZ credential should be declared with the

`CMZ!{ Name: attr1, attr2, attr3 }`

macro.  That macro will internally expand to a struct annotated with
this CMZCred derive.  This derive will output the implementation of
the CMZCredential trait for the declared credential.

*/

use cmz_core::{cmz_core, ProtoSpec};
use darling::FromDeriveInput;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DataStruct, DeriveInput, Fields, FieldsNamed, Ident, Visibility,
};

fn impl_cmzcred_derive(ast: &syn::DeriveInput, group_ident: &Ident) -> TokenStream {
    // Ensure that CMZCred is derived on a struct and not something else
    // (like an enum)
    let Data::Struct(DataStruct {
        struct_token: _,
        fields:
            Fields::Named(FieldsNamed {
                brace_token: _,
                ref named,
            }),
        semi_token: _,
    }) = ast.data
    else {
        panic!("CMZCred derived on a non-struct");
    };
    // attrs and idents are each vectors of the names of the attributes
    // of the credential (not including the MAC and any non-public
    // fields).  attrs stores the names as Strings, while idents stores
    // them as Idents.
    let mut attrs = Vec::<String>::new();
    let mut idents = Vec::<&Ident>::new();
    for n in named {
        let Some(ref ident) = n.ident else {
            panic!("Missing attribute name in CMZCred");
        };
        let id_str = ident.to_string();
        if let Visibility::Public(_) = n.vis {
            if id_str != *"MAC" {
                attrs.push(id_str);
                idents.push(ident);
            }
        }
    }
    let num_attrs = attrs.len();
    let attr_index = 0..num_attrs;
    let name = &ast.ident;
    let errmsg = format!("Invalid attribute name for {} CMZ credential", name);

    // Output the CMZCredential trait implementation
    let gen = quote! {
        impl CMZCredential for #name {
            type Scalar = <#group_ident as Group>::Scalar;
            type Point = #group_ident;

            fn attrs() -> Vec<&'static str> {
                vec![
                    #( #attrs, )*
                ]
            }

            fn num_attrs() -> usize {
                return #num_attrs;
            }

            fn attr_num(attrname: &str) -> usize {
                match attrname {
                    #( #attrs => #attr_index, )*
                    _ => panic!(#errmsg),
                }
            }

            fn attr(&self, attrname: &str) -> &Option<Self::Scalar> {
                match attrname {
                    #( #attrs => &self.#idents, )*
                    _ => panic!(#errmsg),
                }
            }

            fn attr_mut(&mut self, attrname: &str) -> &mut Option<Self::Scalar> {
                match attrname {
                    #( #attrs => &mut self.#idents, )*
                    _ => panic!(#errmsg),
                }
            }

            fn set_pubkey(&mut self, pubkey: &CMZPubkey<Self::Point>) -> &mut Self {
                self.pubkey = pubkey.clone();
                self
            }

            fn get_pubkey<'a> (&'a self) -> &'a CMZPubkey<Self::Point> {
                &self.pubkey
            }

            fn set_privkey(&mut self, privkey: &CMZPrivkey<Self::Point>) -> &mut Self {
                self.pubkey = cmz_privkey_to_pubkey(&privkey);
                self.privkey = privkey.clone();
                self
            }

            fn get_privkey<'a> (&'a self) -> &'a CMZPrivkey<Self::Point> {
                &self.privkey
            }

            fn privkey_x(&self, name: &str) -> Self::Scalar {
                self.privkey.x[Self::attr_num(name)]
            }

            fn pubkey_X(&self, name: &str) -> Self::Point {
                self.pubkey.X[Self::attr_num(name)]
            }

            fn gen_keys(rng: &mut impl RngCore, muCMZ: bool) ->
                    (CMZPrivkey<Self::Point>, CMZPubkey<Self::Point>) {
                // Generate (num_attrs + 2) random scalars as the
                // private key
                let x0 = <Self::Scalar as ff::Field>::random(&mut *rng);
                let xr = <Self::Scalar as ff::Field>::random(&mut *rng);
                let x: Vec<Self::Scalar> = (0..Self::num_attrs())
                    .map(|_| <Self::Scalar as ff::Field>::random(&mut *rng))
                    .collect();
                let privkey = CMZPrivkey { muCMZ, x0, xr, x };

                // Convert the private key to a public key
                let pubkey = cmz_privkey_to_pubkey(&privkey);

                (privkey, pubkey)
            }

            fn compute_MAC_coeff(&self, privkey: &CMZPrivkey<Self::Point>) -> Result<Self::Scalar, ()> {
                if privkey.x.len() != Self::num_attrs() {
                    return Err(());
                }
                let mut coeff = privkey.x0;
                if privkey.muCMZ {
                    coeff += privkey.xr;
                }
                for field in Self::attrs().iter() {
                    let attr_val = self.attr(field).ok_or(())?;
                    coeff += attr_val * privkey.x[Self::attr_num(field)];
                }
                Ok(coeff)
            }

            fn create_MAC(&mut self, rng: &mut impl RngCore, privkey: &CMZPrivkey<Self::Point>) -> Result<(),()> {
                let coeff = self.compute_MAC_coeff(privkey)?;
                self.MAC.P = <Self::Point as group::Group>::random(&mut *rng);
                self.MAC.Q = coeff * self.MAC.P;
                Ok(())
            }

            fn verify_MAC(&self, privkey: &CMZPrivkey<Self::Point>) ->
                    Result<(),()> {
                let coeff = self.compute_MAC_coeff(privkey)?;
                if !bool::from(self.MAC.P.is_identity()) && coeff * self.MAC.P == self.MAC.Q {
                    Ok(())
                } else {
                    Err(())
                }
            }

            fn fake_MAC(&mut self, rng: &mut impl RngCore) {
                self.MAC.P = <Self::Point as group::Group>::random(&mut *rng);
                self.MAC.Q = <Self::Point as group::Group>::random(&mut *rng);
            }

        }
    };
    gen.into()
}

#[derive(FromDeriveInput)]
#[darling(attributes(cmzcred_group))]
struct GroupIdent {
    group: Ident,
}

/// Internal-use derive macro for CMZ credentials.
///
/// The `CMZ!` macro will expand to a struct tagged with this
/// `CMZCred` derive macro.  This attribute will add the methods that
/// implement the `CMZCredential` trait.  You should never need to
/// manually use this `CMZCred` derive macro.
#[proc_macro_derive(CMZCred, attributes(cmzcred_group))]
pub fn cmzcred_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a syntax tree
    // that we can manipulate
    let ast: DeriveInput = syn::parse(input).unwrap();

    // Get the cmzcred_group(group = G) attribute
    let group_ident = GroupIdent::from_derive_input(&ast)
        .expect("missing group parameter to cmzcred_group attribute");

    // Build the trait implementation
    impl_cmzcred_derive(&ast, &group_ident.group)
}

#[cfg(not(doctest))]
/** The CMZ Protocol creation macros.

   The format is:

   ```
   let proto = muCMZProtocol! { proto_name<param1,param2>,
     [ A: Cred {
         attr1: H,
         attr2: R,
       },
       B?: Cred2 {
         attr3: H,
         attr4: I,
       } ],
     C: Cred3 {
       attr5: J,
       attr6: R,
       attr7: H,
       attr8: I,
       attr9: S,
     },
     A.attr1 == B.attr3 + param1,
     A.attr1 == C.attr7,
   };
   ```

   The parameters are:
   - an identifier for the protocol
   - an optional angle-bracketed list of parameters (identifiers)
   - a list of zero or more specifications for credentials that will be shown
   - a list of zero or more specifications for credentials that will be issued
   - zero or more statements relating the attributes in the credentials

   Each credential specification list can be:
   - empty
   - a single credential specification
   - a square-bracketed list of credential specifications

   Each credential specification is:
   - an identifier for the credential
   - for a shown (not issued) credential, an optional "?".  If present,
     the validity of this credential will _not_ be proved by default,
     and must be explicit (perhaps in only some branches of an "OR"
     statement) in the statements; if absent (the default), the validity
     of the shown credential will always be proven
   - a type for the credential, previously defined with the CMZ! macro
   - a braced list of the attributes of the credential (as defined in
     the CMZ! macro), annotated with the attribute specification

   An attribute specification for a credential to be shown is one of:
   - H (hide)
   - R (reveal)
   - I (implicit)

   An attribute specification for a credential to be issued is one of:
   - H (hide)
   - R (reveal)
   - I (implicit)
   - S (set by issuer)
   - J (joint creation)

  There are six variants of the `CMZProtocol` macro.  The ones starting
  with "CMZ14" create protocol implementations using the original CMZ14
  issuing protocol.  The ones starting with "muCMZ" using the more
  efficient µCMZ protocol.  The ones with "Cli" only create the code
  for the client side of the protocol.  The ones with "Iss" only create
  the code for the issuer side of the protocol.  (The ones without
  either create the code for both sides of the protocol.)
*/
#[proc_macro]
pub fn muCMZProtocol(input: TokenStream) -> TokenStream {
    let proto_spec = parse_macro_input!(input as ProtoSpec);
    cmz_core(&proto_spec, true, true, true).into()
}

/// See [`muCMZProtocol!`]
#[proc_macro]
pub fn muCMZCliProtocol(input: TokenStream) -> TokenStream {
    let proto_spec = parse_macro_input!(input as ProtoSpec);
    cmz_core(&proto_spec, true, true, false).into()
}

/// See [`muCMZProtocol!`]
#[proc_macro]
pub fn muCMZIssProtocol(input: TokenStream) -> TokenStream {
    let proto_spec = parse_macro_input!(input as ProtoSpec);
    cmz_core(&proto_spec, true, false, true).into()
}

/// See [`muCMZProtocol!`]
#[proc_macro]
pub fn CMZ14Protocol(input: TokenStream) -> TokenStream {
    let proto_spec = parse_macro_input!(input as ProtoSpec);
    cmz_core(&proto_spec, false, true, true).into()
}

/// See [`muCMZProtocol!`]
#[proc_macro]
pub fn CMZ14CliProtocol(input: TokenStream) -> TokenStream {
    let proto_spec = parse_macro_input!(input as ProtoSpec);
    cmz_core(&proto_spec, false, true, false).into()
}

/// See [`muCMZProtocol!`]
#[proc_macro]
pub fn CMZ14IssProtocol(input: TokenStream) -> TokenStream {
    let proto_spec = parse_macro_input!(input as ProtoSpec);
    cmz_core(&proto_spec, false, false, true).into()
}
