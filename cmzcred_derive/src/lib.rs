/*! The implementation of the CMZCred derive.

This derive should not be explicitly used by a programmer using a CMZ
credential.  Instead, a CMZ credential should be declared with the

`CMZ!{ Name: attr1, attr2, attr3 }`

macro.  That macro will internally expand to a struct annotated with
this CMZCred derive.  This derive will output the implementation of
the CMZCredential trait for the declared credential.

*/

use darling::FromDeriveInput;
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DataStruct, DeriveInput, Fields, FieldsNamed, Ident, Visibility};

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
            if id_str != String::from("MAC") {
                attrs.push(id_str);
                idents.push(ident);
            }
        }
    }
    let num_attrs = attrs.len();
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

            fn get_pubkey(&self) -> CMZPubkey<Self::Point> {
                self.pubkey.clone()
            }

            fn set_privkey(&mut self, privkey: &CMZPrivkey<Self::Point>)
            -> &mut Self {
                self.pubkey = cmz_privkey_to_pubkey(&privkey);
                self.privkey = privkey.clone();
                self
            }

            fn get_privkey(&self) -> CMZPrivkey<Self::Point> {
                self.privkey.clone()
            }

            fn gen_keys(rng: &mut impl RngCore) ->
                    (CMZPrivkey<Self::Point>, CMZPubkey<Self::Point>) {
                // Generate (num_attrs + 2) random scalars as the
                // private key
                let x0tilde: Self::Scalar =
                    <Self::Scalar as ff::Field>::random(&mut *rng);
                let x0: Self::Scalar =
                    <Self::Scalar as ff::Field>::random(&mut *rng);
                let x: Vec<Self::Scalar> = (0..Self::num_attrs())
                    .map(|_| <Self::Scalar as ff::Field>::random(&mut *rng))
                    .collect();
                let privkey = CMZPrivkey { x0tilde, x0, x };

                // Convert the private key to a public key
                let pubkey = cmz_privkey_to_pubkey(&privkey);

                (privkey, pubkey)
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
