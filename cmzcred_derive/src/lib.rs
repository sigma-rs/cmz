// We want the macros like CMZProto to be camel case
#![allow(non_snake_case)]

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
use std::collections::HashMap;
use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::Punctuated;
use syn::{
    braced, bracketed, parse_macro_input, token, Data, DataStruct, DeriveInput, Expr, Fields,
    FieldsNamed, Ident, Token, Visibility,
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

/** The CMZ Protocol creation macros.

   The format is:

   let proto = CMZProtocol! { proto_name<param1,param2>,
     [ A: Cred {
         attr1: H,
         attr2: R,
       },
       B: Cred2 {
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
*/

// The possible attribute specifications for a credential to be shown
#[derive(Copy, Clone, Debug, PartialEq)]
enum ShowSpec {
    Hide,
    Reveal,
    Implicit,
}

impl Parse for ShowSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        let spec: Ident = input.parse()?;
        match spec.to_string().to_uppercase().as_str() {
            "H" | "HIDE" => Ok(Self::Hide),
            "R" | "REVEAL" => Ok(Self::Reveal),
            "I" | "IMPLICIT" => Ok(Self::Implicit),
            _ => Err(input.error("Unknown attribute spec for shown credential")),
        }
    }
}

// The possible attribute specifications for a credential to be issued
#[derive(Copy, Clone, Debug, PartialEq)]
enum IssueSpec {
    Hide,
    Reveal,
    Implicit,
    Set,
    Joint,
}

impl Parse for IssueSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        let spec: Ident = input.parse()?;
        match spec.to_string().to_uppercase().as_str() {
            "H" | "HIDE" => Ok(Self::Hide),
            "R" | "REVEAL" => Ok(Self::Reveal),
            "I" | "IMPLICIT" => Ok(Self::Implicit),
            "S" | "SET" => Ok(Self::Set),
            "J" | "JOINT" => Ok(Self::Joint),
            _ => Err(input.error("Unknown attribute spec for issued credential")),
        }
    }
}

// An attribute specification like "attr1: Reveal"
#[derive(Clone)]
struct AttrSpec<ShowOrIssue: Parse> {
    attr: Ident,
    spec: ShowOrIssue,
}

impl<ShowOrIssue: Parse> Parse for AttrSpec<ShowOrIssue> {
    fn parse(input: ParseStream) -> Result<Self> {
        let attr: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let spec: ShowOrIssue = input.parse()?;
        Ok(Self { attr, spec })
    }
}

// A specification of a credential, either to be shown or issued
#[derive(Debug)]
struct CredSpec<ShowOrIssue: Parse> {
    id: Ident,
    cred_type: Ident,
    attrs: HashMap<String, ShowOrIssue>,
}

impl<ShowOrIssue: Parse + Copy> Parse for CredSpec<ShowOrIssue> {
    fn parse(input: ParseStream) -> Result<Self> {
        let id: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let cred_type: Ident = input.parse()?;
        let content;
        braced!(content in input);
        let attrspecs: Punctuated<AttrSpec<ShowOrIssue>, Token![,]> =
            content.parse_terminated(AttrSpec::<ShowOrIssue>::parse, Token![,])?;
        let mut attrs: HashMap<String, ShowOrIssue> = HashMap::new();
        for attrspec in attrspecs.iter() {
            attrs.insert(attrspec.attr.to_string(), attrspec.spec);
        }
        Ok(Self {
            id,
            cred_type,
            attrs,
        })
    }
}

// A vector of credential specifications, which could be empty, a single
// credential specification, or a bracketed list of credential
// specifications.  We need a newtype here and not just a Vec so that we
// can implement the Parse trait for it.
struct CredSpecVec<ShowOrIssue: Parse>(Vec<CredSpec<ShowOrIssue>>);

impl<ShowOrIssue: Parse + Copy> Parse for CredSpecVec<ShowOrIssue> {
    fn parse(input: ParseStream) -> Result<Self> {
        let specvec: Vec<CredSpec<ShowOrIssue>> = if input.peek(Token![,]) {
            // The list is empty
            Vec::new()
        } else if input.peek(token::Bracket) {
            let content;
            bracketed!(content in input);
            let specs: Punctuated<CredSpec<ShowOrIssue>, Token![,]> =
                content.parse_terminated(CredSpec::<ShowOrIssue>::parse, Token![,])?;
            specs.into_iter().collect()
        } else {
            let spec: CredSpec<ShowOrIssue> = input.parse()?;
            vec![spec]
        };

        Ok(Self(specvec))
    }
}

// A protocol specification, following the syntax described above.
#[derive(Debug)]
struct ProtoSpec {
    proto_name: Ident,
    params: Vec<Ident>,
    show_creds: Vec<CredSpec<ShowSpec>>,
    issue_creds: Vec<CredSpec<IssueSpec>>,
    statements: Vec<Expr>,
}

impl Parse for ProtoSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut params: Vec<Ident> = Vec::new();
        let proto_name: Ident = input.parse()?;
        // See if there are optional parameters; Rust does not provide a
        // convenient angle-bracket parser like it does parens, square
        // brackets, and braces, so we just roll our own.
        if input.peek(Token![<]) {
            input.parse::<Token![<]>()?;
            loop {
                if input.peek(Token![>]) {
                    break;
                }
                let param: Ident = input.parse()?;
                params.push(param);
                if input.peek(Token![>]) {
                    break;
                }
                input.parse::<Token![,]>()?;
            }
            input.parse::<Token![>]>()?;
        }
        input.parse::<Token![,]>()?;
        let showvec: CredSpecVec<ShowSpec> = input.parse()?;
        input.parse::<Token![,]>()?;
        let issuevec: CredSpecVec<IssueSpec> = input.parse()?;
        input.parse::<Token![,]>()?;
        let statementpunc: Punctuated<Expr, Token![,]> =
            input.parse_terminated(Expr::parse, Token![,])?;
        let statements: Vec<Expr> = statementpunc.into_iter().collect();

        Ok(ProtoSpec {
            proto_name,
            params,
            show_creds: showvec.0,
            issue_creds: issuevec.0,
            statements,
        })
    }
}

// This is where the main work is done.  The six macros in the
// CMZProtocol macro family (below) all call this function, with
// different values for the bools.
fn protocol_macro(
    input: TokenStream,
    use_muCMZ: bool,
    emit_client: bool,
    emit_issuer: bool,
) -> TokenStream {
    let proto_spec: ProtoSpec = parse_macro_input!(input as ProtoSpec);

    let proto_name = &proto_spec.proto_name;

    // Build the ClientState struct
    let client_state = quote! {
        #[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
        pub struct ClientState {
        }

        impl TryFrom<&[u8]> for ClientState {
            type Error = bincode::Error;

            fn try_from(bytes: &[u8]) -> bincode::Result<ClientState> {
                bincode::deserialize::<ClientState>(bytes)
            }
        }

        impl From<&ClientState> for Vec<u8> {
            fn from(req: &ClientState) -> Vec<u8> {
                bincode::serialize(req).unwrap()
            }
        }

        impl ClientState {
            pub fn as_bytes(&self) -> Vec<u8> {
                self.into()
            }
        }
    };

    // Build the Request and Reply structs
    let messages = quote! {
        #[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
        pub struct Request {
        }

        impl TryFrom<&[u8]> for Request {
            type Error = bincode::Error;

            fn try_from(bytes: &[u8]) -> bincode::Result<Request> {
                bincode::deserialize::<Request>(bytes)
            }
        }

        impl From<&Request> for Vec<u8> {
            fn from(req: &Request) -> Vec<u8> {
                bincode::serialize(req).unwrap()
            }
        }

        impl Request {
            pub fn as_bytes(&self) -> Vec<u8> {
                self.into()
            }
        }

        #[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
        pub struct Reply {
        }

        impl TryFrom<&[u8]> for Reply {
            type Error = bincode::Error;

            fn try_from(bytes: &[u8]) -> bincode::Result<Reply> {
                bincode::deserialize::<Reply>(bytes)
            }
        }

        impl From<&Reply> for Vec<u8> {
            fn from(rep: &Reply) -> Vec<u8> {
                bincode::serialize(rep).unwrap()
            }
        }

        impl Reply {
            pub fn as_bytes(&self) -> Vec<u8> {
                self.into()
            }
        }
    };

    // The argument list for the client's prepare function.  There is an
    // immutable reference for each credential to be shown, and an owned
    // value for each credential to be issued.
    let client_show_args = proto_spec.show_creds.iter().map(|c| {
        let id = &c.id;
        let cred_type = &c.cred_type;
        quote! { #id: &#cred_type, }
        });

    let client_issue_args = proto_spec.issue_creds.iter().map(|c| {
        let id = &c.id;
        let cred_type = &c.cred_type;
        quote! { #id: #cred_type, }
        });

    // Build the client's prepare function
    let client_func = quote! {
        pub fn prepare(#(#client_show_args)* #(#client_issue_args)*)
                -> Result<(Request, ClientState),CMZError> {
            Ok((Request{}, ClientState{}))
        }
    };

    // Build the issuer's handle function
    let issuer_func = quote! {
        pub fn handle(request: Request) -> Result<Reply,CMZError> {
            Ok(Reply{})
        }
    };

    let client_side = if emit_client {
        quote! { #client_state #client_func }
    } else {
        quote! {}
    };

    let issuer_side = if emit_issuer {
        issuer_func
    } else {
        quote! {}
    };

    // Output the generated module for this protocol
    quote! {
        pub mod #proto_name {
            use super::*;

            #messages
            #client_side
            #issuer_side
        }
    }
    .into()
}

/** There are six variants of the CMZProtocol macro.  The ones starting
  with "CMZ" create protocol implementations using the original CMZ
  issuing protocol.  The ones starting with "muCMZ" using the more
  efficient µCMZ protocol.  The ones with "Cli" only create the code
  for the client side of the protocol.  The ones with "Iss" only create
  the code for the issuer side of the protocol.  (The ones without
  either create the code for both sides of the protocol.)
*/
#[proc_macro]
pub fn CMZProtocol(input: TokenStream) -> TokenStream {
    protocol_macro(input, false, true, true)
}

#[proc_macro]
pub fn CMZCliProtocol(input: TokenStream) -> TokenStream {
    protocol_macro(input, false, true, false)
}

#[proc_macro]
pub fn CMZIssProtocol(input: TokenStream) -> TokenStream {
    protocol_macro(input, false, false, true)
}

#[proc_macro]
pub fn muCMZProtocol(input: TokenStream) -> TokenStream {
    protocol_macro(input, true, true, true)
}

#[proc_macro]
pub fn muCMZCliProtocol(input: TokenStream) -> TokenStream {
    protocol_macro(input, true, true, false)
}

#[proc_macro]
pub fn muCMZIssProtocol(input: TokenStream) -> TokenStream {
    protocol_macro(input, true, false, true)
}
