// We want the macros like CMZProtocol to be camel case
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
use proc_macro::{Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
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

            fn gen_keys(rng: &mut impl RngCore, muCMZ: bool) ->
                    (CMZPrivkey<Self::Point>, CMZPubkey<Self::Point>) {
                // Generate (num_attrs + 2) random scalars as the
                // private key
                let x0tilde: Self::Scalar = if muCMZ {
                    <Self::Scalar as ff::Field>::ZERO
                } else {
                    <Self::Scalar as ff::Field>::random(&mut *rng)
                };
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

impl ShowSpec {
    fn abbr(&self) -> &'static str {
        match self {
            Self::Hide => "H",
            Self::Reveal => "R",
            Self::Implicit => "I",
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

impl IssueSpec {
    fn abbr(&self) -> &'static str {
        match self {
            Self::Hide => "H",
            Self::Reveal => "R",
            Self::Implicit => "I",
            Self::Set => "S",
            Self::Joint => "J",
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
    attrs: HashMap<Ident, ShowOrIssue>,
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
        let mut attrs: HashMap<Ident, ShowOrIssue> = HashMap::new();
        for attrspec in attrspecs.iter() {
            attrs.insert(attrspec.attr.clone(), attrspec.spec);
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

// Names and types of fields that might end up in a generated struct
enum StructField {
    Scalar(Ident),
    Point(Ident),
    EncPoint(Ident),
}

// Convenience functions to create StructField items
impl StructField {
    pub fn scalar(s: &str) -> Self {
        Self::Scalar(Ident::new(s, Span::call_site().into()))
    }
    pub fn point(s: &str) -> Self {
        Self::Point(Ident::new(s, Span::call_site().into()))
    }
    pub fn encpoint(s: &str) -> Self {
        Self::EncPoint(Ident::new(s, Span::call_site().into()))
    }
}

// A list of StructField items
#[derive(Default)]
struct StructFieldList {
    fields: Vec<StructField>,
}

impl StructFieldList {
    pub fn push_scalar(&mut self, s: &str) {
        self.fields.push(StructField::scalar(s));
    }
    pub fn push_point(&mut self, s: &str) {
        self.fields.push(StructField::point(s));
    }
    pub fn push_encpoint(&mut self, s: &str) {
        self.fields.push(StructField::encpoint(s));
    }
    /// Output an iterator consisting of the field names
    pub fn field_iter<'a>(&'a self) -> impl Iterator<Item = &'a Ident> {
        self.fields.iter().map(|f| match f {
            StructField::Scalar(id) => id,
            StructField::Point(id) => id,
            StructField::EncPoint(id) => id,
        })
    }
    /// Output a ToTokens of the fields as they would appear in a struct
    /// definition (including the serde_as annotations)
    pub fn field_decls(&self) -> impl ToTokens {
        let decls = self.fields.iter().map(|f| match f {
            StructField::Scalar(id) => quote! {
                #[serde_as(as = "SerdeScalar")]
                pub #id: Scalar,
            },
            StructField::Point(id) => quote! {
                #[serde_as(as = "SerdePoint")]
                pub #id: Point,
            },
            StructField::EncPoint(id) => quote! {
                #[serde_as(as = "(SerdePoint, SerdePoint)")]
                pub #id: (Point, Point),
            },
        });
        quote! { #(#decls)* }
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
    let has_params = proto_spec.params.len() > 0;
    let tot_num_creds = proto_spec.show_creds.len() + proto_spec.issue_creds.len();

    // Use the group of the first named credential type
    let group_types = if proto_spec.show_creds.len() > 0 {
        let first_cred_type = &proto_spec.show_creds[0].cred_type;
        quote! {
            pub type Scalar = <#first_cred_type as CMZCredential>::Scalar;
            pub type Point = <#first_cred_type as CMZCredential>::Point;
        }
    } else if proto_spec.issue_creds.len() > 0 {
        let first_cred_type = &proto_spec.issue_creds[0].cred_type;
        quote! {
            pub type Scalar = <#first_cred_type as CMZCredential>::Scalar;
            pub type Point = <#first_cred_type as CMZCredential>::Point;
        }
    } else {
        quote! {}
    };

    /* Credential issuing

       For each attribute of each credential to be issued, handle it
       according to its IssueSpec:
    */
    // The fields that will end up in the ClientState
    let mut clientstate_fields = StructFieldList::default();

    // The fields that will end up in the Request
    let mut request_fields = StructFieldList::default();

    // The fields that will end up in the Reply
    let mut reply_fields = StructFieldList::default();

    // The code that will end up in prepare
    let mut prepare_code = quote! {};

    // The code that will end up in handle, before the call to
    // fill_creds
    let mut handle_code_pre_fill = quote! {};

    // The code that will end up in handle, after the call to
    // fill_creds but before the call to authorize
    let mut handle_code_post_fill = quote! {};

    // The code that will end up in handle, after the call to
    // authorize
    let mut handle_code_post_auth = quote! {};

    // The code that will end up in finalize
    let mut finalize_code = quote! {};

    // Are there any Hide or Joint attributes in _any_ credential to be
    // issued?
    let mut any_hide_joint = false;
    for iss_cred in proto_spec.issue_creds.iter() {
        // Are there any Hide or Joint attributes in this particular
        // credential to be issued?
        let mut cred_hide_joint = false;
        let iss_cred_id = format_ident!("cred_{}", iss_cred.id);
        for (attr, &spec) in iss_cred.attrs.iter() {
            // String versions of the credential name and the attribute
            // name
            let cred_str = iss_cred.id.to_string();
            let attr_str = attr.to_string();

            // The scoped attribute name
            let scoped_attr = format_ident!("iss_{}attr_{}_{}", spec.abbr(), iss_cred.id, attr);

            if spec == IssueSpec::Hide || spec == IssueSpec::Joint {
                cred_hide_joint = true;
            }

            if !use_muCMZ && (spec == IssueSpec::Hide || spec == IssueSpec::Joint) {
                /* For each Hide and Joint attribute (for CMZ): Compute an
                   exponential El Gamal encryption (of the attribute) E_attr =
                   (r_attr*B, attr*B + r_attr*D) for random r_attr.  Include E_attr
                   in the Request, attr in the ClientState, and attr,
                   r_attr, and E_attr in the CliProof.  Hide attributes
                   will be passed into prepare on the client side; Joint
                   attributes (client contribution) will be generated
                   randomly by prepare on the client side, and (issuer
                   contribution) by handle on the issuer side.
                */
                let enc_attr = format_ident!("E_{}", scoped_attr);
                let r_attr = format_ident!("r_{}", scoped_attr);
                request_fields.push_encpoint(&enc_attr.to_string());
                clientstate_fields.push_scalar(&scoped_attr.to_string());
                if spec == IssueSpec::Hide {
                    prepare_code = quote! {
                        #prepare_code
                        let #scoped_attr =
                        #iss_cred_id.#attr.ok_or(CMZError::HideAttrMissing(#cred_str,
                        #attr_str))?;
                    };
                } else {
                    prepare_code = quote! {
                        #prepare_code
                        let #scoped_attr = <Scalar as ff::Field>::random(&mut *rng);
                    };
                    reply_fields.push_scalar(&scoped_attr.to_string());
                    handle_code_pre_fill = quote! {
                        #handle_code_pre_fill
                        let #scoped_attr = <Scalar as ff::Field>::random(&mut *rng);
                    };
                    finalize_code = quote! {
                        #finalize_code
                        let #scoped_attr = self.#scoped_attr + reply.#scoped_attr;
                        #iss_cred_id.#attr = Some(#scoped_attr);
                    };
                }
                prepare_code = quote! {
                    #prepare_code
                    let #r_attr = <Scalar as ff::Field>::random(&mut *rng);
                    let #enc_attr = (bp.mulB(&#r_attr),
                        bp.mulB(&#scoped_attr) +
                        #r_attr * D);
                };
            }

            /* For all Hide and Joint attributes of a single credential to be
               isued (for CMZ): the issuer chooses a random b, computes
               P = b*B, E_Q = b*x_0*B + \sum_{hide,joint} b*x_attr*E_attr
               + (0,\sum_{implicit,reveal,set,joint} b*x_attr*attr*B)
               (note that E_Q and each E_attr are all pairs of Points; the
               scalar multiplication is componentwise).  Include P, E_Q in
               Reply. For each such attribute, include t_attr = b*x_attr and
               T_attr = b*X_attr = t_attr*A in Reply and IssProof.  The client
               will compute Q = E_Q[1] - d*E_Q[0].
            */

            /* For all Hide and Joint attributes of a single credential to be
               issued (for µCMZ): The client chooses a random s, computes C =
               (\sum_{hide,joint} attr*X_attr) + s*A, where X_attr is the
               public key for that attribute.  Include s in the ClientState, C
               in the Request, and the attributes, s, and C in the CliProof.
               Hide attributes will be passed into prepare on the client side;
               Joint attributes (client contribution) will be generated randomly
               by prepare on the client side.  On the issuer side, handle will
               pick a random b, compute P = b*A, R = b*(x_0*A + C) +
               \sum_{implicit,reveal,set,joint} x_attr*attr*P.  Include P
               and R in Reply, and x_0, b, P, R, C in IssProof.  For each
               implicit,reveal,set,joint attribute, include x_attr and P_attr =
               attr*P in IssProof.  The client will compute Q = R - s*P.
            */

            /* For each Reveal attribute: include attr in Request (client will
               pass the value into prepare)
            */
            if spec == IssueSpec::Reveal {
                request_fields.push_scalar(&scoped_attr.to_string());
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::RevealAttrMissing(#cred_str,
                    #attr_str))?;
                };
                handle_code_pre_fill = quote! {
                    #handle_code_pre_fill
                    let #scoped_attr = request.#scoped_attr;
                }
            }

            /* For each Implicit attribute: does not appear (will be filled in
               by fill_creds on the issuer side and passed into prepare on the
               client side)
            */
            if spec == IssueSpec::Implicit {
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::ImplicitAttrCliMissing(#cred_str,
                    #attr_str))?;
                };
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::ImplicitAttrIssMissing(#cred_str,
                    #attr_str))?;
                }
            }

            /* For each Set attribute: the issuer's value will be set
              by fill_creds.  Include the value in Reply.
            */
            if spec == IssueSpec::Set {
                reply_fields.push_scalar(&scoped_attr.to_string());
                handle_code_post_auth = quote! {
                    #handle_code_post_auth
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::SetAttrMissing(#cred_str,
                    #attr_str))?;
                };
                finalize_code = quote! {
                    #finalize_code
                    let #scoped_attr = reply.#scoped_attr;
                    #iss_cred_id.#attr = Some(#scoped_attr);
                }
            }
        }
        any_hide_joint |= cred_hide_joint;
    }

    /* If there are _any_ Hide or Joint attributes in CMZ (as opposed to
       µCMZ), the client generates an El Gamal keypair (d, D=d*B).
       Include d in the ClientState and D in the Request.
    */
    if any_hide_joint && !use_muCMZ {
        clientstate_fields.push_scalar("d");
        request_fields.push_point("D");
        prepare_code = quote! {
            let (d,D) = bp.keypairB(&mut *rng);
            #prepare_code
        }
    }

    // Build the Params struct, if we have params
    let params_struct = if has_params {
        let param_list = &proto_spec.params;
        quote! {
            pub struct Params {
                #( pub #param_list: Scalar, )*
            }
        }
    } else {
        quote! {}
    };

    // Build the ClientState struct
    let client_state = {
        let decls = clientstate_fields.field_decls();
        quote! {
            #[serde_as]
            #[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
            pub struct ClientState {
                #decls
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
        }
    };

    // Build the Request and Reply structs
    let messages = {
        let reqdecls = request_fields.field_decls();
        let repdecls = reply_fields.field_decls();
        quote! {
            #[serde_as]
            #[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
            pub struct Request {
                #reqdecls
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

            #[serde_as]
            #[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
            pub struct Reply {
                #repdecls
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
        }
    };

    // The argument list for the client's prepare function.  There is an
    // immutable reference for each credential to be shown, and an owned
    // value for each credential to be issued.
    let client_show_args = proto_spec.show_creds.iter().map(|c| {
        let id = format_ident!("cred_{}", c.id);
        let cred_type = &c.cred_type;
        quote! { #id: &#cred_type, }
    });

    let client_issue_args = proto_spec.issue_creds.iter().map(|c| {
        let id = format_ident!("cred_{}", c.id);
        let cred_type = &c.cred_type;
        quote! { #id: #cred_type, }
    });

    let client_params_arg = if has_params {
        quote! { params: &Params, }
    } else {
        quote! {}
    };

    // Build the client's prepare function
    let client_func = {
        let reqf = request_fields.field_iter();
        let csf = clientstate_fields.field_iter();
        quote! {
            pub fn prepare(rng: &mut impl RngCore,
                #(#client_show_args)* #(#client_issue_args)* #client_params_arg)
                    -> Result<(Request, ClientState),CMZError> {
                let bp = cmz_basepoints::<Point>();
                #prepare_code
                Ok((Request{#(#reqf,)*}, ClientState{#(#csf,)*}))
            }
        }
    };

    // Build the issuer's handle function
    let issuer_func = {
        // The credential declarations for the issuer's handle function
        let cred_decls = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let id = format_ident!("cred_{}", c.id);
                let cred_type = &c.cred_type;
                quote! { let mut #id = #cred_type::default(); }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("cred_{}", c.id);
                let cred_type = &c.cred_type;
                quote! { let mut #id = #cred_type::default(); }
            }));

        // The type of the returned credentials from handle
        let cred_rettypes = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let cred_type = &c.cred_type;
                quote! { #cred_type }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let cred_type = &c.cred_type;
                quote! { #cred_type }
            }));

        // The return type
        let rettype = if tot_num_creds > 1 {
            quote! { Result<(Reply, (#(#cred_rettypes),*)),CMZError> }
        } else if tot_num_creds == 1 {
            quote! { Result<(Reply, #(#cred_rettypes)*),CMZError> }
        } else {
            quote! { Result<Reply,CMZError> }
        };

        // The return value
        let cred_retvals = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let id = format_ident!("cred_{}", c.id);
                quote! { #id }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("cred_{}", c.id);
                quote! { #id }
            }));

        // The argument list for the issuer's fill_creds callback
        let fill_creds_args = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let cred_type = &c.cred_type;
                quote! { &mut #cred_type, }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let cred_type = &c.cred_type;
                quote! { &mut #cred_type, }
            }));

        // The parameters for the fill_creds callback
        let fill_creds_params = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let id = format_ident!("cred_{}", c.id);
                quote! { &mut #id, }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("cred_{}", c.id);
                quote! { &mut #id, }
            }));

        // The return value of the callback
        let fill_creds_params_ret = if has_params {
            quote! { Params }
        } else {
            quote! { () }
        };

        // The argument list for the issuer's authorize callback
        let authorize_args = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let cred_type = &c.cred_type;
                quote! { &#cred_type, }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let cred_type = &c.cred_type;
                quote! { &#cred_type, }
            }));

        // The parameters for the authorize callback
        let authorize_params = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let id = format_ident!("cred_{}", c.id);
                quote! { &#id, }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("cred_{}", c.id);
                quote! { &#id, }
            }));

        let repf = reply_fields.field_iter();
        let retval = if tot_num_creds > 1 {
            quote! { Ok((Reply{#(#repf,)*}, (#(#cred_retvals),*))) }
        } else if tot_num_creds == 1 {
            quote! { Ok((Reply{#(#repf,)*}, #(#cred_retvals)*)) }
        } else {
            quote! { Ok(Reply{#(#repf,)*}) }
        };

        quote! {
            pub fn handle<F,A>(rng: &mut impl RngCore,
                request: Request, fill_creds: F, authorize: A)
                -> #rettype
            where
                F: FnOnce(#(#fill_creds_args)*) ->
                    Result<#fill_creds_params_ret, CMZError>,
                A: FnOnce(#(#authorize_args)*) ->
                    Result<(),CMZError>
            {
                #(#cred_decls)*
                #handle_code_pre_fill
                fill_creds(#(#fill_creds_params)*)?;
                #handle_code_post_fill
                authorize(#(#authorize_params)*)?;
                #handle_code_post_auth
                #retval
            }
        }
    };

    // Build the ClientState's finalize function
    let clientstate_finalize_func = {
        // The credential declarations for the client's finalize function
        let cred_decls = proto_spec.issue_creds.iter().map(|c| {
            let id = format_ident!("cred_{}", c.id);
            let cred_type = &c.cred_type;
            quote! { let mut #id = #cred_type::default(); }
        });

        // The type of the returned credentials from finalize
        let cred_rettypes = proto_spec.issue_creds.iter().map(|c| {
            let cred_type = &c.cred_type;
            quote! { #cred_type }
        });

        let rettype = if proto_spec.issue_creds.len() > 1 {
            quote! { Result<(#(#cred_rettypes),*),(CMZError,Self)> }
        } else if proto_spec.issue_creds.len() == 1 {
            quote! { Result<#(#cred_rettypes)*,(CMZError,Self)> }
        } else {
            quote! { Result<(),(CMZError,Self)> }
        };

        // Return value for ClientState's finalize function
        let cred_retvals = proto_spec.issue_creds.iter().map(|c| {
            let id = format_ident!("cred_{}", c.id);
            quote! { #id }
        });

        let retval = if proto_spec.issue_creds.len() > 1 {
            quote! { Ok((#(#cred_retvals),*)) }
        } else if proto_spec.issue_creds.len() == 1 {
            quote! { Ok(#(#cred_retvals)*) }
        } else {
            quote! { Ok(()) }
        };

        quote! {
            impl ClientState {
                pub fn finalize(self, reply: Reply)
                    -> #rettype {
                    #(#cred_decls)*
                    #finalize_code
                    #retval
                }
            }
        }
    };

    let client_side = if emit_client {
        quote! { #client_state #client_func #clientstate_finalize_func }
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

            #group_types
            #params_struct
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
