// We want to allow Point variables to be uppercase
#![allow(non_snake_case)]

//! The core functionality of the CMZ protocol macros
//!
//! You should not need to use this crate directly.  The [`cmz_core`]
//! function is called by the `cmz_derive` crate to implement the
//! `CMZProtocol` family of macros.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use std::collections::{BTreeMap, HashMap};
use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::Punctuated;
use syn::visit_mut::{self, VisitMut};
use syn::{braced, bracketed, parse_quote, token, Expr, Ident, Member, Token};

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
struct CredSpec<ShowOrIssue: Parse, const VALID_OPTIONAL: bool> {
    id: Ident,
    cred_type: Ident,
    // For shown credentials only (not issued credentials): set to true
    // if we want to only optionally (for example, in an "OR" clause)
    // show that this credential is valid.  The default state of false
    // means we should always show that the credential is valid.
    valid_optional: bool,
    attrs: BTreeMap<Ident, ShowOrIssue>,
}

impl<ShowOrIssue: Parse + Copy, const VALID_OPTIONAL: bool> Parse
    for CredSpec<ShowOrIssue, VALID_OPTIONAL>
{
    fn parse(input: ParseStream) -> Result<Self> {
        let id: Ident = input.parse()?;
        let valid_optional = if VALID_OPTIONAL && input.peek(Token![?]) {
            input.parse::<Token![?]>()?;
            true
        } else {
            false
        };
        input.parse::<Token![:]>()?;
        let cred_type: Ident = input.parse()?;
        let content;
        braced!(content in input);
        let attrspecs: Punctuated<AttrSpec<ShowOrIssue>, Token![,]> =
            content.parse_terminated(AttrSpec::<ShowOrIssue>::parse, Token![,])?;
        let mut attrs: BTreeMap<Ident, ShowOrIssue> = BTreeMap::new();
        for attrspec in attrspecs.iter() {
            attrs.insert(attrspec.attr.clone(), attrspec.spec);
        }
        Ok(Self {
            id,
            cred_type,
            valid_optional,
            attrs,
        })
    }
}

// A vector of credential specifications, which could be empty, a single
// credential specification, or a bracketed list of credential
// specifications.  We need a newtype here and not just a Vec so that we
// can implement the Parse trait for it.
struct CredSpecVec<ShowOrIssue: Parse, const VALID_OPTIONAL: bool>(
    Vec<CredSpec<ShowOrIssue, VALID_OPTIONAL>>,
);

impl<ShowOrIssue: Parse + Copy, const VALID_OPTIONAL: bool> Parse
    for CredSpecVec<ShowOrIssue, VALID_OPTIONAL>
{
    fn parse(input: ParseStream) -> Result<Self> {
        let specvec: Vec<CredSpec<ShowOrIssue, VALID_OPTIONAL>> = if input.peek(Token![,]) {
            // The list is empty
            Vec::new()
        } else if input.peek(token::Bracket) {
            let content;
            bracketed!(content in input);
            let specs: Punctuated<CredSpec<ShowOrIssue, VALID_OPTIONAL>, Token![,]> = content
                .parse_terminated(CredSpec::<ShowOrIssue, VALID_OPTIONAL>::parse, Token![,])?;
            specs.into_iter().collect()
        } else {
            let spec: CredSpec<ShowOrIssue, VALID_OPTIONAL> = input.parse()?;
            vec![spec]
        };

        Ok(Self(specvec))
    }
}

/// A parsed protocol specification, following the syntax described in
/// the documentation for the `muCMZProtocol!` macro in the `cmz` crate.
#[derive(Debug)]
pub struct ProtoSpec {
    proto_name: Ident,
    params: Vec<Ident>,
    point_params: Vec<Ident>,
    show_creds: Vec<CredSpec<ShowSpec, true>>,
    issue_creds: Vec<CredSpec<IssueSpec, false>>,
    statements: Vec<Expr>,
}

impl Parse for ProtoSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut params: Vec<Ident> = Vec::new();
        let mut point_params: Vec<Ident> = Vec::new();
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
                if input.peek(Token![@]) {
                    // Param identifiers starting with @ are Points
                    // rather than Scalars.
                    input.parse::<Token![@]>()?;
                    let param: Ident = input.parse()?;
                    point_params.push(param);
                } else {
                    let param: Ident = input.parse()?;
                    params.push(param);
                }
                if input.peek(Token![>]) {
                    break;
                }
                input.parse::<Token![,]>()?;
            }
            input.parse::<Token![>]>()?;
        }
        input.parse::<Token![,]>()?;
        let showvec: CredSpecVec<ShowSpec, true> = input.parse()?;
        input.parse::<Token![,]>()?;
        let issuevec: CredSpecVec<IssueSpec, false> = input.parse()?;
        input.parse::<Token![,]>()?;
        let statementpunc: Punctuated<Expr, Token![,]> =
            input.parse_terminated(Expr::parse, Token![,])?;
        let statements: Vec<Expr> = statementpunc.into_iter().collect();

        Ok(ProtoSpec {
            proto_name,
            params,
            point_params,
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
    Pubkey(Ident),
    ByteVec(Ident),
}

// A list of StructField items
#[derive(Default)]
struct StructFieldList {
    fields: Vec<StructField>,
}

impl StructFieldList {
    pub fn push_scalar(&mut self, s: &Ident) {
        self.fields.push(StructField::Scalar(s.clone()));
    }
    pub fn push_point(&mut self, s: &Ident) {
        self.fields.push(StructField::Point(s.clone()));
    }
    pub fn push_encpoint(&mut self, s: &Ident) {
        self.fields.push(StructField::EncPoint(s.clone()));
    }
    pub fn push_pubkey(&mut self, s: &Ident) {
        self.fields.push(StructField::Pubkey(s.clone()));
    }
    pub fn push_bytevec(&mut self, s: &Ident) {
        self.fields.push(StructField::ByteVec(s.clone()));
    }
    /// Output an iterator consisting of the field names
    pub fn field_iter(&self) -> impl Iterator<Item = &Ident> {
        self.fields.iter().map(|f| match f {
            StructField::Scalar(id) => id,
            StructField::Point(id) => id,
            StructField::EncPoint(id) => id,
            StructField::Pubkey(id) => id,
            StructField::ByteVec(id) => id,
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
            StructField::Pubkey(id) => quote! {
                pub #id: CMZPubkey<Point>,
            },
            StructField::ByteVec(id) => quote! {
                #[serde(with = "serde_bytes")]
                pub #id: Vec<u8>,
            },
        });
        quote! { #(#decls)* }
    }
}

/// Produce the expansion of the `CMZProtocol` family of macros.
///
/// The six macros in the `CMZProtocol` macro family all call this
/// function, with different values for the bools.
pub fn cmz_core(
    proto_spec: &ProtoSpec,
    use_muCMZ: bool,
    emit_client: bool,
    emit_issuer: bool,
) -> TokenStream {
    let proto_name = &proto_spec.proto_name;
    let has_params = !proto_spec.params.is_empty() || !proto_spec.point_params.is_empty();
    let tot_num_creds = proto_spec.show_creds.len() + proto_spec.issue_creds.len();

    // Use the group of the first named credential type
    let group_types = if !proto_spec.show_creds.is_empty() {
        let first_cred_type = &proto_spec.show_creds[0].cred_type;
        quote! {
            pub type Scalar = <#first_cred_type as CMZCredential>::Scalar;
            pub type Point = <#first_cred_type as CMZCredential>::Point;
        }
    } else if !proto_spec.issue_creds.is_empty() {
        let first_cred_type = &proto_spec.issue_creds[0].cred_type;
        quote! {
            pub type Scalar = <#first_cred_type as CMZCredential>::Scalar;
            pub type Point = <#first_cred_type as CMZCredential>::Point;
        }
    } else {
        quote! {}
    };

    // The structure of the client's ZKP
    let mut cli_proof_rand_scalars = Vec::<Ident>::default();
    let mut cli_proof_priv_scalars = Vec::<Ident>::default();
    let mut cli_proof_pub_scalars = Vec::<Ident>::default();
    let mut cli_proof_cind_points = Vec::<Ident>::default();
    let mut cli_proof_pub_points = Vec::<Ident>::default();
    let mut cli_proof_const_points = Vec::<Ident>::default();
    let mut cli_proof_statements = Vec::<TokenStream>::default();
    // A map from the credential name and attribute name (as Strings) to
    // the scoped attribute identifier.  This map is used to translate
    // expressions like `L.id` in the user-provided statements into the
    // appropriate identifier.
    let mut cli_proof_idmap = HashMap::<(String, String), Ident>::default();

    // The structure of the issuer's ZKP
    let mut iss_proof_rand_scalars = Vec::<Ident>::default();
    let mut iss_proof_priv_scalars = Vec::<Ident>::default();
    let mut iss_proof_pub_scalars = Vec::<Ident>::default();
    // The issuer has no cind_points
    let mut iss_proof_pub_points = Vec::<Ident>::default();
    let mut iss_proof_const_points = Vec::<Ident>::default();
    let mut iss_proof_statements = Vec::<TokenStream>::default();

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

    let A_ident = format_ident!("A_generator");
    let B_ident = format_ident!("B_generator");
    let d_ident = format_ident!("d_privkey");
    let D_ident = format_ident!("D_pubkey");
    let iss_proof_sessid_ident = format_ident!("iss_proof_sessid");

    prepare_code = quote! {
        #prepare_code
        let #A_ident = bp.A();
    };
    handle_code_pre_fill = quote! {
        #handle_code_pre_fill
        let #A_ident = bp.A();
    };
    finalize_code = quote! {
        #finalize_code
        let #A_ident = bp.A();
    };
    iss_proof_const_points.push(A_ident.clone());

    prepare_code = quote! {
        #prepare_code
        let #B_ident = bp.B();
    };
    handle_code_pre_fill = quote! {
        #handle_code_pre_fill
        let #B_ident = bp.B();
    };
    if !use_muCMZ || !proto_spec.issue_creds.is_empty() {
        finalize_code = quote! {
            #finalize_code
            let #B_ident = bp.B();
        };
        iss_proof_const_points.push(B_ident.clone());
    }

    // Stash the issue proof session id in prepare so that it can be
    // used in finalize
    clientstate_fields.push_bytevec(&iss_proof_sessid_ident);

    for iss_cred in proto_spec.issue_creds.iter() {
        // Are there any Hide or Joint attributes in this particular
        // credential to be issued?
        let mut cred_hide_joint = false;

        // The credential being issued
        let iss_cred_id = format_ident!("iss_cred_{}", iss_cred.id);
        // The public key for the credential
        let pubkey_cred = format_ident!("pubkey_iss_cred_{}", iss_cred.id);
        // The randomizing factor to generate P
        let b_cred = format_ident!("b_iss_cred_{}", iss_cred.id);
        // The (revealed part of) the MAC
        let P_cred = format_ident!("P_iss_cred_{}", iss_cred.id);
        let Q_cred = format_ident!("Q_iss_cred_{}", iss_cred.id);

        // Only for CMZ14, not µCMZ:

        // The encrypted form of the hidden part of the MAC
        let EQ_cred = format_ident!("EQ_iss_cred_{}", iss_cred.id);
        let EQ0_cred = format_ident!("EQ0_iss_cred_{}", iss_cred.id);
        let EQ1_cred = format_ident!("EQ1_iss_cred_{}", iss_cred.id);
        // The ZKP statements that prove the format of EQ_cred
        let mut eq0_statement = quote! {};
        let mut eq1_statement = quote! {};

        // Only for µCMZ, not CMZ14:

        // The Pedersen commitment to only the Hide and Joint attributes
        let C_cred = format_ident!("C_iss_cred_{}", iss_cred.id);
        // The completed Pedersen commitment to the attributes
        // (including all kinds of attributes)
        let K_cred = format_ident!("K_iss_cred_{}", iss_cred.id);
        // The ZKP statement that proves the format of C
        let mut C_statement = quote! {};

        let iss_cred_type = &iss_cred.cred_type;

        // String version of the credential name
        let cred_str = iss_cred.id.to_string();

        // Check that fill_creds filled in the private key for this
        // credential and that it's for the right protocol (CMZ14 or
        // µCMZ)
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            if #iss_cred_id.get_privkey().x.len() != #iss_cred_type::num_attrs() {
                return Err(CMZError::PrivkeyMissing(#cred_str));
            }
            if #iss_cred_id.get_privkey().muCMZ != #use_muCMZ {
                return Err(CMZError::WrongProtocol(#cred_str));
            }
        };

        // Check that the credential passed to prepare has its public
        // key set and that it's for the right protocol (CMZ14 or µCMZ)
        prepare_code = quote! {
            #prepare_code
            if #iss_cred_id.get_pubkey().X.len() != #iss_cred_type::num_attrs() {
                return Err(CMZError::PubkeyMissing(#cred_str));
            }
            if #iss_cred_id.get_pubkey().Xr.is_some() != #use_muCMZ {
                return Err(CMZError::WrongProtocol(#cred_str));
            }
        };

        // Stash the public key in prepare and use it to fill in the
        // public key of the completed credential in finalize
        clientstate_fields.push_pubkey(&pubkey_cred);
        prepare_code = quote! {
            #prepare_code
            let #pubkey_cred = #iss_cred_id.get_pubkey().clone();
        };
        finalize_code = quote! {
            #finalize_code
            #iss_cred_id.set_pubkey(&self.#pubkey_cred);
        };

        for (attr, &spec) in iss_cred.attrs.iter() {
            // String version of the attribute name
            let attr_str = attr.to_string();

            // The scoped attribute name
            let scoped_attr = format_ident!("iss_{}attr_{}_{}", spec.abbr(), iss_cred.id, attr);

            // Remember the mapping from the credential and attribute
            // name to the scoped attribute
            cli_proof_idmap.insert(
                (iss_cred.id.to_string(), attr.to_string()),
                scoped_attr.clone(),
            );

            // The private and public key for this attribute
            let x_attr = format_ident!("x_{}", scoped_attr);
            let X_attr = format_ident!("X_{}", scoped_attr);

            if spec == IssueSpec::Hide || spec == IssueSpec::Joint {
                cred_hide_joint = true;
            }

            if !use_muCMZ {
                // For CMZ14, we prove that the encrypted MAC is
                // consistent with all components of the credential's
                // public key
                handle_code_post_auth = quote! {
                    #handle_code_post_auth
                    let #x_attr = #iss_cred_id.privkey_x(#attr_str);
                    let #X_attr = #iss_cred_id.pubkey_X(#attr_str);
                };
                finalize_code = quote! {
                    #finalize_code
                    let #X_attr = #iss_cred_id.pubkey_X(#attr_str);
                };
                iss_proof_priv_scalars.push(x_attr.clone());
                iss_proof_pub_points.push(X_attr.clone());
                iss_proof_statements.push(quote! {
                    #X_attr = #x_attr * #A_ident,
                });
            }

            if spec == IssueSpec::Hide {
                /* For each Hide attribute, the attribute (passed in the
                   prepare) goes in the ClientState, and from there to
                   to the generated credential in finalize.
                */
                clientstate_fields.push_scalar(&scoped_attr);
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::HideAttrMissing(#cred_str,
                    #attr_str))?;
                };
                finalize_code = quote! {
                    #finalize_code
                    #iss_cred_id.#attr = Some(self.#scoped_attr);
                }
            }

            if spec == IssueSpec::Joint {
                /* For each Joint attribute, the client's part of the
                   attribute (randomly generated) goes in the
                   ClientState, and the issuer's part of the attribute
                   (randomly generated) goes in the Reply.
                */
                clientstate_fields.push_scalar(&scoped_attr);
                reply_fields.push_scalar(&scoped_attr);
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr = <Scalar as ff::Field>::random(&mut *rng);
                };
                handle_code_pre_fill = quote! {
                    #handle_code_pre_fill
                    let #scoped_attr = <Scalar as ff::Field>::random(&mut *rng);
                };
                finalize_code = quote! {
                    #finalize_code
                    let #scoped_attr = reply.#scoped_attr;
                    #iss_cred_id.#attr = Some(self.#scoped_attr + reply.#scoped_attr);
                };
            }

            if !use_muCMZ && (spec == IssueSpec::Hide || spec == IssueSpec::Joint) {
                /* For each Hide and Joint attribute (for CMZ14): Compute an
                   exponential El Gamal encryption (of the attribute) E_attr =
                   (r_attr*B, attr*B + r_attr*D) for random r_attr.  Include E_attr
                   in the Request, attr in the ClientState, and attr,
                   r_attr, and E_attr in the CliProof.  Add
                   b*x_attr*E_attr to E_Q in handle, for the b chosen on
                   a per-issued-credential basis below.  Include x_attr,
                   X_attr, and t_attr = b*x_attr in IssProof and T_attr
                   = b*X_attr = t_attr*A in Reply and IssProof.
                */
                let enc_attr = format_ident!("E_{}", scoped_attr);
                let enc0_attr = format_ident!("E0_{}", scoped_attr);
                let enc1_attr = format_ident!("E1_{}", scoped_attr);
                let r_attr = format_ident!("r_{}", scoped_attr);
                let t_attr = format_ident!("t_{}", scoped_attr);
                let T_attr = format_ident!("T_{}", scoped_attr);
                request_fields.push_encpoint(&enc_attr);
                clientstate_fields.push_encpoint(&enc_attr);
                reply_fields.push_point(&T_attr);
                iss_proof_priv_scalars.push(t_attr.clone());
                iss_proof_pub_points.push(T_attr.clone());
                iss_proof_pub_points.push(enc0_attr.clone());
                iss_proof_pub_points.push(enc1_attr.clone());
                iss_proof_statements.push(quote! {
                    #T_attr = #t_attr * #A_ident,
                    #T_attr = #b_cred * #X_attr,
                });
                eq0_statement = quote! {
                    #eq0_statement + #t_attr * #enc0_attr
                };
                eq1_statement = quote! {
                    #eq1_statement + #t_attr * #enc1_attr
                };
                cli_proof_priv_scalars.push(scoped_attr.clone());
                cli_proof_rand_scalars.push(r_attr.clone());
                cli_proof_pub_points.push(enc0_attr.clone());
                cli_proof_pub_points.push(enc1_attr.clone());
                cli_proof_statements.push(quote! {
                    #enc0_attr = #r_attr * #B_ident,
                    #enc1_attr = #scoped_attr * #B_ident + #r_attr * #D_ident,
                });
                prepare_code = quote! {
                    #prepare_code
                    let #r_attr = <Scalar as ff::Field>::random(&mut *rng);
                    let #enc0_attr = bp.mulB(&#r_attr);
                    let #enc1_attr = bp.mulB(&#scoped_attr) +
                        #r_attr * #D_ident;
                    let #enc_attr = (#enc0_attr, #enc1_attr);
                };
                handle_code_post_fill = quote! {
                    #handle_code_post_fill

                    let #enc0_attr = request.#enc_attr.0;
                    let #enc1_attr = request.#enc_attr.1;
                };
                handle_code_post_auth = quote! {
                    #handle_code_post_auth

                    let #t_attr = #b_cred * #x_attr;
                    #EQ_cred.0 += #t_attr * #enc0_attr;
                    #EQ_cred.1 += #t_attr * #enc1_attr;
                    let #T_attr = bp.mulA(&#t_attr);
                };
                finalize_code = quote! {
                    #finalize_code
                    let #T_attr = reply.#T_attr;
                    let #enc0_attr = self.#enc_attr.0;
                    let #enc1_attr = self.#enc_attr.1;
                };
            }

            if use_muCMZ && (spec == IssueSpec::Hide || spec == IssueSpec::Joint) {
                /* For each Hide and Joint attribute (for µCMZ): add
                   attr*X_attr to C.
                */
                prepare_code = quote! {
                    #prepare_code
                    let #X_attr = #pubkey_cred.X[#iss_cred_type::attr_num(#attr_str)];
                    #C_cred += #scoped_attr * #X_attr;
                };
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    let #X_attr = #iss_cred_id.pubkey_X(#attr_str);
                };
                C_statement = quote! {
                    #C_statement + #scoped_attr * #X_attr
                };
                cli_proof_priv_scalars.push(scoped_attr.clone());
                cli_proof_cind_points.push(X_attr.clone());
            }

            /* For each Reveal attribute: include attr in Request (client will
               pass the value into prepare).  Also store it in the
               ClientState.
            */
            if spec == IssueSpec::Reveal {
                request_fields.push_scalar(&scoped_attr);
                clientstate_fields.push_scalar(&scoped_attr);
                cli_proof_pub_scalars.push(scoped_attr.clone());
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::RevealAttrMissing(#cred_str,
                    #attr_str))?;
                };
                handle_code_pre_fill = quote! {
                    #handle_code_pre_fill
                    let #scoped_attr = request.#scoped_attr;
                    #iss_cred_id.#attr = Some(#scoped_attr);
                };
                finalize_code = quote! {
                    #finalize_code
                    #iss_cred_id.#attr = Some(self.#scoped_attr);
                };
            }

            /* For each Implicit attribute: store it in ClientState
               (will be passed into prepare) on the client side, and
               will be filled in by fill_creds on the issuer side.
            */
            if spec == IssueSpec::Implicit {
                clientstate_fields.push_scalar(&scoped_attr);
                cli_proof_pub_scalars.push(scoped_attr.clone());
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
                };
                finalize_code = quote! {
                    #finalize_code
                    #iss_cred_id.#attr = Some(self.#scoped_attr);
                };
            }

            /* For each Set attribute: the issuer's value will be set
              by fill_creds.  Include the value in Reply.
            */
            if spec == IssueSpec::Set {
                reply_fields.push_scalar(&scoped_attr);
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    let #scoped_attr =
                    #iss_cred_id.#attr.ok_or(CMZError::SetAttrMissing(#cred_str,
                    #attr_str))?;
                };
                finalize_code = quote! {
                    #finalize_code
                    #iss_cred_id.#attr = Some(reply.#scoped_attr);
                }
            }

            if spec == IssueSpec::Reveal
                || spec == IssueSpec::Implicit
                || spec == IssueSpec::Set
                || spec == IssueSpec::Joint
            {
                if use_muCMZ {
                    /* For each Reveal, Implicit, Set, or Joint attribute, add
                       attr*X_attr to K in handle and finalize.
                    */
                    handle_code_post_fill = quote! {
                        #handle_code_post_fill
                        #K_cred += (#scoped_attr *
                            #iss_cred_id.pubkey_X(#attr_str));
                    };
                    // For a Joint attribute, we only want to use the
                    // issuer's contribution (which is in #scoped_attr),
                    // not #iss_cred_id.#attr, which is the sum of the
                    // client's and issuer's contributions
                    let use_attr = if spec == IssueSpec::Joint {
                        quote! { #scoped_attr }
                    } else {
                        quote! { #iss_cred_id.#attr.unwrap() }
                    };
                    finalize_code = quote! {
                        #finalize_code
                        #K_cred += (#use_attr *
                            #iss_cred_id.pubkey_X(#attr_str));
                    };
                } else {
                    /* For each Reveal, Implicit, Set, or Joint attribute, add
                       attr*x_attr*P to Q in handle.
                    */
                    handle_code_post_auth = quote! {
                        #handle_code_post_auth
                        #Q_cred += (#scoped_attr * #x_attr) * #P_cred;
                    };
                    // For Joint attributes, we only want to use the
                    // issuer's contribution.  We already set
                    // #scoped_attr to the issuer's contribution earlier
                    // on.
                    if spec != IssueSpec::Joint {
                        finalize_code = quote! {
                            #finalize_code
                            let #scoped_attr = #iss_cred_id.#attr.unwrap();
                        };
                    }
                    eq1_statement = quote! {
                        #eq1_statement + #x_attr * ( #scoped_attr * #P_cred )
                    };
                    iss_proof_pub_scalars.push(scoped_attr.clone());
                }
            }
        }

        if !use_muCMZ {
            /* For all Hide and Joint attributes of a single credential to be
               issued (for CMZ14): the issuer chooses random b and s, computes
               P = b*B, E_Q = (s*B,s*D+b*x_0*B) + \sum_{hide,joint}
               b*x_attr*E_attr + (0,\sum_{implicit,reveal,set,joint}
               b*x_attr*attr*B) (note that E_Q and each E_attr are all
               pairs of Points; the scalar multiplication is
               componentwise).  Include P, E_Q in Reply. The client will
               compute Q = E_Q[1] - d*E_Q[0].
            */
            let s_cred = format_ident!("s_iss_cred_{}", iss_cred.id);
            let x0_cred = format_ident!("x0_iss_cred_{}", iss_cred.id);
            let xr_cred = format_ident!("xr_cred{}", iss_cred.id);
            let X0_cred = format_ident!("X0_iss_cred_{}", iss_cred.id);
            reply_fields.push_point(&P_cred);
            if cred_hide_joint {
                reply_fields.push_encpoint(&EQ_cred);
            } else {
                reply_fields.push_point(&Q_cred);
            }
            let EQ_cred_code_pre = if cred_hide_joint {
                quote! {
                    let #s_cred = <Scalar as ff::Field>::random(&mut *rng);
                    let mut #EQ_cred = (bp.mulB(&#s_cred), #s_cred * #D_ident);
                }
            } else {
                quote! {}
            };
            let EQ_cred_code_post = if cred_hide_joint {
                quote! {
                    #EQ_cred.1 += #Q_cred;
                    let #EQ0_cred = #EQ_cred.0;
                    let #EQ1_cred = #EQ_cred.1;
                }
            } else {
                quote! {}
            };
            if cred_hide_joint {
                iss_proof_pub_points.push(EQ0_cred.clone());
                iss_proof_pub_points.push(EQ1_cred.clone());
                iss_proof_statements.push(quote! {
                    #EQ0_cred = #s_cred * #B_ident #eq0_statement,
                    #EQ1_cred = #s_cred * #D_ident + #x0_cred * #P_cred #eq1_statement,
                });
            }
            handle_code_post_auth = quote! {
                let #b_cred = <Scalar as ff::Field>::random(&mut *rng);
                let #P_cred = bp.mulB(&#b_cred);
                #iss_cred_id.MAC.P = #P_cred;
                let #x0_cred = #iss_cred_id.get_privkey().x0;
                let #xr_cred = #iss_cred_id.get_privkey().xr;
                let #X0_cred = #iss_cred_id.get_pubkey().X0.unwrap();
                let mut #Q_cred = bp.mulB(&(#b_cred * #iss_cred_id.get_privkey().x0));
                #EQ_cred_code_pre

                #handle_code_post_auth

                #EQ_cred_code_post
            };
            let finalize_Q_code = if cred_hide_joint {
                quote! {
                    let #EQ0_cred = reply.#EQ_cred.0;
                    let #EQ1_cred = reply.#EQ_cred.1;
                    #iss_cred_id.MAC.Q = #EQ1_cred - self.#d_ident * #EQ0_cred;
                }
            } else {
                quote! {
                    #iss_cred_id.MAC.Q = reply.#Q_cred;
                }
            };
            finalize_code = quote! {
                #finalize_code
                let #P_cred = reply.#P_cred;
                let #X0_cred = #iss_cred_id.get_pubkey().X0.unwrap();
                #iss_cred_id.MAC.P = #P_cred;
                #finalize_Q_code
            };
            if cred_hide_joint {
                iss_proof_rand_scalars.push(s_cred.clone());
            }
            iss_proof_pub_points.push(P_cred.clone());
            iss_proof_priv_scalars.push(x0_cred.clone());
            iss_proof_rand_scalars.push(xr_cred.clone());
            iss_proof_pub_points.push(X0_cred.clone());
            iss_proof_rand_scalars.push(b_cred.clone());
            iss_proof_statements.push(quote! {
                #X0_cred = #x0_cred * #B_ident + #xr_cred * #A_ident,
            });
        }

        if use_muCMZ {
            /* For all Hide and Joint attributes of a single credential to be
               issued (for µCMZ): The client chooses a random s, computes C =
               (\sum_{hide,joint} attr*X_attr) + s*A, where X_attr is the
               public key for that attribute.  Include s and C in the
               ClientState, C in the Request, and the attributes, s, and
               C in the CliProof.  Hide attributes will be passed into
               prepare on the client side; Joint attributes (client
               contribution) will be generated randomly by prepare on
               the client side.  On the issuer side, handle will pick a
               random b, compute P = b*A, K = C + X_r +
               \sum_{implicit,reveal,set,joint} attr*X_attr, R =
               b*(x_0*A + K).  Include P and R in Reply, and x_0, b, P,
               R, K in IssProof.  For each implicit,reveal,set,joint
               attribute, include x_attr and P_attr = attr*P in
               IssProof.  The client will compute K as above, and Q = R
               - s*P.
            */
            let R_cred = format_ident!("R_iss_cred_{}", iss_cred.id);
            let s_cred = format_ident!("s_iss_cred_{}", iss_cred.id);
            let x0_cred = format_ident!("x0_iss_cred_{}", iss_cred.id);
            let X0_cred = format_ident!("X0_iss_cred_{}", iss_cred.id);
            reply_fields.push_point(&P_cred);
            reply_fields.push_point(&R_cred);
            if cred_hide_joint {
                clientstate_fields.push_scalar(&s_cred);
                clientstate_fields.push_point(&C_cred);
                request_fields.push_point(&C_cred);
                cli_proof_pub_points.push(C_cred.clone());
                cli_proof_rand_scalars.push(s_cred.clone());
                prepare_code = quote! {
                    let #s_cred = <Scalar as ff::Field>::random(&mut *rng);
                    let mut #C_cred = bp.mulA(&#s_cred);
                    #prepare_code
                };
                handle_code_post_fill = quote! {
                    let #C_cred = request.#C_cred;
                    let mut #K_cred = #C_cred + #iss_cred_id.get_pubkey().Xr.unwrap();
                    #handle_code_post_fill
                };
                finalize_code = quote! {
                    let mut #K_cred = self.#C_cred + self.#pubkey_cred.Xr.unwrap();
                    #finalize_code
                };
                // Construct the client proof for this credential
                cli_proof_statements.push(quote! {
                    #C_cred = #s_cred * #A_ident #C_statement,
                });
            } else {
                handle_code_post_fill = quote! {
                    let mut #K_cred = #iss_cred_id.get_pubkey().Xr.unwrap();
                    #handle_code_post_fill
                };
                finalize_code = quote! {
                    let mut #K_cred = self.#pubkey_cred.Xr.unwrap();
                    #finalize_code
                };
            }
            handle_code_post_auth = quote! {
                #handle_code_post_auth
                let #b_cred = <Scalar as ff::Field>::random(&mut *rng);
                let #P_cred = bp.mulA(&#b_cred);
                #iss_cred_id.MAC.P = #P_cred;
                let #x0_cred = #iss_cred_id.get_privkey().x0;
                let #X0_cred = #iss_cred_id.get_pubkey().X0.unwrap();
                let #R_cred = #b_cred * (bp.mulA(&#x0_cred) + #K_cred);
            };
            let finalize_Q_code = if cred_hide_joint {
                quote! {
                    #iss_cred_id.MAC.Q = reply.#R_cred - self.#s_cred * reply.#P_cred;
                }
            } else {
                quote! {
                    #iss_cred_id.MAC.Q = reply.#R_cred;
                }
            };
            finalize_code = quote! {
                #finalize_code
                let #P_cred = reply.#P_cred;
                let #X0_cred = #iss_cred_id.get_pubkey().X0.unwrap();
                let #R_cred = reply.#R_cred;
                #iss_cred_id.MAC.P = #P_cred;
                #finalize_Q_code
            };
            // Construct the issuer proof for this credential
            iss_proof_priv_scalars.push(x0_cred.clone());
            iss_proof_rand_scalars.push(b_cred.clone());
            iss_proof_pub_points.push(P_cred.clone());
            iss_proof_pub_points.push(X0_cred.clone());
            iss_proof_pub_points.push(K_cred.clone());
            iss_proof_pub_points.push(R_cred.clone());
            iss_proof_statements.push(quote! {
                #P_cred = #b_cred * #A_ident,
                #X0_cred = #x0_cred * #B_ident,
                #R_cred = #x0_cred * #P_cred + #b_cred * #K_cred,
            });
        }

        any_hide_joint |= cred_hide_joint;
    }

    /* If there are _any_ Hide or Joint attributes in CMZ14 (as opposed
       to µCMZ), the client generates an El Gamal keypair (d, D=d*B).
       Include d in the ClientState and D in the Request.
    */
    if any_hide_joint && !use_muCMZ {
        clientstate_fields.push_scalar(&d_ident);
        clientstate_fields.push_point(&D_ident);
        cli_proof_rand_scalars.push(d_ident.clone());
        cli_proof_pub_points.push(D_ident.clone());
        request_fields.push_point(&D_ident);
        cli_proof_statements.push(quote! {
            #D_ident = #d_ident * #B_ident,
        });
        prepare_code = quote! {
            let (#d_ident,#D_ident) = bp.keypairB(&mut *rng);
            #prepare_code
        };
        handle_code_post_fill = quote! {
            let #D_ident = request.#D_ident;
            #handle_code_post_fill
        };
        finalize_code = quote! {
            #finalize_code
            let #D_ident = self.#D_ident;
        };
        iss_proof_pub_points.push(D_ident.clone());
    }

    if !proto_spec.issue_creds.is_empty() {
        // The issuer will create a zero-knowledge proof
        let iss_proof_ident = format_ident!("iss_proof");
        reply_fields.push_bytevec(&iss_proof_ident);
        let iss_instance_fields = iss_proof_pub_points
            .iter()
            .chain(iss_proof_const_points.iter())
            .chain(iss_proof_pub_scalars.iter());
        let iss_witness_fields = iss_proof_rand_scalars
            .iter()
            .chain(iss_proof_priv_scalars.iter());
        handle_code_post_auth = quote! {
            #handle_code_post_auth
            let iss_proof_instance = issuer_proof::Instance {
                #(#iss_instance_fields,)*
            };
            let iss_proof_witness = issuer_proof::Witness {
                #(#iss_witness_fields,)*
            };
            // If prove returns Err here, there's an actual bug.
            let #iss_proof_ident =
            issuer_proof::prove(&iss_proof_instance,
                &iss_proof_witness, &iss_proof_sessid, rng).unwrap();
        };
        let cli_iss_instance_fields = iss_proof_pub_points
            .iter()
            .chain(iss_proof_const_points.iter())
            .chain(iss_proof_pub_scalars.iter());
        finalize_code = quote! {
            #finalize_code
            let iss_proof_instance = issuer_proof::Instance {
                #(#cli_iss_instance_fields,)*
            };
            if issuer_proof::verify(&iss_proof_instance,
                &reply.#iss_proof_ident, &self.iss_proof_sessid).is_err() {
                return Err((CMZError::IssProofFailed, self));
            }
        };
    }

    // Validity proofs for shown credentials with valid_optional go here
    let mut validity_proofs: HashMap<String, TokenStream> = HashMap::new();

    for show_cred in proto_spec.show_creds.iter() {
        // The credential being shown
        let show_cred_id = format_ident!("show_cred_{}", show_cred.id);
        // The rerandomizing factor for the MAC
        let t_cred = format_ident!("t_show_cred_{}", show_cred.id);
        // The rerandomized MAC
        let P_cred = format_ident!("P_show_cred_{}", show_cred.id);
        let Q_cred = format_ident!("Q_show_cred_{}", show_cred.id);
        // The randomness for the Pedersen commitment to Q
        let zQ_cred = format_ident!("zQ_show_cred_{}", show_cred.id);
        // The Pedersen commitment to Q
        let CQ_cred = format_ident!("CQ_show_cred_{}", show_cred.id);
        // The verification point
        let V_cred = format_ident!("V_show_cred_{}", show_cred.id);
        // The coefficient (on P) of the MAC on the Reveal and Implicit
        // attributes, computed by the issuer
        let q_cred = format_ident!("q_show_cred_{}", show_cred.id);

        let show_cred_type = &show_cred.cred_type;

        // String version of the credential name
        let cred_str = show_cred.id.to_string();

        // Check that fill_creds filled in the private key for this
        // credential and that it's for the right protocol (CMZ14 or
        // µCMZ)
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            if #show_cred_id.get_privkey().x.len() != #show_cred_type::num_attrs() {
                return Err(CMZError::PrivkeyMissing(#cred_str));
            }
            if #show_cred_id.get_privkey().muCMZ != #use_muCMZ {
                return Err(CMZError::WrongProtocol(#cred_str));
            }
        };

        // Check that the credential passed to prepare has its public
        // key set and that it's for the right protocol (CMZ14 or µCMZ)
        prepare_code = quote! {
            #prepare_code
            if #show_cred_id.get_pubkey().X.len() != #show_cred_type::num_attrs() {
                return Err(CMZError::PubkeyMissing(#cred_str));
            }
            if #show_cred_id.get_pubkey().Xr.is_some() != #use_muCMZ {
                return Err(CMZError::WrongProtocol(#cred_str));
            }
        };

        // Rerandomize the MAC and construct a Pedersen commitment to Q
        // Also start constructing the client's version of the
        // verification point V (which will be updated with each Hide
        // attribute below)
        prepare_code = quote! {
            #prepare_code
            let #t_cred = <Scalar as ff::Field>::random(&mut *rng);
            let #P_cred = #t_cred * #show_cred_id.MAC.P;
            let #Q_cred = #t_cred * #show_cred_id.MAC.Q;
            let #zQ_cred = <Scalar as ff::Field>::random(&mut *rng);
            let #CQ_cred = #Q_cred - bp.mulB(&#zQ_cred);
            let mut #V_cred = bp.mulB(&#zQ_cred);
        };
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            let #P_cred = request.#P_cred;
            if bool::from(#P_cred.is_identity()) {
                return Err(CMZError::CliProofFailed);
            }
        };
        request_fields.push_point(&P_cred);
        request_fields.push_point(&CQ_cred);
        cli_proof_rand_scalars.push(zQ_cred.clone());
        cli_proof_cind_points.push(P_cred.clone());
        cli_proof_pub_points.push(V_cred.clone());

        // The ZKP statement that proves the format of V
        let mut V_statement = quote! {
            #V_cred = #zQ_cred * #B_ident
        };

        // Start constructing the issuer's version of the verification
        // point Vi (which will be updated with each Hide attribute below)
        // and the MAC on the Reveal and Implicit attributes

        // µCMZ has the extra xr to add in here
        let q_init = if use_muCMZ {
            quote! { #show_cred_id.get_privkey().x0 + #show_cred_id.get_privkey().xr }
        } else {
            quote! { #show_cred_id.get_privkey().x0 }
        };
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            let mut #V_cred = -request.#CQ_cred;
            let mut #q_cred = #q_init;
        };

        for (attr, &spec) in show_cred.attrs.iter() {
            // String version of the attribute name
            let attr_str = attr.to_string();

            // The scoped attribute name
            let scoped_attr = format_ident!("show_{}attr_{}_{}", spec.abbr(), show_cred.id, attr);

            // The public key for this attribute
            let X_attr = format_ident!("X_{}", scoped_attr);

            // Remember the mapping from the credential and attribute
            // name to the scoped attribute
            cli_proof_idmap.insert(
                (show_cred.id.to_string(), attr.to_string()),
                scoped_attr.clone(),
            );

            if spec == ShowSpec::Hide {
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #show_cred_id.#attr.ok_or(CMZError::HideAttrMissing(#cred_str,
                    #attr_str))?;
                };
                // Construct a Pedersen commitment to the Hide attribute
                // and update the verification point
                let z_attr = format_ident!("z_{}", scoped_attr);
                let C_attr = format_ident!("C_{}", scoped_attr);
                request_fields.push_point(&C_attr);
                prepare_code = quote! {
                    #prepare_code
                    let #z_attr = <Scalar as ff::Field>::random(&mut *rng);
                    let #C_attr = #scoped_attr * #P_cred + bp.mulA(&#z_attr);
                    let #X_attr = #show_cred_id.pubkey_X(#attr_str);
                    #V_cred += #z_attr * #X_attr;
                };
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    let #C_attr = request.#C_attr;
                    let #X_attr = #show_cred_id.pubkey_X(#attr_str);
                    #V_cred += #show_cred_id.privkey_x(#attr_str)
                        * #C_attr;
                };
                cli_proof_priv_scalars.push(scoped_attr.clone());
                cli_proof_rand_scalars.push(z_attr.clone());
                cli_proof_pub_points.push(C_attr.clone());
                cli_proof_cind_points.push(X_attr.clone());
                cli_proof_statements.push(quote! {
                    #C_attr = #scoped_attr * #P_cred + #z_attr * #A_ident,
                });
                V_statement = quote! {
                    #V_statement + #z_attr * #X_attr
                };
            }

            if spec == ShowSpec::Reveal {
                request_fields.push_scalar(&scoped_attr);
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #show_cred_id.#attr.ok_or(CMZError::RevealAttrMissing(#cred_str,
                    #attr_str))?;
                };
                handle_code_pre_fill = quote! {
                    #handle_code_pre_fill
                    let #scoped_attr = request.#scoped_attr;
                    #show_cred_id.#attr = Some(#scoped_attr);
                };
                // Accumulate the coefficient (of P) on the component of
                // Q due to this attribute
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    #q_cred += #scoped_attr *
                        #show_cred_id.privkey_x(#attr_str);
                };
                cli_proof_pub_scalars.push(scoped_attr.clone());
            }

            if spec == ShowSpec::Implicit {
                prepare_code = quote! {
                    #prepare_code
                    let #scoped_attr =
                    #show_cred_id.#attr.ok_or(CMZError::ImplicitAttrCliMissing(#cred_str,
                    #attr_str))?;
                };
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    let #scoped_attr =
                    #show_cred_id.#attr.ok_or(CMZError::ImplicitAttrIssMissing(#cred_str,
                    #attr_str))?;
                };
                // Accumulate the coefficient (of P) on the component of
                // Q due to this attribute
                handle_code_post_fill = quote! {
                    #handle_code_post_fill
                    #q_cred += #scoped_attr *
                        #show_cred_id.privkey_x(#attr_str);
                };
                cli_proof_pub_scalars.push(scoped_attr.clone());
            }
        }
        // Compute the computation of the issuer's version of the
        // Verification point Vi
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            #V_cred += #q_cred * #P_cred;
        };

        if show_cred.valid_optional {
            validity_proofs.insert(
                cred_str,
                quote! {
                    #V_statement
                },
            );
        } else {
            cli_proof_statements.push(quote! {
                #V_statement,
            });
        }
    }
    cli_proof_const_points.push(A_ident.clone());
    cli_proof_const_points.push(B_ident.clone());

    for paramid in proto_spec.params.iter() {
        let scoped_param = format_ident!("param_{}", paramid);
        prepare_code = quote! {
            #prepare_code
            let #scoped_param = params.#paramid;
        };
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            let #scoped_param = params.#paramid;
        };
        cli_proof_pub_scalars.push(scoped_param.clone());
        cli_proof_idmap.insert(("".to_string(), paramid.to_string()), scoped_param.clone());
    }

    for paramid in proto_spec.point_params.iter() {
        let scoped_param = format_ident!("param_{}", paramid);
        prepare_code = quote! {
            #prepare_code
            let #scoped_param = params.#paramid;
        };
        handle_code_post_fill = quote! {
            #handle_code_post_fill
            let #scoped_param = params.#paramid;
        };
        cli_proof_pub_points.push(scoped_param.clone());
        cli_proof_idmap.insert(("".to_string(), paramid.to_string()), scoped_param.clone());
    }

    // The client will create a zero-knowledge proof
    let cli_proof_ident = format_ident!("cli_proof");
    request_fields.push_bytevec(&cli_proof_ident);
    let cli_instance_fields = cli_proof_pub_points
        .iter()
        .chain(cli_proof_const_points.iter())
        .chain(cli_proof_cind_points.iter())
        .chain(cli_proof_pub_scalars.iter());
    let cli_witness_fields = cli_proof_rand_scalars
        .iter()
        .chain(cli_proof_priv_scalars.iter());
    prepare_code = quote! {
        #prepare_code
        let cli_proof_instance = client_proof::Instance {
            #(#cli_instance_fields,)*
        };
        let cli_proof_witness = client_proof::Witness {
            #(#cli_witness_fields,)*
        };
        // If prove returns Err here, there's an actual bug.
        let #cli_proof_ident = client_proof::prove(&cli_proof_instance,
            &cli_proof_witness, &cli_proof_sessid, rng).unwrap();
    };
    let iss_cli_instance_fields = cli_proof_pub_points
        .iter()
        .chain(cli_proof_const_points.iter())
        .chain(cli_proof_cind_points.iter())
        .chain(cli_proof_pub_scalars.iter());
    handle_code_post_fill = quote! {
        #handle_code_post_fill
        let cli_proof_instance = client_proof::Instance {
            #(#iss_cli_instance_fields,)*
        };
        if client_proof::verify(&cli_proof_instance,
            &request.#cli_proof_ident, &cli_proof_sessid).is_err() {
            return Err(CMZError::CliProofFailed);
        }
    };

    // Build the Params struct, if we have params
    let params_struct = if has_params {
        let param_list = &proto_spec.params;
        let point_param_list = &proto_spec.point_params;
        quote! {
            pub struct Params {
                #( pub #param_list: Scalar, )*
                #( pub #point_param_list: Point, )*
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

    // Massage the statements provided in the protocol spec to change
    // any expression of the form "L.id" (a credential name and an
    // attribute name) into the corresponding scoped attribute.
    // Bare identifiers that are protocol parameter names also get
    // modified into the corresponding scoped attribute.  These names
    // are stored in the idmap with an empty string for the credential
    // name.
    //
    // The expression "valid(A)" for a shown credential A with
    // valid_optional set expands to the proof of validity for that
    // credential.

    struct StatementScoper<'a> {
        idmap: &'a HashMap<(String, String), Ident>,
        validity_proofs: &'a HashMap<String, TokenStream>,
    }

    impl<'a> VisitMut for StatementScoper<'a> {
        fn visit_expr_mut(&mut self, node: &mut Expr) {
            if let Expr::Field(exfld) = node {
                let base = *exfld.base.clone();
                if let Expr::Path(basepath) = base {
                    if let Member::Named(attrid) = &exfld.member {
                        if let Some(credid) = basepath.path.get_ident() {
                            if let Some(scopedid) =
                                self.idmap.get(&(credid.to_string(), attrid.to_string()))
                            {
                                *node = parse_quote! { #scopedid };
                                return;
                            }
                        }
                    }
                }
            }

            if let Expr::Path(expath) = node {
                if let Some(id) = expath.path.get_ident() {
                    if let Some(scopedparam) = self.idmap.get(&("".to_string(), id.to_string())) {
                        *node = parse_quote! { #scopedparam };
                        return;
                    }
                }
            }

            if let Expr::Call(excall) = node {
                let base = *excall.func.clone();
                if let Expr::Path(basepath) = base {
                    if let Some(id) = basepath.path.get_ident() {
                        if *id == "valid" && excall.args.len() == 1 {
                            let mut validity_statement = quote! {};
                            let argexpr = excall.args.first().unwrap();
                            if let Expr::Path(argpath) = argexpr {
                                if let Some(credid) = argpath.path.get_ident() {
                                    let credstr = credid.to_string();
                                    match self.validity_proofs.get(&credstr) {
                                        Some(tokens) => {
                                            validity_statement = tokens.clone();
                                        },
                                        None => panic!("{} is not a shown credential with optional validity proof", credstr),
                                    }
                                }
                            }
                            *node = parse_quote! { #validity_statement };
                            return;
                        }
                    }
                }
            }

            // Unless we bailed out above, continue with the default
            // traversal
            visit_mut::visit_expr_mut(self, node);
        }
    }

    let mut statement_scoper = StatementScoper {
        idmap: &cli_proof_idmap,
        validity_proofs: &validity_proofs,
    };
    let mut cli_proof_scoped_statements = proto_spec.statements.clone();
    cli_proof_scoped_statements
        .iter_mut()
        .for_each(|expr| statement_scoper.visit_expr_mut(expr));

    // The client's zero-knowledge proof
    let cli_sigma_compiler_macro = if emit_client && emit_issuer {
        quote! { sigma_compiler }
    } else if emit_client {
        quote! { sigma_compiler_prover }
    } else {
        quote! { sigma_compiler_verifier }
    };

    let cli_proof = {
        quote! {
            #cli_sigma_compiler_macro! { client_proof<Point>,
                (#(rand #cli_proof_rand_scalars,)*
                 #(#cli_proof_priv_scalars,)*
                 #(pub #cli_proof_pub_scalars,)*),
                (#(cind #cli_proof_cind_points,)*
                 #(#cli_proof_pub_points,)*
                 #(cind const #cli_proof_const_points,)*),
                #(#cli_proof_scoped_statements,)*
                #(#cli_proof_statements)*
            }
        }
    };

    // The issuer's zero-knowledge proof
    let iss_sigma_compiler_macro = if emit_client && emit_issuer {
        quote! { sigma_compiler }
    } else if emit_issuer {
        quote! { sigma_compiler_prover }
    } else {
        quote! { sigma_compiler_verifier }
    };

    let iss_proof = {
        quote! {
            #iss_sigma_compiler_macro! { issuer_proof<Point>,
                (#(rand #iss_proof_rand_scalars,)*
                 #(#iss_proof_priv_scalars,)*
                 #(pub #iss_proof_pub_scalars,)*),
                // no cind_points
                (#(#iss_proof_pub_points,)*
                 #(cind const #iss_proof_const_points,)*),
                #(#iss_proof_statements)*
            }
        }
    };

    // The argument list for the client's prepare function.  There is an
    // immutable reference for each credential to be shown, and an owned
    // value for each credential to be issued.
    let client_show_args = proto_spec.show_creds.iter().map(|c| {
        let id = format_ident!("show_cred_{}", c.id);
        let cred_type = &c.cred_type;
        quote! { #id: &#cred_type, }
    });

    let client_issue_args = proto_spec.issue_creds.iter().map(|c| {
        let id = format_ident!("iss_cred_{}", c.id);
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
            pub fn prepare(rng: &mut (impl CryptoRng + RngCore),
                session_id: &[u8],
                #(#client_show_args)* #(#client_issue_args)* #client_params_arg)
                    -> Result<(Request, ClientState),CMZError> {
                let bp = cmz_basepoints::<Point>();
                let mut cli_proof_sessid: Vec<u8> = Vec::new();
                cli_proof_sessid.extend(b"cli_");
                cli_proof_sessid.extend(session_id);
                let mut iss_proof_sessid: Vec<u8> = Vec::new();
                iss_proof_sessid.extend(b"iss_");
                iss_proof_sessid.extend(session_id);
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
                let id = format_ident!("show_cred_{}", c.id);
                let cred_type = &c.cred_type;
                quote! { let mut #id = #cred_type::default(); }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("iss_cred_{}", c.id);
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
        let rettype = match tot_num_creds {
            0 => quote! { Result<Reply,CMZError> },
            1 => quote! { Result<(Reply, #(#cred_rettypes)*),CMZError> },
            _ => quote! { Result<(Reply, (#(#cred_rettypes),*)),CMZError> },
        };

        // The return value
        let cred_retvals = proto_spec
            .show_creds
            .iter()
            .map(|c| {
                let id = format_ident!("show_cred_{}", c.id);
                quote! { #id }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("iss_cred_{}", c.id);
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
                let id = format_ident!("show_cred_{}", c.id);
                quote! { &mut #id, }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("iss_cred_{}", c.id);
                quote! { &mut #id, }
            }));

        // The return value of the callback
        let fill_creds_params_ret = if has_params {
            quote! { Params }
        } else {
            quote! { () }
        };

        // The assignment of the return value of the callback
        let fill_creds_assign = if has_params {
            quote! { let params = }
        } else {
            quote! {}
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
                let id = format_ident!("show_cred_{}", c.id);
                quote! { &#id, }
            })
            .chain(proto_spec.issue_creds.iter().map(|c| {
                let id = format_ident!("iss_cred_{}", c.id);
                quote! { &#id, }
            }));

        let repf = reply_fields.field_iter();
        let retval = match tot_num_creds {
            0 => quote! { Ok(Reply{#(#repf,)*}) },
            1 => quote! { Ok((Reply{#(#repf,)*}, #(#cred_retvals)*)) },
            _ => quote! { Ok((Reply{#(#repf,)*}, (#(#cred_retvals),*))) },
        };

        quote! {
            pub fn handle<F,A>(rng: &mut (impl CryptoRng + RngCore),
                session_id: &[u8],
                request: Request, fill_creds: F, authorize: A)
                -> #rettype
            where
                F: FnOnce(#(#fill_creds_args)*) ->
                    Result<#fill_creds_params_ret, CMZError>,
                A: FnOnce(#(#authorize_args)*) ->
                    Result<(),CMZError>
            {
                let bp = cmz_basepoints::<Point>();
                let mut cli_proof_sessid: Vec<u8> = Vec::new();
                cli_proof_sessid.extend(b"cli_");
                cli_proof_sessid.extend(session_id);
                let mut iss_proof_sessid: Vec<u8> = Vec::new();
                iss_proof_sessid.extend(b"iss_");
                iss_proof_sessid.extend(session_id);
                #(#cred_decls)*
                #handle_code_pre_fill
                #fill_creds_assign fill_creds(#(#fill_creds_params)*)?;
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
            let id = format_ident!("iss_cred_{}", c.id);
            let cred_type = &c.cred_type;
            quote! { let mut #id = #cred_type::default(); }
        });

        // The type of the returned credentials from finalize
        let cred_rettypes = proto_spec.issue_creds.iter().map(|c| {
            let cred_type = &c.cred_type;
            quote! { #cred_type }
        });

        let rettype = match proto_spec.issue_creds.len() {
            0 => quote! { Result<(),(CMZError,Self)> },
            1 => quote! { Result<#(#cred_rettypes)*,(CMZError,Self)> },
            _ => quote! { Result<(#(#cred_rettypes),*),(CMZError,Self)> },
        };

        // Return value for ClientState's finalize function
        let cred_retvals = proto_spec.issue_creds.iter().map(|c| {
            let id = format_ident!("iss_cred_{}", c.id);
            quote! { #id }
        });

        let retval = match proto_spec.issue_creds.len() {
            0 => quote! { Ok(()) },
            1 => quote! { Ok(#(#cred_retvals)*) },
            _ => quote! { Ok((#(#cred_retvals),*)) },
        };

        quote! {
            impl ClientState {
                pub fn finalize(
                    self,
                    reply: Reply,
                ) -> #rettype {
                    let bp = cmz_basepoints::<Point>();
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
        #[allow(non_snake_case)]
        pub mod #proto_name {
            use super::*;
            use sigma_compiler::*;
            use group::GroupEncoding;

            #group_types
            #params_struct
            #messages
            #cli_proof
            #iss_proof
            #client_side
            #issuer_side
        }
    }
}
