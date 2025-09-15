use clap::Parser;
use cmz_core::*;
use std::io;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// use CMZ14 (as opposed to the default of µCMZ)
    #[arg(short = '1', long)]
    cmz14: bool,

    /// only generate the client-side code
    #[arg(short, long)]
    client_only: bool,

    /// only generate the issuer-side code
    #[arg(short, long)]
    issuer_only: bool,
}

fn pretty_print(code_str: &str) {
    let parsed_output = syn::parse_file(code_str).unwrap();
    let formatted_output = prettyplease::unparse(&parsed_output);
    println!("{}", formatted_output);
}

fn main() -> ExitCode {
    let args = Args::parse();
    let stdin = io::read_to_string(io::stdin()).unwrap();

    if args.client_only && args.issuer_only {
        eprintln!("client_only and issuer_only cannot be used together");
        return ExitCode::FAILURE;
    };
    let emit_client = !args.issuer_only;
    let emit_issuer = !args.client_only;
    let use_mucmz = !args.cmz14;

    let proto_spec: ProtoSpec = match syn::parse_str(&stdin) {
        Err(_) => {
            eprintln!("Could not parse stdin as a CMZ protocol specification");
            return ExitCode::FAILURE;
        }
        Ok(proto_spec) => proto_spec,
    };

    let output = cmz_core(&proto_spec, use_mucmz, emit_client, emit_issuer);
    pretty_print(&output.to_string());

    ExitCode::SUCCESS
}
