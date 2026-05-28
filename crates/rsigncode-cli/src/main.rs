use std::fs::{self, File};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use cryptographic_message_syntax;
use rsigncode::crypto::certs::KeyMaterial;
use rsigncode::crypto::chain;
use rsigncode::crypto::signing::{self, HashAlgorithm, SigningOptions};
use rsigncode::crypto::timestamp;
use rsigncode::crypto::verify::{self, VerifyOptions};
use rsigncode::format::pe;

#[derive(Parser)]
#[command(name = "rsigncode", about = "Microsoft Authenticode signing tool (Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[command(rename_all = "kebab-case")]
enum Command {
    /// Digitally sign a file
    Sign(SignArgs),
    /// Verify an embedded signature
    Verify(VerifyArgs),
    /// Extract data content to be signed
    ExtractData(ExtractDataArgs),
    /// Extract signature from a previously-signed file
    ExtractSignature(ExtractSignatureArgs),
    /// Attach a signature from a file
    AttachSignature(AttachSignatureArgs),
    /// Remove signature from a file
    RemoveSignature(RemoveSignatureArgs),
    /// Add timestamp or unauthenticated blob to a signed file
    Add(AddArgs),
}

#[derive(clap::Args)]
struct SignArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "out")]
    outfile: PathBuf,
    #[arg(long = "certs", alias = "spc")]
    certs: Option<PathBuf>,
    #[arg(long = "key")]
    key: Option<PathBuf>,
    #[arg(long = "pkcs12")]
    pkcs12: Option<PathBuf>,
    #[arg(long = "ac")]
    ac: Option<PathBuf>,
    #[arg(long = "h", default_value = "sha256")]
    h: String,
    #[arg(short = 'n')]
    n: Option<String>,
    #[arg(short = 'i')]
    i: Option<String>,
    #[arg(long = "ph")]
    ph: bool,
    #[arg(long = "comm")]
    comm: bool,
    #[arg(long = "nest")]
    nest: bool,
    #[arg(long = "pem")]
    pem: bool,
    #[arg(long = "pass")]
    pass: Option<String>,
    #[arg(long = "readpass")]
    readpass: Option<PathBuf>,
    #[arg(short = 't', action = clap::ArgAction::Append)]
    t: Vec<String>,
    #[arg(long = "ts", action = clap::ArgAction::Append)]
    ts: Vec<String>,
    #[arg(long = "time")]
    time: Option<i64>,
    #[arg(long = "verbose")]
    verbose: bool,
    #[arg(long = "add-msi-dse")]
    add_msi_dse: bool,
}

#[derive(clap::Args)]
struct VerifyArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "CAfile")]
    cafile: Option<PathBuf>,
    #[arg(long = "CRLfile")]
    crlfile: Option<PathBuf>,
    #[arg(long = "TSA-CAfile")]
    tsa_cafile: Option<PathBuf>,
    #[arg(long = "TSA-CRLfile")]
    tsa_crlfile: Option<PathBuf>,
    #[arg(long = "require-leaf-hash")]
    require_leaf_hash: Option<String>,
    #[arg(long = "time")]
    time: Option<i64>,
    #[arg(long = "ignore-timestamp")]
    ignore_timestamp: bool,
    #[arg(long = "ignore-cdp")]
    ignore_cdp: bool,
    #[arg(long = "ignore-crl")]
    ignore_crl: bool,
    #[arg(long = "verbose")]
    verbose: bool,
}

#[derive(clap::Args)]
struct ExtractDataArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "out")]
    outfile: PathBuf,
    #[arg(long = "h", default_value = "sha256")]
    h: String,
    #[arg(long = "ph")]
    ph: bool,
    #[arg(long = "pem")]
    pem: bool,
    #[arg(long = "add-msi-dse")]
    add_msi_dse: bool,
}

#[derive(clap::Args)]
struct ExtractSignatureArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "out")]
    outfile: PathBuf,
    #[arg(long = "pem")]
    pem: bool,
}

#[derive(clap::Args)]
struct AttachSignatureArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "out")]
    outfile: PathBuf,
    #[arg(long = "sigin")]
    sigin: PathBuf,
    #[arg(long = "nest")]
    nest: bool,
    #[arg(long = "h", default_value = "sha256")]
    h: String,
    #[arg(long = "CAfile")]
    cafile: Option<PathBuf>,
    #[arg(long = "CRLfile")]
    crlfile: Option<PathBuf>,
    #[arg(long = "time")]
    time: Option<i64>,
    #[arg(long = "add-msi-dse")]
    add_msi_dse: bool,
}

#[derive(clap::Args)]
struct RemoveSignatureArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "out")]
    outfile: PathBuf,
}

#[derive(clap::Args)]
struct AddArgs {
    #[arg(long = "in")]
    infile: PathBuf,
    #[arg(long = "out")]
    outfile: PathBuf,
    #[arg(short = 't', action = clap::ArgAction::Append)]
    t: Vec<String>,
    #[arg(long = "ts", action = clap::ArgAction::Append)]
    ts: Vec<String>,
    #[arg(long = "verbose")]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Sign(args) => cmd_sign(args),
        Command::Verify(args) => cmd_verify(args),
        Command::ExtractData(args) => cmd_extract_data(args),
        Command::ExtractSignature(args) => cmd_extract_signature(args),
        Command::AttachSignature(args) => cmd_attach_signature(args),
        Command::RemoveSignature(args) => cmd_remove_signature(args),
        Command::Add(args) => cmd_add(args),
    }
}

fn cmd_sign(args: SignArgs) -> Result<()> {
    let hash_algo = HashAlgorithm::from_name(&args.h)
        .context("invalid hash algorithm")?;

    let certfile = args.certs.context("--certs required")?;
    let keyfile = args.key.context("--key required")?;

    let mut km = KeyMaterial::from_pem(&certfile, &keyfile)
        .context("failed to load certificates/key")?;

    if let Some(ac) = &args.ac {
        km.add_extra_certs_pem(ac)
            .context("failed to load extra certificates")?;
    }

    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;
    let pe_info = pe::parse_pe(&mut input)
        .context("failed to parse PE file")?;

    let digest = signing::pe_digest(&mut input, &pe_info, hash_algo)
        .context("failed to calculate digest")?;

    let opts = SigningOptions {
        hash_algo,
        program_name: args.n.as_deref(),
        program_url: args.i.as_deref(),
        rfc3161_urls: args.ts.clone(),
        authenticode_urls: args.t.clone(),
    };

    let pkcs7_der = signing::create_authenticode_signature(
        &km.signing_key,
        km.signer_cert.clone(),
        km.extra_certs.clone(),
        &digest,
        &opts,
    )
    .context("failed to create signature")?;

    pe::write_signed_pe(&mut input, &args.outfile, &pe_info, &pkcs7_der)
        .context("failed to write signed PE")?;

    eprintln!("Signed: {:?} -> {:?}", args.infile, args.outfile);
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<()> {
    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;

    let mut opts = VerifyOptions {
        ignore_timestamp: args.ignore_timestamp,
        ignore_cdp: args.ignore_cdp,
        ignore_crl: args.ignore_crl,
        verbose: args.verbose,
        time: args.time,
        require_leaf_hash: args.require_leaf_hash,
        ..Default::default()
    };

    if let Some(ref path) = args.cafile {
        opts.ca_certs = chain::load_pem_certs(path)
            .context("failed to load --CAfile")?;
    }
    if let Some(ref path) = args.tsa_cafile {
        opts.tsa_ca_certs = chain::load_pem_certs(path)
            .context("failed to load --TSA-CAfile")?;
    }

    let result = verify::verify_pe_rich(&mut input, &opts)
        .context("Verification failed")?;

    verify::print_verify_result(&result);

    if result.all_ok() {
        println!("Succeeded");
        Ok(())
    } else {
        bail!("Failed");
    }
}

fn cmd_extract_data(args: ExtractDataArgs) -> Result<()> {
    let hash_algo = HashAlgorithm::from_name(&args.h)
        .context("invalid hash algorithm")?;

    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;
    let pe_info = pe::parse_pe(&mut input)
        .context("failed to parse PE file")?;

    let digest = signing::pe_digest(&mut input, &pe_info, hash_algo)
        .context("failed to calculate digest")?;

    let opts = SigningOptions {
        hash_algo,
        program_name: None,
        program_url: None,
        rfc3161_urls: Vec::new(),
        authenticode_urls: Vec::new(),
    };

    let pkcs7_der = signing::build_extract_data_pkcs7(&digest, &opts)
        .context("failed to build PKCS#7 data content")?;

    if args.pem {
        let pem_data = pem::encode(&pem::Pem::new("PKCS7", pkcs7_der));
        fs::write(&args.outfile, pem_data)
            .with_context(|| format!("failed to write: {:?}", args.outfile))?;
    } else {
        fs::write(&args.outfile, &pkcs7_der)
            .with_context(|| format!("failed to write: {:?}", args.outfile))?;
    }

    eprintln!("Extracted data: {:?} -> {:?}", args.infile, args.outfile);
    Ok(())
}

fn cmd_extract_signature(args: ExtractSignatureArgs) -> Result<()> {
    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;
    let pe_info = pe::parse_pe(&mut input)
        .context("failed to parse PE file")?;

    let sig = pe::extract_signature(&mut input, &pe_info)?
        .ok_or_else(|| anyhow::anyhow!("no signature found"))?;

    if args.pem {
        let pem_data = pem::encode(&pem::Pem::new("PKCS7", sig));
        fs::write(&args.outfile, pem_data)
            .with_context(|| format!("failed to write: {:?}", args.outfile))?;
    } else {
        fs::write(&args.outfile, &sig)
            .with_context(|| format!("failed to write: {:?}", args.outfile))?;
    }

    eprintln!("Extracted signature: {:?} -> {:?}", args.infile, args.outfile);
    Ok(())
}

fn cmd_attach_signature(args: AttachSignatureArgs) -> Result<()> {
    let sig_data = fs::read(&args.sigin)
        .with_context(|| format!("failed to read signature: {:?}", args.sigin))?;

    // Try PEM first, fall back to DER
    let pkcs7_der = if let Ok(pem_data) = pem::parse(&sig_data) {
        pem_data.into_contents()
    } else {
        sig_data
    };

    // Validate the blob is actually parseable PKCS#7
    cryptographic_message_syntax::SignedData::parse_ber(&pkcs7_der)
        .context("--sigin file is not a valid PKCS#7 SignedData")?;

    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;
    let pe_info = pe::parse_pe(&mut input)
        .context("failed to parse PE file")?;

    pe::write_signed_pe(&mut input, &args.outfile, &pe_info, &pkcs7_der)
        .context("failed to write signed PE")?;

    eprintln!(
        "Attached signature: {:?} + {:?} -> {:?}",
        args.infile, args.sigin, args.outfile
    );
    Ok(())
}

fn cmd_remove_signature(args: RemoveSignatureArgs) -> Result<()> {
    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;
    let pe_info = pe::parse_pe(&mut input)
        .context("failed to parse PE file")?;

    pe::write_unsigned_pe(&mut input, &args.outfile, &pe_info)
        .context("failed to remove signature")?;

    eprintln!("Removed signature: {:?} -> {:?}", args.infile, args.outfile);
    Ok(())
}

fn cmd_add(args: AddArgs) -> Result<()> {
    if args.ts.is_empty() && args.t.is_empty() {
        bail!("at least one -t or --ts URL is required");
    }

    let mut input = File::open(&args.infile)
        .with_context(|| format!("failed to open: {:?}", args.infile))?;
    let pe_info = pe::parse_pe(&mut input)
        .context("failed to parse PE file")?;

    let pkcs7_der = pe::extract_signature(&mut input, &pe_info)?
        .ok_or_else(|| anyhow::anyhow!("no signature found — file must be signed first"))?;

    let timestamped = timestamp::add_timestamps(&pkcs7_der, &args.ts, &args.t)
        .context("failed to add timestamps")?;

    pe::write_signed_pe(&mut input, &args.outfile, &pe_info, &timestamped)
        .context("failed to write output PE")?;

    eprintln!("Added timestamp: {:?} -> {:?}", args.infile, args.outfile);
    Ok(())
}
