# rsigncode

A Rust implementation of Microsoft Authenticode signing and verification for Windows PE binaries.

`rsigncode` is a from-scratch Rust port of the functionality provided by tools like [`osslsigncode`](https://github.com/mtrojnar/osslsigncode) and Microsoft's `signtool.exe`. It produces and verifies Authenticode signatures embedded in PE files (`.exe`, `.dll`, ...), with support for RFC 3161 and legacy Authenticode timestamping.

## Status

Early development (`0.1.0`). The CLI surface is intentionally close to `osslsigncode` so existing build pipelines port over with minimal changes.

## Installation

From source:

```sh
cargo install --path crates/rsigncode-cli
```

This installs the `rsigncode` binary.

## Usage

### Sign a PE file

```sh
rsigncode sign \
    --in  myapp.exe \
    --out myapp-signed.exe \
    --certs cert.pem \
    --key   key.pem \
    --h sha256 \
    -n "My App" \
    -i "https://example.org/" \
    --ts http://timestamp.digicert.com
```

### Verify a signed file

```sh
rsigncode verify --in myapp-signed.exe --CAfile ca-bundle.pem
```

### Other subcommands

| Command             | Purpose                                                           |
| ------------------- | ----------------------------------------------------------------- |
| `sign`              | Digitally sign a PE file                                          |
| `verify`            | Validate an embedded signature                                    |
| `extract-data`      | Extract the data-to-be-signed digest as PKCS#7                    |
| `extract-signature` | Extract an existing embedded signature                            |
| `attach-signature`  | Attach a pre-made PKCS#7 signature to a PE file                   |
| `remove-signature`  | Strip the signature from a PE file                                |
| `add`               | Add an RFC 3161 / Authenticode timestamp to an already-signed PE  |

Run `rsigncode <command> --help` for the full list of flags per subcommand.

## Building

```sh
cargo build --release
```

The workspace contains two crates:

- `crates/rsigncode` — library (PE parsing, ASN.1, signing, verification, timestamping)
- `crates/rsigncode-cli` — `rsigncode` command-line binary

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
