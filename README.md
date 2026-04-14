# PoCX Key Helper

A small, offline, cross-platform GUI tool to derive the **first BIP84 receive address** for the [Bitcoin-PoCX](https://github.com/Bitcoin-PoCX) network from either a 24-word BIP39 mnemonic or an extended private key (`xprv`).

Primary use case: plot the same storage once and reuse it on **both mainnet and testnet**. The tool shows the matching address on each network, and — gated behind explicit warnings — the corresponding WIF plus a ready-to-paste `bitcoin-cli importdescriptors` command.

## Screenshot

*(run it once and drop a PNG here)*

## Features

- **24-word mnemonic → first native-segwit address** at `m/84'/0'/0'/0/0`, with optional BIP39 passphrase
- **`xprv` input** as an alternative — accepts either a master xprv (depth 0) or a BIP84 account xprv (depth 3); the intermediate xprv derived from a mnemonic is never displayed
- **Two tabs** — *Mainnet → Testnet* and *Testnet → Mainnet* — swap which network is primary
- **Advanced section** (collapsed by default) shows the other network's address plus the WIF and a full `importdescriptors` command with a BIP-380 checksum
- **Offline-only**: no network code compiled in, no file writes, no logging
- **Safety gates**: masked input, explicit risk-acknowledgement checkbox, reveal-to-show, clipboard auto-clears 30 s after any copy, all secret buffers are `zeroize`d on drop and on exit
- Single binary; no runtime dependencies beyond system OpenGL (`libGL`) on Linux

## Quick start

### Run a release binary

Grab the archive for your platform from the [Releases](../../releases) page, extract, and run the binary. On Windows, double-click `keyhelper.exe`. On macOS/Linux, run `./keyhelper` from a terminal.

### Build from source

Requires Rust stable.

```bash
git clone <repo>
cd keyhelper
cargo run --release
```

Linux build dependencies (Debian/Ubuntu):

```bash
sudo apt-get install -y \
  libgl1-mesa-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libssl-dev libfontconfig1-dev libgtk-3-dev
```

## Usage

1. Choose an input mode: **24-word mnemonic** or **xprv**.
2. Paste the seed or xprv. (Masked by default; tick *Show* to reveal.)
3. Optional: enter a BIP39 passphrase.
4. Click **Derive**. The primary network's address appears immediately — this is the address you plot.
5. For the other network's address and the private key, expand **Advanced**, read the warning, tick the acknowledgement, and click **Reveal**.

The `importdescriptors` command produced in the Advanced section is a single-key `wpkh(WIF)` descriptor with a BIP-380 checksum. Pipe it directly to `bitcoin-cli` (or use the RPC) on the matching network.

## Security model

The tool is designed to be run on an **air-gapped machine**. It performs no network I/O and writes nothing to disk. Nevertheless:

- Treat **every WIF** it produces as your full mainnet private key. Mainnet and testnet WIFs differ only by a one-byte prefix (`0x80` vs `0xEF`); a testnet WIF can be converted into a mainnet WIF in seconds and used to spend real funds.
- Never post a testnet WIF in public chats, bug reports, or screenshots.
- Clipboard contents are cleared 30 s after any copy. Closing the app clears all in-memory secrets.
- The binary is unsigned unless you sign it yourself. If you distribute builds, sign them.

## Network parameters

Pulled from `bitcoin-pocx/src/kernel/chainparams.cpp`:

| | Mainnet | Testnet |
|---|---|---|
| bech32 HRP | `pocx` | `tpocx` |
| WIF prefix | `0x80` | `0xEF` |
| `EXT_SECRET_KEY` (xprv) | `0x0488ADE4` | `0x04358394` |

The xprv version bytes match upstream Bitcoin, so standard BIP32 libraries parse PoCX xprvs without patching.

## Derivation path

Fixed at **`m/84'/0'/0'/0/0`** (BIP84, first external receive). Coin type `0` is deliberate: PoCX does not claim a separate SLIP-44 number, so the same 24 words recover the same keys on a stock Bitcoin wallet that allows custom HRP/version-byte overrides. This preserves an independent recovery path.

## Project layout

```
keyhelper/
├── Cargo.toml
├── src/
│   ├── main.rs      # eframe/egui GUI
│   └── derive.rs    # BIP39/BIP32/BIP84, bech32, WIF, BIP-380 checksum, unit test
└── .github/workflows/
    ├── ci.yml       # fmt + clippy + test + cargo audit
    └── release.yml  # multi-target release build on v* tags
```

## Testing

```bash
cargo test
```

Covers:

- Mainnet/testnet address HRPs and witness programs
- Mainnet/testnet WIFs decode to the same private key
- BIP-380 checksum in the import command self-validates
- Roundtrip through master xprv (depth 0) and BIP84 account xprv (depth 3) produce identical output

## Release process

Push an annotated tag matching `v*`:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The release workflow builds for:

| Target | Runner |
|---|---|
| `x86_64-pc-windows-msvc` | windows-latest |
| `x86_64-apple-darwin` | macos-latest (cross-compiled from arm64) |
| `aarch64-apple-darwin` | macos-latest (Apple Silicon) |
| `x86_64-unknown-linux-gnu` | ubuntu-latest |
| `aarch64-unknown-linux-gnu` | ubuntu-latest via `cross` |

Each target produces a `.zip` (Windows) or `.tar.gz` (Unix) with a SHA-256 sidecar. All artifacts attach to a **draft** GitHub Release; review and publish manually.

MUSL targets are intentionally omitted: eframe/egui requires dynamic `libGL`/X11, which defeats the point of a MUSL build.

## License

*(add before first public release)*

## Disclaimer

This software is provided as-is. The authors accept no liability for lost funds. Verify any address and command the tool produces before using it with real value. Run on an air-gapped machine whenever possible.
