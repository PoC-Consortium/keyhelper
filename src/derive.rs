use bip32::{ChildNumber, DerivationPath, XPrv};
use bip39::Mnemonic;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use zeroize::Zeroize;

pub struct Derived {
    pub mainnet_address: String,
    pub testnet_address: String,
    pub mainnet_wif: String,
    pub testnet_wif: String,
    pub mainnet_import: String,
    pub testnet_import: String,
    pub path: String,
}

impl Drop for Derived {
    fn drop(&mut self) {
        self.mainnet_wif.zeroize();
        self.testnet_wif.zeroize();
        self.mainnet_import.zeroize();
        self.testnet_import.zeroize();
    }
}

const MAINNET_HRP: &str = "pocx";
const TESTNET_HRP: &str = "tpocx";
const MAINNET_WIF_PREFIX: u8 = 0x80;
const TESTNET_WIF_PREFIX: u8 = 0xEF;
const FULL_PATH: &str = "m/84'/0'/0'/0/0";

pub fn derive_from_mnemonic(mnemonic_str: &str, passphrase: &str) -> Result<Derived, String> {
    let normalized = mnemonic_str.trim().to_lowercase();
    let mnemonic =
        Mnemonic::parse_normalized(&normalized).map_err(|e| format!("Invalid mnemonic: {e}"))?;

    let mut seed_bytes = mnemonic.to_seed(passphrase);
    let xprv = XPrv::new(seed_bytes).map_err(|e| format!("Master key error: {e}"))?;
    seed_bytes.zeroize();

    let path: DerivationPath = FULL_PATH.parse().map_err(|e| format!("Path error: {e}"))?;
    finalize(xprv, path.as_ref(), FULL_PATH.to_string())
}

pub fn derive_from_xprv(xprv_str: &str) -> Result<Derived, String> {
    let xprv = XPrv::from_str(xprv_str.trim()).map_err(|e| format!("Invalid xprv: {e}"))?;
    let depth = xprv.attrs().depth;

    let (remaining, shown_path): (Vec<ChildNumber>, String) = match depth {
        0 => {
            let path: DerivationPath = FULL_PATH.parse().map_err(|e| format!("Path error: {e}"))?;
            (
                path.as_ref().to_vec(),
                format!("{FULL_PATH}  (from master xprv)"),
            )
        }
        3 => (
            vec![
                ChildNumber::new(0, false).map_err(|e| format!("Child error: {e}"))?,
                ChildNumber::new(0, false).map_err(|e| format!("Child error: {e}"))?,
            ],
            "<account>/0/0  (from BIP84 account xprv)".to_string(),
        ),
        _ => {
            return Err(format!(
                "Unsupported xprv depth {depth}. Expected master (depth 0) or BIP84 account xprv (depth 3)."
            ));
        }
    };

    finalize(xprv, &remaining, shown_path)
}

pub fn validate_mnemonic(mnemonic_str: &str) -> bool {
    let normalized = mnemonic_str.trim().to_lowercase();
    Mnemonic::parse_normalized(&normalized).is_ok()
}

fn finalize(
    mut child: XPrv,
    path_children: &[ChildNumber],
    shown_path: String,
) -> Result<Derived, String> {
    for c in path_children {
        child = child
            .derive_child(*c)
            .map_err(|e| format!("Derive error: {e}"))?;
    }

    let mut priv_bytes: [u8; 32] = child.private_key().to_bytes().into();
    let pubkey_bytes = child.public_key().to_bytes();
    let h160 = hash160(&pubkey_bytes);

    let mainnet_address = encode_p2wpkh(MAINNET_HRP, &h160)?;
    let testnet_address = encode_p2wpkh(TESTNET_HRP, &h160)?;
    let mainnet_wif = encode_wif(MAINNET_WIF_PREFIX, &priv_bytes, true);
    let testnet_wif = encode_wif(TESTNET_WIF_PREFIX, &priv_bytes, true);

    priv_bytes.zeroize();

    let mainnet_import = build_import_command(&mainnet_wif);
    let testnet_import = build_import_command(&testnet_wif);

    Ok(Derived {
        mainnet_address,
        testnet_address,
        mainnet_wif,
        testnet_wif,
        mainnet_import,
        testnet_import,
        path: shown_path,
    })
}

fn build_import_command(wif: &str) -> String {
    let body = format!("wpkh({wif})");
    let cksum = descriptor_checksum(&body);
    format!(
        "importdescriptors '[{{\"desc\": \"{body}#{cksum}\", \"timestamp\": \"now\", \"label\": \"pocx-keyhelper\"}}]'"
    )
}

// BIP-380 descriptor checksum
fn descriptor_checksum(desc: &str) -> String {
    const INPUT_CHARSET: &str =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    let input_chars: Vec<char> = INPUT_CHARSET.chars().collect();
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u32 = 0;

    for ch in desc.chars() {
        let pos = match input_chars.iter().position(|&x| x == ch) {
            Some(p) => p as u64,
            None => return String::from("BAD_CHAR"),
        };
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;

    let mut out = String::with_capacity(8);
    for i in 0..8 {
        let idx = ((c >> (5 * (7 - i))) & 31) as usize;
        out.push(CHECKSUM_CHARSET[idx] as char);
    }
    out
}

fn polymod(mut c: u64, val: u64) -> u64 {
    let c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if c0 & 1 != 0 {
        c ^= 0xf5dee51989;
    }
    if c0 & 2 != 0 {
        c ^= 0xa9fdca3312;
    }
    if c0 & 4 != 0 {
        c ^= 0x1bab10e32d;
    }
    if c0 & 8 != 0 {
        c ^= 0x3706b1677a;
    }
    if c0 & 16 != 0 {
        c ^= 0x644d626ffd;
    }
    c
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

fn encode_p2wpkh(hrp_str: &str, program: &[u8; 20]) -> Result<String, String> {
    let hrp = bech32::Hrp::parse(hrp_str).map_err(|e| format!("HRP error: {e}"))?;
    bech32::segwit::encode_v0(hrp, program).map_err(|e| format!("bech32 error: {e}"))
}

fn encode_wif(prefix: u8, privkey: &[u8; 32], compressed: bool) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(prefix);
    payload.extend_from_slice(privkey);
    if compressed {
        payload.push(0x01);
    }
    let wif = bs58::encode(&payload).with_check().into_string();
    payload.zeroize();
    wif
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical BIP39 test vector.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// End-to-end roundtrip:
    ///   1. mnemonic -> addresses + WIFs + import commands
    ///   2. master xprv (reconstructed from same mnemonic) -> must reproduce identical output
    ///   3. account xprv at m/84'/0'/0' -> must also reproduce identical output
    ///   4. mainnet and testnet addresses must share one 20-byte witness program
    ///   5. mainnet and testnet WIFs must decode to the same 32-byte private key
    ///      (only prefix byte differs; swapping 0xEF <-> 0x80 converts between networks)
    ///   6. BIP-380 checksum in the import command must validate against itself
    #[test]
    fn roundtrip_from_mnemonic_and_xprv() {
        let from_mnemonic = derive_from_mnemonic(TEST_MNEMONIC, "").expect("mnemonic derive");

        // --- (1) HRP sanity and address structure ---
        assert!(
            from_mnemonic.mainnet_address.starts_with("pocx1q"),
            "mainnet HRP/witness-v0 prefix wrong: {}",
            from_mnemonic.mainnet_address
        );
        assert!(
            from_mnemonic.testnet_address.starts_with("tpocx1q"),
            "testnet HRP/witness-v0 prefix wrong: {}",
            from_mnemonic.testnet_address
        );

        // --- (4) same witness program on both networks ---
        let (hrp_m, _ver_m, prog_m) =
            bech32::segwit::decode(&from_mnemonic.mainnet_address).expect("mainnet bech32");
        let (hrp_t, _ver_t, prog_t) =
            bech32::segwit::decode(&from_mnemonic.testnet_address).expect("testnet bech32");
        assert_eq!(hrp_m.as_str(), "pocx");
        assert_eq!(hrp_t.as_str(), "tpocx");
        assert_eq!(prog_m.len(), 20);
        assert_eq!(
            prog_m, prog_t,
            "mainnet and testnet addresses must encode the same 20-byte program"
        );

        // --- (5) WIFs decode to the same private key, only prefix differs ---
        let m = bs58::decode(&from_mnemonic.mainnet_wif)
            .with_check(None)
            .into_vec()
            .expect("mainnet WIF base58check");
        let t = bs58::decode(&from_mnemonic.testnet_wif)
            .with_check(None)
            .into_vec()
            .expect("testnet WIF base58check");
        assert_eq!(m.len(), 34, "compressed WIF must be 1 + 32 + 1 bytes");
        assert_eq!(t.len(), 34);
        assert_eq!(m[0], 0x80, "mainnet WIF prefix");
        assert_eq!(t[0], 0xEF, "testnet WIF prefix");
        assert_eq!(m[33], 0x01, "compressed flag");
        assert_eq!(t[33], 0x01);
        assert_eq!(
            m[1..33],
            t[1..33],
            "the private key bytes must be identical across networks"
        );

        // --- (6) self-validating BIP-380 checksum in the import command ---
        for cmd in [&from_mnemonic.mainnet_import, &from_mnemonic.testnet_import] {
            let (body, cksum) = extract_descriptor_body_and_checksum(cmd);
            assert_eq!(
                descriptor_checksum(&body),
                cksum,
                "BIP-380 checksum mismatch in import command: {cmd}"
            );
        }

        // --- (2) roundtrip via master xprv (depth 0) ---
        let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master = XPrv::new(seed).unwrap();
        let master_xprv_str = master.to_string(bip32::Prefix::XPRV).to_string();

        let from_master = derive_from_xprv(&master_xprv_str).expect("master xprv derive");
        assert_eq!(from_master.mainnet_address, from_mnemonic.mainnet_address);
        assert_eq!(from_master.testnet_address, from_mnemonic.testnet_address);
        assert_eq!(from_master.mainnet_wif, from_mnemonic.mainnet_wif);
        assert_eq!(from_master.testnet_wif, from_mnemonic.testnet_wif);

        // --- (3) roundtrip via BIP84 account xprv (depth 3) ---
        let account_path: DerivationPath = "m/84'/0'/0'".parse().unwrap();
        let mut account = master.clone();
        for c in account_path.as_ref() {
            account = account.derive_child(*c).unwrap();
        }
        let account_xprv_str = account.to_string(bip32::Prefix::XPRV).to_string();

        let from_account = derive_from_xprv(&account_xprv_str).expect("account xprv derive");
        assert_eq!(from_account.mainnet_address, from_mnemonic.mainnet_address);
        assert_eq!(from_account.testnet_address, from_mnemonic.testnet_address);
        assert_eq!(from_account.mainnet_wif, from_mnemonic.mainnet_wif);
        assert_eq!(from_account.testnet_wif, from_mnemonic.testnet_wif);
    }

    fn extract_descriptor_body_and_checksum(cmd: &str) -> (String, String) {
        // cmd looks like: importdescriptors '[{"desc": "wpkh(WIF)#CKSUM", ...}]'
        let start = cmd.find("\"desc\": \"").expect("desc field") + "\"desc\": \"".len();
        let rest = &cmd[start..];
        let end = rest.find('"').expect("desc end quote");
        let full = &rest[..end];
        let hash = full.rfind('#').expect("# checksum separator");
        (full[..hash].to_string(), full[hash + 1..].to_string())
    }
}
