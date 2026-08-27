use std::{env, path::PathBuf, str::FromStr};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    signers::{
        ledger::{HDPath as LedgerHDPath, LedgerSigner},
        local::PrivateKeySigner,
        trezor::{HDPath as TrezorHDPath, TrezorSigner},
    },
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use incognito_safe::{
    artifact::{DeploymentArtifact, load_artifact, write_unique_artifact},
    config::{SafeConfig, load_config},
    deployment::{
        DeploymentReceipt, Prediction, SAFE_VERSION, SafeVariant, deploy_safe, fetch_safe_config,
        generate_seed, parse_seed, predict_safe,
    },
};
use serde_json::json;
use zeroize::Zeroizing;

const DEFAULT_PRIVATE_KEY_ENV: &str = "INC_SAFE_PRIVATE_KEY";
const MAX_LEDGER_ACCOUNT: usize = (1 << 31) - 1;
const MAX_TREZOR_INDEX: usize = (1 << 31) - 1;

#[derive(Debug, Parser)]
#[command(
    name = "incognito-safe",
    version,
    about = "Generate and deploy counterfactual Safe v1.5.0 addresses",
    long_about = None
)]
struct Cli {
    /// EVM JSON-RPC override. Prefer `ETH_RPC_URL` to avoid shell history.
    #[arg(long, global = true, env = "ETH_RPC_URL")]
    rpc_url: Option<String>,

    /// Network whose public RPC and chain ID should be used.
    /// Defaults to Ethereum when no RPC override is provided.
    #[arg(long, global = true, value_enum)]
    chain: Option<ChainArg>,

    /// Safe singleton initialization strategy (default: portable).
    #[arg(long, global = true, value_enum)]
    variant: Option<VariantArg>,

    /// Bind the CREATE2 address to this chain ID instead of making it replayable cross-chain.
    #[arg(long, global = true)]
    chain_specific: bool,

    /// Emit machine-readable JSON to stdout.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum VariantArg {
    /// Recommended: Safe on chain 1, `SafeL2` on every other EVM chain.
    #[default]
    Portable,
    /// Always initialize the proxy against the L1 Safe singleton.
    L1,
    /// Always initialize the proxy against the `SafeL2` singleton.
    L2,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ChainArg {
    /// Ethereum mainnet (chain ID 1).
    #[default]
    Ethereum,
    /// Ethereum Sepolia (chain ID 11155111).
    EthereumSepolia,
    /// World Chain mainnet (chain ID 480).
    World,
    /// OP Mainnet (chain ID 10).
    Optimism,
    /// OP Sepolia (chain ID 11155420).
    OptimismSepolia,
    /// Base mainnet (chain ID 8453).
    Base,
    /// Base Sepolia (chain ID 84532).
    BaseSepolia,
    /// Gnosis Chain (chain ID 100).
    Gnosis,
    /// Polygon proof-of-stake network (chain ID 137).
    Polygon,
}

impl ChainArg {
    const fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self::Ethereum),
            11_155_111 => Some(Self::EthereumSepolia),
            480 => Some(Self::World),
            10 => Some(Self::Optimism),
            11_155_420 => Some(Self::OptimismSepolia),
            8_453 => Some(Self::Base),
            84_532 => Some(Self::BaseSepolia),
            100 => Some(Self::Gnosis),
            137 => Some(Self::Polygon),
            _ => None,
        }
    }

    const fn chain_id(self) -> u64 {
        match self {
            Self::Ethereum => 1,
            Self::EthereumSepolia => 11_155_111,
            Self::World => 480,
            Self::Optimism => 10,
            Self::OptimismSepolia => 11_155_420,
            Self::Base => 8_453,
            Self::BaseSepolia => 84_532,
            Self::Gnosis => 100,
            Self::Polygon => 137,
        }
    }

    const fn public_rpc(self) -> &'static str {
        match self {
            Self::Ethereum => "https://ethereum-rpc.publicnode.com",
            Self::EthereumSepolia => "https://ethereum-sepolia-rpc.publicnode.com",
            Self::World => "https://worldchain-mainnet.g.alchemy.com/public",
            Self::Optimism => "https://mainnet.optimism.io",
            Self::OptimismSepolia => "https://sepolia.optimism.io",
            Self::Base => "https://mainnet.base.org",
            Self::BaseSepolia => "https://sepolia.base.org",
            Self::Gnosis => "https://rpc.gnosischain.com",
            Self::Polygon => "https://polygon.drpc.org",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Ethereum => "Ethereum",
            Self::EthereumSepolia => "Ethereum Sepolia",
            Self::World => "World Chain",
            Self::Optimism => "OP Mainnet",
            Self::OptimismSepolia => "OP Sepolia",
            Self::Base => "Base",
            Self::BaseSepolia => "Base Sepolia",
            Self::Gnosis => "Gnosis Chain",
            Self::Polygon => "Polygon PoS",
        }
    }
}

#[derive(Debug)]
struct RpcSelection {
    url: String,
    expected_chain_id: Option<u64>,
    description: String,
}

fn select_rpc(
    rpc_override: Option<&str>,
    chain: Option<ChainArg>,
    artifact_chain_id: Option<u64>,
) -> Result<RpcSelection> {
    if let (Some(selected), Some(artifact_chain_id)) = (chain, artifact_chain_id) {
        ensure!(
            selected.chain_id() == artifact_chain_id,
            "selected {} chain ID {} does not match deployment artifact chain ID {artifact_chain_id}",
            selected.name(),
            selected.chain_id()
        );
    }

    if let Some(url) = rpc_override {
        return Ok(RpcSelection {
            url: url.to_owned(),
            expected_chain_id: artifact_chain_id.or_else(|| chain.map(ChainArg::chain_id)),
            description: chain.map_or_else(
                || "custom RPC".to_owned(),
                |selected| format!("custom RPC for {}", selected.name()),
            ),
        });
    }

    let artifact_chain = artifact_chain_id.and_then(ChainArg::from_chain_id);
    ensure!(
        artifact_chain_id.is_none() || artifact_chain.is_some() || chain.is_some(),
        "deployment artifact chain ID {} has no built-in public RPC; set ETH_RPC_URL or pass --rpc-url",
        artifact_chain_id.unwrap_or_default()
    );
    let selected = chain.or(artifact_chain).unwrap_or_default();
    Ok(RpcSelection {
        url: selected.public_rpc().to_owned(),
        expected_chain_id: Some(selected.chain_id()),
        description: format!("built-in {} public RPC", selected.name()),
    })
}

impl From<VariantArg> for SafeVariant {
    fn from(value: VariantArg) -> Self {
        match value {
            VariantArg::Portable => Self::Portable,
            VariantArg::L1 => Self::L1,
            VariantArg::L2 => Self::L2,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a cryptographically random seed and its unoccupied Safe address.
    Generate {
        #[command(flatten)]
        source: ConfigSource,
        /// Directory in which to save the unique deployment artifact.
        #[arg(long, value_name = "DIR", default_value = ".")]
        output_dir: PathBuf,
    },
    /// Recompute a Safe address from an existing seed without sending a transaction.
    Predict {
        /// Exact 32-byte seed emitted by `generate`.
        #[arg(long)]
        seed: String,
        #[command(flatten)]
        source: ConfigSource,
    },
    /// Atomically deploy and initialize the Safe at its predicted address.
    Deploy {
        /// Exact 32-byte seed emitted by `generate`.
        #[arg(long, required_unless_present = "file", requires = "deploy_config")]
        seed: Option<String>,
        #[command(flatten)]
        source: DeployConfigSource,
        /// Saved deployment artifact emitted by `generate`.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["seed", "config", "from_safe"]
        )]
        file: Option<PathBuf>,
        /// Sign with a Ledger using the Ledger Live derivation path.
        #[arg(long, conflicts_with_all = ["private_key_env", "trezor"])]
        ledger: bool,
        /// Ledger Live account index (path m/44'/60'/<INDEX>'/0/0).
        #[arg(long, value_name = "INDEX", requires = "ledger")]
        ledger_account: Option<usize>,
        /// Sign with a Trezor using its standard Ethereum derivation path.
        #[arg(long, conflicts_with_all = ["private_key_env", "ledger"])]
        trezor: bool,
        /// Trezor address index (path m/44'/60'/0'/0/<INDEX>).
        #[arg(long, value_name = "INDEX", requires = "trezor")]
        trezor_index: Option<usize>,
        /// Private-key environment variable (default: `INC_SAFE_PRIVATE_KEY`).
        #[arg(long, value_name = "NAME", conflicts_with_all = ["ledger", "trezor"])]
        private_key_env: Option<String>,
    },
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct ConfigSource {
    /// YAML file containing `signers` and `threshold`.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Existing Safe-compatible contract whose owners and threshold should be cloned.
    #[arg(long, value_name = "ADDRESS")]
    from_safe: Option<Address>,
}

#[derive(Args, Debug)]
#[group(id = "deploy_config", required = false, multiple = false)]
struct DeployConfigSource {
    /// YAML file containing `signers` and `threshold`.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Existing Safe-compatible contract whose owners and threshold should be cloned.
    #[arg(long, value_name = "ADDRESS")]
    from_safe: Option<Address>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let mut deployment_artifact = match &cli.command {
        Command::Deploy {
            file: Some(path), ..
        } => Some(load_artifact(path)?),
        _ => None,
    };
    let artifact_chain_id = deployment_artifact
        .as_ref()
        .map(|artifact| artifact.chain_id);
    let rpc = select_rpc(cli.rpc_url.as_deref(), cli.chain, artifact_chain_id)?;
    eprintln!("using {}", rpc.description);
    let read_provider =
        ProviderBuilder::new().connect_http(rpc.url.parse().context("invalid RPC URL")?);
    let actual_chain_id = read_provider
        .get_chain_id()
        .await
        .context("failed to query RPC chain ID")?;
    if let Some(expected_chain_id) = rpc.expected_chain_id {
        ensure!(
            actual_chain_id == expected_chain_id,
            "RPC chain ID {actual_chain_id} does not match selected chain ID {expected_chain_id}"
        );
    }

    match cli.command {
        Command::Generate { source, output_dir } => {
            generate_command(
                &read_provider,
                source,
                &output_dir,
                cli.variant.unwrap_or_default().into(),
                cli.chain_specific,
                cli.json,
            )
            .await?;
        }
        Command::Predict { seed, source } => {
            predict_command(
                &read_provider,
                source,
                &seed,
                cli.variant.unwrap_or_default().into(),
                cli.chain_specific,
                cli.json,
            )
            .await?;
        }
        Command::Deploy {
            seed,
            source,
            file: _,
            ledger,
            ledger_account,
            trezor,
            trezor_index,
            private_key_env,
        } => {
            let deployer_signer = select_deployer_signer(
                ledger,
                ledger_account,
                trezor,
                trezor_index,
                private_key_env,
            )?;
            deploy_command(
                &read_provider,
                &rpc.url,
                source,
                seed.as_deref(),
                deployment_artifact.take(),
                cli.variant,
                cli.chain_specific,
                deployer_signer,
                cli.json,
            )
            .await?;
        }
    }
    Ok(())
}

async fn generate_command<P: Provider>(
    provider: &P,
    source: ConfigSource,
    output_dir: &std::path::Path,
    variant: SafeVariant,
    chain_specific: bool,
    json_output: bool,
) -> Result<()> {
    let config = resolve_config(provider, source).await?;
    let seed = generate_seed()?;
    let prediction = predict_safe(provider, &config, seed, variant, chain_specific).await?;
    let occupied = !provider.get_code_at(prediction.address).await?.is_empty();
    ensure!(
        !occupied,
        "cryptographically improbable address collision at {}; generate again",
        prediction.address
    );
    let artifact = DeploymentArtifact::from_prediction(&config, &prediction)?;
    let artifact_path = write_unique_artifact(output_dir, &artifact)?;
    print_prediction(
        &prediction,
        &config,
        false,
        Some(&artifact_path),
        json_output,
    )
}

async fn predict_command<P: Provider>(
    provider: &P,
    source: ConfigSource,
    seed: &str,
    variant: SafeVariant,
    chain_specific: bool,
    json_output: bool,
) -> Result<()> {
    let config = resolve_config(provider, source).await?;
    let prediction = predict_safe(
        provider,
        &config,
        parse_seed(seed)?,
        variant,
        chain_specific,
    )
    .await?;
    let occupied = !provider.get_code_at(prediction.address).await?.is_empty();
    print_prediction(&prediction, &config, occupied, None, json_output)
}

#[allow(clippy::too_many_arguments)]
async fn deploy_command<P: Provider>(
    read_provider: &P,
    rpc_url: &str,
    source: DeployConfigSource,
    seed: Option<&str>,
    artifact: Option<DeploymentArtifact>,
    requested_variant: Option<VariantArg>,
    requested_chain_specific: bool,
    deployer_signer: DeployerSigner,
    json_output: bool,
) -> Result<()> {
    let (config, seed, variant, chain_specific) = if let Some(artifact) = &artifact {
        let artifact_variant = artifact.safe_variant()?;
        if let Some(requested_variant) = requested_variant {
            ensure!(
                SafeVariant::from(requested_variant) == artifact_variant,
                "--variant does not match the saved deployment artifact"
            );
        }
        ensure!(
            !requested_chain_specific || artifact.chain_specific,
            "--chain-specific does not match the saved deployment artifact"
        );
        (
            artifact.config()?,
            artifact.seed,
            artifact_variant,
            artifact.chain_specific,
        )
    } else {
        (
            resolve_deploy_config(read_provider, source).await?,
            parse_seed(seed.context("--seed is required without --file")?)?,
            requested_variant.unwrap_or_default().into(),
            requested_chain_specific,
        )
    };
    let prediction = predict_safe(read_provider, &config, seed, variant, chain_specific).await?;
    if let Some(artifact) = &artifact {
        artifact.verify_prediction(&prediction)?;
        eprintln!("verified deployment artifact for {}", prediction.address);
    }

    let (wallet, deployer, signer_description) =
        deployment_wallet(deployer_signer, prediction.chain_id).await?;
    eprintln!(
        "deploying Safe v{SAFE_VERSION} at {} on chain {} from {deployer} using {signer_description}",
        prediction.address, prediction.chain_id,
    );
    let signed_provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().context("invalid RPC URL")?);
    let receipt = deploy_safe(&signed_provider, &config, &prediction).await?;
    print_deployment(&prediction, &config, &receipt, json_output)
}

fn ledger_live_path(account: usize) -> Result<LedgerHDPath> {
    ensure!(
        account <= MAX_LEDGER_ACCOUNT,
        "Ledger account index must be at most {MAX_LEDGER_ACCOUNT}"
    );
    Ok(LedgerHDPath::LedgerLive(account))
}

fn trezor_path(index: usize) -> Result<TrezorHDPath> {
    ensure!(
        index <= MAX_TREZOR_INDEX,
        "Trezor address index must be at most {MAX_TREZOR_INDEX}"
    );
    Ok(TrezorHDPath::TrezorLive(index))
}

#[derive(Debug)]
enum DeployerSigner {
    Ledger { account: usize },
    Trezor { index: usize },
    PrivateKeyEnv(String),
}

fn select_deployer_signer(
    use_ledger: bool,
    ledger_account: Option<usize>,
    use_trezor: bool,
    trezor_index: Option<usize>,
    private_key_env: Option<String>,
) -> Result<DeployerSigner> {
    ensure!(
        !(use_ledger && use_trezor),
        "--ledger conflicts with --trezor"
    );

    if use_ledger {
        ensure!(
            private_key_env.is_none() && trezor_index.is_none(),
            "--ledger conflicts with Trezor and private-key options"
        );
        return Ok(DeployerSigner::Ledger {
            account: ledger_account.unwrap_or(0),
        });
    }

    if use_trezor {
        ensure!(
            private_key_env.is_none() && ledger_account.is_none(),
            "--trezor conflicts with Ledger and private-key options"
        );
        return Ok(DeployerSigner::Trezor {
            index: trezor_index.unwrap_or(0),
        });
    }

    ensure!(
        ledger_account.is_none(),
        "--ledger-account requires --ledger"
    );
    ensure!(trezor_index.is_none(), "--trezor-index requires --trezor");
    Ok(DeployerSigner::PrivateKeyEnv(
        private_key_env.unwrap_or_else(|| DEFAULT_PRIVATE_KEY_ENV.to_owned()),
    ))
}

async fn deployment_wallet(
    deployer_signer: DeployerSigner,
    chain_id: u64,
) -> Result<(EthereumWallet, Address, String)> {
    match deployer_signer {
        DeployerSigner::Ledger { account } => {
            let path = ledger_live_path(account)?;
            let path_display = path.to_string();
            eprintln!(
                "connecting to Ledger at {path_display}; unlock it and open the Ethereum app"
            );
            let signer = LedgerSigner::new(path, Some(chain_id))
                .await
                .with_context(|| {
                    "failed to connect to Ledger; unlock it, open the Ethereum app, and check USB access"
                })?;
            let deployer = signer
                .get_address()
                .await
                .context("failed to read the Ethereum address from Ledger")?;
            Ok((
                EthereumWallet::from(signer),
                deployer,
                format!("Ledger Live path {path_display}"),
            ))
        }
        DeployerSigner::Trezor { index } => {
            let path = trezor_path(index)?;
            let path_display = path.to_string();
            eprintln!(
                "connecting to Trezor at {path_display}; unlock it and follow device prompts"
            );
            let signer = TrezorSigner::new(path, Some(chain_id))
                .await
                .with_context(|| {
                    "failed to connect to Trezor; connect and unlock exactly one device and check USB access"
                })?;
            let deployer = signer
                .get_address()
                .await
                .context("failed to read the Ethereum address from Trezor")?;
            Ok((
                EthereumWallet::from(signer),
                deployer,
                format!("Trezor path {path_display}"),
            ))
        }
        DeployerSigner::PrivateKeyEnv(env_name) => {
            validate_env_name(&env_name)?;
            let secret = Zeroizing::new(env::var(&env_name).with_context(|| {
                format!("private-key environment variable `{env_name}` is not set")
            })?);
            let signer = PrivateKeySigner::from_str(&secret)
                .with_context(|| format!("`{env_name}` is not a valid secp256k1 private key"))?;
            let deployer = signer.address();
            Ok((
                EthereumWallet::from(signer),
                deployer,
                format!("private key from `{env_name}`"),
            ))
        }
    }
}

async fn resolve_config<P: Provider>(provider: &P, source: ConfigSource) -> Result<SafeConfig> {
    match (source.config, source.from_safe) {
        (Some(path), None) => load_config(&path),
        (None, Some(address)) => fetch_safe_config(provider, address).await,
        _ => unreachable!("clap enforces exactly one config source"),
    }
}

async fn resolve_deploy_config<P: Provider>(
    provider: &P,
    source: DeployConfigSource,
) -> Result<SafeConfig> {
    match (source.config, source.from_safe) {
        (Some(path), None) => load_config(&path),
        (None, Some(address)) => fetch_safe_config(provider, address).await,
        _ => unreachable!("clap enforces exactly one deploy config source without --file"),
    }
}

fn validate_env_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty(),
        "private-key environment variable name cannot be empty"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()),
        "private-key environment variable name may contain only ASCII letters, digits, and underscore"
    );
    Ok(())
}

fn print_prediction(
    prediction: &Prediction,
    config: &SafeConfig,
    occupied: bool,
    deployment_file: Option<&std::path::Path>,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "safe_version": SAFE_VERSION,
                "address": prediction.address.to_checksum(None),
                "seed": format_b256(prediction.seed),
                "chain_id": prediction.chain_id,
                "variant": prediction.variant.as_str(),
                "chain_specific": prediction.chain_specific,
                "singleton": prediction.singleton.to_checksum(None),
                "expected_runtime_singleton": prediction.expected_runtime_singleton.to_checksum(None),
                "signer_count": config.signers.len(),
                "threshold": config.threshold,
                "occupied": occupied,
                "deployment_file": deployment_file.map(|path| path.display().to_string()),
            }))?
        );
    } else {
        println!(
            "Safe v{SAFE_VERSION} predicted address: {}",
            prediction.address.to_checksum(None)
        );
        println!(
            "Seed (keep private until deployment): {}",
            format_b256(prediction.seed)
        );
        println!("Chain ID: {}", prediction.chain_id);
        println!("Variant: {}", prediction.variant.as_str());
        println!("Chain-specific salt: {}", prediction.chain_specific);
        println!(
            "Threshold: {} of {}",
            config.threshold,
            config.signers.len()
        );
        println!("Address already occupied: {occupied}");
        if let Some(path) = deployment_file {
            println!("Deployment file: {}", path.display());
        }
    }
    Ok(())
}

fn print_deployment(
    prediction: &Prediction,
    config: &SafeConfig,
    receipt: &DeploymentReceipt,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "safe_version": SAFE_VERSION,
                "address": receipt.address.to_checksum(None),
                "seed": format_b256(prediction.seed),
                "chain_id": prediction.chain_id,
                "variant": prediction.variant.as_str(),
                "chain_specific": prediction.chain_specific,
                "runtime_singleton": receipt.runtime_singleton.to_checksum(None),
                "signer_count": config.signers.len(),
                "threshold": config.threshold,
                "transaction_hash": format_b256(receipt.transaction_hash),
                "block_number": receipt.block_number,
                "verified": true,
            }))?
        );
    } else {
        println!(
            "Deployed and verified Safe: {}",
            receipt.address.to_checksum(None)
        );
        println!("Transaction: {}", format_b256(receipt.transaction_hash));
        println!("Block: {}", receipt.block_number);
        println!(
            "Runtime singleton: {}",
            receipt.runtime_singleton.to_checksum(None)
        );
        println!(
            "Owners/threshold verified: {} of {}",
            config.threshold,
            config.signers.len()
        );
    }
    Ok(())
}

fn format_b256(value: B256) -> String {
    format!("{value:#x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn deploy_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "incognito-safe".to_owned(),
            "--rpc-url".to_owned(),
            "http://127.0.0.1:8545".to_owned(),
            "deploy".to_owned(),
            "--seed".to_owned(),
            TEST_SEED.to_owned(),
            "--config".to_owned(),
            "safe.yml".to_owned(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args
    }

    #[test]
    fn ledger_path_is_always_ledger_live() {
        assert_eq!(ledger_live_path(0).unwrap().to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(ledger_live_path(7).unwrap().to_string(), "m/44'/60'/7'/0/0");
        assert!(ledger_live_path(MAX_LEDGER_ACCOUNT + 1).is_err());
    }

    #[test]
    fn ledger_account_requires_ledger() {
        assert!(Cli::try_parse_from(deploy_args(&["--ledger-account", "2"])).is_err());
    }

    #[test]
    fn ledger_conflicts_with_private_key_environment() {
        assert!(
            Cli::try_parse_from(deploy_args(&[
                "--ledger",
                "--private-key-env",
                "DEPLOYER_KEY",
            ]))
            .is_err()
        );
    }

    #[test]
    fn ledger_live_account_is_parsed() {
        let cli = Cli::try_parse_from(deploy_args(&["--ledger", "--ledger-account", "2"])).unwrap();
        let Command::Deploy {
            ledger,
            ledger_account,
            private_key_env,
            ..
        } = cli.command
        else {
            panic!("expected deploy command");
        };
        assert!(ledger);
        assert_eq!(ledger_account, Some(2));
        assert!(private_key_env.is_none());
    }

    #[test]
    fn trezor_path_is_standard_ethereum_path() {
        assert_eq!(trezor_path(0).unwrap().to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(trezor_path(7).unwrap().to_string(), "m/44'/60'/0'/0/7");
        assert!(trezor_path(MAX_TREZOR_INDEX + 1).is_err());
    }

    #[test]
    fn trezor_index_requires_trezor() {
        assert!(Cli::try_parse_from(deploy_args(&["--trezor-index", "2"])).is_err());
    }

    #[test]
    fn trezor_conflicts_with_other_signer_options() {
        assert!(
            Cli::try_parse_from(deploy_args(&[
                "--trezor",
                "--private-key-env",
                "DEPLOYER_KEY",
            ]))
            .is_err()
        );
        assert!(Cli::try_parse_from(deploy_args(&["--trezor", "--ledger"])).is_err());
    }

    #[test]
    fn trezor_index_is_parsed() {
        let cli = Cli::try_parse_from(deploy_args(&["--trezor", "--trezor-index", "2"])).unwrap();
        let Command::Deploy {
            trezor,
            trezor_index,
            private_key_env,
            ..
        } = cli.command
        else {
            panic!("expected deploy command");
        };
        assert!(trezor);
        assert_eq!(trezor_index, Some(2));
        assert!(private_key_env.is_none());
    }

    #[test]
    fn ethereum_public_rpc_is_the_default() {
        let selected = select_rpc(None, None, None).unwrap();
        assert_eq!(selected.url, "https://ethereum-rpc.publicnode.com");
        assert_eq!(selected.expected_chain_id, Some(1));
    }

    #[test]
    fn custom_rpc_can_be_pinned_to_a_named_chain() {
        let selected =
            select_rpc(Some("https://rpc.example"), Some(ChainArg::World), None).unwrap();
        assert_eq!(selected.url, "https://rpc.example");
        assert_eq!(selected.expected_chain_id, Some(480));

        let unpinned = select_rpc(Some("https://rpc.example"), None, None).unwrap();
        assert_eq!(unpinned.expected_chain_id, None);
    }

    #[test]
    fn deployment_artifact_selects_and_pins_its_chain() {
        let selected = select_rpc(None, None, Some(480)).unwrap();
        assert_eq!(
            selected.url,
            "https://worldchain-mainnet.g.alchemy.com/public"
        );
        assert_eq!(selected.expected_chain_id, Some(480));

        assert!(select_rpc(None, None, Some(999_999)).is_err());
        assert!(select_rpc(None, Some(ChainArg::Base), Some(480)).is_err());

        let custom = select_rpc(Some("https://rpc.example"), None, Some(999_999)).unwrap();
        assert_eq!(custom.expected_chain_id, Some(999_999));
    }

    #[test]
    fn deployment_file_replaces_seed_and_config_arguments() {
        let valid = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "deploy",
            "--file",
            "deployment.json",
            "--ledger",
        ]);
        assert!(valid.is_ok());

        let conflicting = Cli::try_parse_from([
            "incognito-safe",
            "deploy",
            "--file",
            "deployment.json",
            "--config",
            "safe.yml",
        ]);
        assert!(conflicting.is_err());
    }

    #[test]
    fn built_in_chain_registry_has_expected_ids_and_urls() {
        let cases = [
            (ChainArg::Ethereum, 1, "https://ethereum-rpc.publicnode.com"),
            (
                ChainArg::EthereumSepolia,
                11_155_111,
                "https://ethereum-sepolia-rpc.publicnode.com",
            ),
            (
                ChainArg::World,
                480,
                "https://worldchain-mainnet.g.alchemy.com/public",
            ),
            (ChainArg::Optimism, 10, "https://mainnet.optimism.io"),
            (
                ChainArg::OptimismSepolia,
                11_155_420,
                "https://sepolia.optimism.io",
            ),
            (ChainArg::Base, 8_453, "https://mainnet.base.org"),
            (ChainArg::BaseSepolia, 84_532, "https://sepolia.base.org"),
            (ChainArg::Gnosis, 100, "https://rpc.gnosischain.com"),
            (ChainArg::Polygon, 137, "https://polygon.drpc.org"),
        ];

        for (chain, expected_id, expected_url) in cases {
            assert_eq!(chain.chain_id(), expected_id);
            assert_eq!(chain.public_rpc(), expected_url);
        }
    }
}
