use std::{env, path::PathBuf, str::FromStr};

#[cfg(feature = "ledger")]
use alloy::signers::ledger::{HDPath as LedgerHDPath, LedgerSigner};
#[cfg(feature = "trezor")]
use alloy::signers::trezor::{HDPath as TrezorHDPath, TrezorSigner};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    signers::{Signer, local::PrivateKeySigner},
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
use url::{Position, Url};
use zeroize::Zeroizing;

const DEFAULT_PRIVATE_KEY_ENV: &str = "INC_SAFE_PRIVATE_KEY";
const REDACTED_RPC_URL: &str = "<redacted-rpc-url>";
const REDACTED_RPC_SECRET: &str = "<redacted-rpc-secret>";
const GENERIC_SHORT_CREDENTIAL_RPC_ERROR: &str = "RPC request failed; endpoint details were suppressed because the URL contains a short credential";
#[cfg(feature = "ledger")]
const MAX_LEDGER_ACCOUNT: usize = (1 << 31) - 1;
#[cfg(feature = "trezor")]
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
    #[arg(long, global = true, env = "ETH_RPC_URL", hide_env_values = true)]
    rpc_url: Option<String>,

    /// Permit use of a built-in public RPC when no trusted RPC override is configured.
    #[arg(long, global = true)]
    allow_public_rpc: bool,

    /// Target network and expected chain ID.
    /// Selects a built-in RPC only together with `--allow-public-rpc`.
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
    endpoint: RpcEndpoint,
    expected_chain_id: Option<u64>,
    description: String,
}

#[derive(Clone, Debug)]
struct RpcEndpoint {
    url: Url,
    identity: String,
    sensitive_parts: Vec<String>,
    has_short_credential: bool,
}

impl RpcEndpoint {
    fn parse(input: &str, description: &str) -> Result<Self> {
        let mut url =
            Url::parse(input).map_err(|_| anyhow::anyhow!("invalid {description} RPC URL"))?;
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.host().is_some(),
            "{description} RPC URL must be an absolute HTTP(S) URL"
        );

        let mut sensitive_parts = Vec::new();
        let mut has_short_credential = false;
        let mut remember_credential = |part: String| {
            if part.is_empty() {
                return;
            }
            if part.chars().count() <= 2 {
                has_short_credential = true;
            } else if !sensitive_parts.contains(&part) {
                sensitive_parts.push(part);
            }
        };
        remember_credential(url.username().to_owned());
        if let Some(password) = url.password() {
            remember_credential(password.to_owned());
        }
        for (_, value) in url.query_pairs() {
            remember_credential(value.into_owned());
        }

        // Long route components can contain provider keys and are useful to redact when a
        // transport library repeats them outside the URL. Short route words are not credentials:
        // replacing them globally would hide ordinary diagnostics such as "RPC" or "safe".
        let mut remember_long_route = |part: String| {
            if part.len() >= 6 && !sensitive_parts.contains(&part) {
                sensitive_parts.push(part);
            }
        };
        if let Some(segments) = url.path_segments() {
            for segment in segments.filter(|segment| !segment.is_empty()) {
                remember_long_route(segment.to_owned());
            }
        }
        if let Some(fragment) = url.fragment() {
            remember_long_route(fragment.to_owned());
        }

        url.set_fragment(None);
        let default_port = matches!(
            (url.scheme(), url.port()),
            ("http", Some(80)) | ("https", Some(443))
        );
        if default_port {
            url.set_port(None)
                .map_err(|()| anyhow::anyhow!("invalid {description} RPC URL"))?;
        }
        let normalized_path = url[Position::BeforePath..Position::AfterPath]
            .trim_end_matches('/')
            .to_owned();
        let normalized_path = if normalized_path.is_empty() {
            "/".to_owned()
        } else {
            normalized_path
        };
        let identity = format!(
            "{}{}{}",
            &url[..Position::BeforePath],
            normalized_path,
            &url[Position::AfterPath..]
        );
        Ok(Self {
            url,
            identity,
            sensitive_parts,
            has_short_credential,
        })
    }

    fn same_endpoint(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

fn redact_rpc_error(error: &anyhow::Error, endpoints: &[RpcEndpoint]) -> anyhow::Error {
    if endpoints
        .iter()
        .any(|endpoint| endpoint.has_short_credential)
    {
        return anyhow::anyhow!(GENERIC_SHORT_CREDENTIAL_RPC_ERROR);
    }
    anyhow::anyhow!(redact_rpc_message(&format!("{error:#}"), endpoints))
}

/// Redacts URL ranges before applying component replacement to the remaining text.
///
/// This ordering means endpoint components can never rewrite the protected URL marker and avoids
/// introducing an internal sentinel that might escape into the rendered error.
fn redact_rpc_message(input: &str, endpoints: &[RpcEndpoint]) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    loop {
        let lowercase = remaining.to_ascii_lowercase();
        let http = lowercase.find("http://");
        let https = lowercase.find("https://");
        let start = match (http, https) {
            (Some(http), Some(https)) => http.min(https),
            (Some(start), None) | (None, Some(start)) => start,
            (None, None) => {
                output.push_str(&redact_rpc_components(remaining, endpoints));
                break;
            }
        };
        output.push_str(&redact_rpc_components(&remaining[..start], endpoints));
        let url_like = &remaining[start..];
        let end = url_like
            .char_indices()
            .find_map(|(index, character)| {
                (index > 0 && is_url_terminator(character)).then_some(index)
            })
            .unwrap_or(url_like.len());
        output.push_str(REDACTED_RPC_URL);
        remaining = &url_like[end..];
    }
    output
}

fn redact_rpc_components(input: &str, endpoints: &[RpcEndpoint]) -> String {
    let mut output = input.to_owned();
    for endpoint in endpoints {
        for sensitive_part in &endpoint.sensitive_parts {
            output = output.replace(sensitive_part, REDACTED_RPC_SECRET);
        }
    }
    output
}

fn is_url_terminator(character: char) -> bool {
    character.is_whitespace() || matches!(character, '"' | '`' | '<' | '>')
}

fn select_rpc(
    rpc_override: Option<&str>,
    chain: Option<ChainArg>,
    target_chain_id: Option<u64>,
    allow_public_rpc: bool,
) -> Result<RpcSelection> {
    if let Some(url) = rpc_override {
        return Ok(RpcSelection {
            endpoint: RpcEndpoint::parse(url, "primary")?,
            expected_chain_id: target_chain_id.or_else(|| chain.map(ChainArg::chain_id)),
            description: chain
                .or_else(|| target_chain_id.and_then(ChainArg::from_chain_id))
                .map_or_else(
                    || "custom RPC".to_owned(),
                    |selected| format!("custom RPC for {}", selected.name()),
                ),
        });
    }

    ensure!(
        allow_public_rpc,
        "no trusted RPC configured; set ETH_RPC_URL or pass --rpc-url (or explicitly accept the built-in public RPC with --allow-public-rpc)"
    );
    let target_chain = target_chain_id.and_then(ChainArg::from_chain_id);
    ensure!(
        target_chain_id.is_none() || target_chain.is_some() || chain.is_some(),
        "target chain ID {} has no built-in public RPC; set ETH_RPC_URL or pass --rpc-url",
        target_chain_id.unwrap_or_default()
    );
    let selected = chain.or(target_chain).unwrap_or_default();
    Ok(RpcSelection {
        endpoint: RpcEndpoint::parse(selected.public_rpc(), "built-in")?,
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
    /// Recompute and inspect a saved deployment artifact without sending a transaction.
    Verify {
        /// Saved deployment artifact emitted by `generate`.
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// Include exact owner addresses in the output.
        #[arg(long)]
        show_owners: bool,
        /// Independent read-only RPC used to corroborate prediction and occupancy.
        /// The occupancy check discloses the predicted address to this provider.
        #[arg(
            long,
            value_name = "URL",
            env = "CROSS_CHECK_RPC_URL",
            hide_env_values = true
        )]
        cross_check_rpc_url: Option<String>,
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
        /// Exact predicted Safe address that authorizes this deployment.
        #[arg(long, value_name = "ADDRESS")]
        confirm_address: Address,
        /// Independent read-only RPC used to corroborate prediction and occupancy.
        /// The occupancy check discloses the predicted address to this provider.
        #[arg(
            long,
            value_name = "URL",
            env = "CROSS_CHECK_RPC_URL",
            hide_env_values = true
        )]
        cross_check_rpc_url: Option<String>,
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
    let (deployment_artifact, rpc, cross_check_endpoint) = prepare_execution(&cli)?;
    let redaction_endpoints = [Some(rpc.endpoint.clone()), cross_check_endpoint.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    run_prepared(cli, deployment_artifact, rpc, cross_check_endpoint)
        .await
        .map_err(|error| redact_rpc_error(&error, &redaction_endpoints))
}

async fn run_prepared(
    cli: Cli,
    mut deployment_artifact: Option<DeploymentArtifact>,
    rpc: RpcSelection,
    cross_check_endpoint: Option<RpcEndpoint>,
) -> Result<()> {
    let (effective_variant, _) = effective_options(&cli, deployment_artifact.as_ref())?;
    let read_provider = ProviderBuilder::new().connect_http(rpc.endpoint.url.clone());
    let actual_chain_id = pin_provider_chain(&read_provider, rpc.expected_chain_id).await?;
    if rpc.expected_chain_id.is_none()
        && effective_variant == SafeVariant::L1
        && actual_chain_id != 1
    {
        eprintln!(
            "warning: --variant l1 on detected chain {actual_chain_id} retains the L1 singleton and does not provide the expected SafeL2 events and behavior"
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
                actual_chain_id,
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
                actual_chain_id,
                cli.json,
            )
            .await?;
        }
        Command::Verify {
            file: _,
            show_owners,
            cross_check_rpc_url: _,
        } => {
            verify_command(
                &read_provider,
                &rpc.endpoint,
                deployment_artifact
                    .take()
                    .expect("verify always loads an artifact"),
                actual_chain_id,
                cross_check_endpoint.as_ref(),
                show_owners,
                cli.json,
            )
            .await?;
        }
        Command::Deploy {
            seed,
            source,
            file: _,
            confirm_address,
            cross_check_rpc_url: _,
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
                &rpc.endpoint,
                source,
                seed.as_deref(),
                deployment_artifact.take(),
                cli.variant,
                cli.chain_specific,
                actual_chain_id,
                confirm_address,
                cross_check_endpoint.as_ref(),
                deployer_signer,
                cli.json,
            )
            .await?;
        }
    }
    Ok(())
}

async fn pin_provider_chain<P: Provider>(
    provider: &P,
    selected_chain_id: Option<u64>,
) -> Result<u64> {
    let actual_chain_id = provider
        .get_chain_id()
        .await
        .context("failed to query RPC chain ID")?;
    if let Some(selected_chain_id) = selected_chain_id {
        ensure!(
            actual_chain_id == selected_chain_id,
            "RPC chain ID {actual_chain_id} does not match selected chain ID {selected_chain_id}"
        );
    }
    Ok(actual_chain_id)
}

fn prepare_execution(
    cli: &Cli,
) -> Result<(
    Option<DeploymentArtifact>,
    RpcSelection,
    Option<RpcEndpoint>,
)> {
    let deployment_artifact = match &cli.command {
        Command::Deploy {
            file: Some(path), ..
        }
        | Command::Verify { file: path, .. } => Some(load_artifact(path)?),
        _ => None,
    };

    if let Some(artifact) = deployment_artifact.as_ref() {
        validate_artifact_options(artifact, cli.variant, cli.chain_specific)?;
        if let Command::Deploy {
            confirm_address, ..
        } = &cli.command
        {
            confirm_address_matches(*confirm_address, artifact.predicted_address).context(
                "deployment confirmation does not match the saved artifact; refusing before RPC access",
            )?;
        }
    }
    let (effective_variant, effective_chain_specific) =
        effective_options(cli, deployment_artifact.as_ref())?;

    let target_chain_id = cli.chain.map(ChainArg::chain_id).or_else(|| {
        deployment_artifact
            .as_ref()
            .map(|artifact| artifact.chain_id)
    });
    if let (Some(artifact), Some(target_chain_id)) = (deployment_artifact.as_ref(), target_chain_id)
    {
        ensure!(
            artifact.allows_target_chain(target_chain_id),
            "deployment artifact from chain {} cannot target chain {target_chain_id}; cross-chain use requires a portable, non-chain-specific artifact",
            artifact.chain_id
        );
        if target_chain_id != artifact.chain_id {
            eprintln!(
                "warning: retargeting portable artifact from chain {} to chain {target_chain_id}; confirm every owner (especially smart-contract owners) exists and behaves as intended on the target chain",
                artifact.chain_id
            );
        }
    }
    for warning in option_warnings(effective_variant, effective_chain_specific, target_chain_id) {
        eprintln!("warning: {warning}");
    }

    let rpc = select_rpc(
        cli.rpc_url.as_deref(),
        cli.chain,
        target_chain_id,
        cli.allow_public_rpc,
    )?;
    if cli.rpc_url.is_none() {
        eprintln!(
            "warning: using {}; prediction and occupancy queries are visible to that provider",
            rpc.description
        );
    } else {
        eprintln!("using {}", rpc.description);
    }
    let cross_check_url = match &cli.command {
        Command::Verify {
            cross_check_rpc_url,
            ..
        }
        | Command::Deploy {
            cross_check_rpc_url,
            ..
        } => cross_check_rpc_url.as_deref(),
        _ => None,
    };
    let cross_check_endpoint = cross_check_url
        .map(|url| RpcEndpoint::parse(url, "cross-check"))
        .transpose()?;
    if let Some(cross_check_endpoint) = &cross_check_endpoint {
        ensure!(
            !rpc.endpoint.same_endpoint(cross_check_endpoint),
            "--cross-check-rpc-url resolves to the same endpoint as the primary RPC URL"
        );
    }
    Ok((deployment_artifact, rpc, cross_check_endpoint))
}

fn effective_options(
    cli: &Cli,
    artifact: Option<&DeploymentArtifact>,
) -> Result<(SafeVariant, bool)> {
    if let Some(artifact) = artifact {
        Ok((artifact.safe_variant()?, artifact.chain_specific))
    } else {
        Ok((cli.variant.unwrap_or_default().into(), cli.chain_specific))
    }
}

fn option_warnings(
    variant: SafeVariant,
    chain_specific: bool,
    target_chain_id: Option<u64>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if matches!(variant, SafeVariant::L1 | SafeVariant::L2) {
        warnings.push(format!(
            "effective Safe variant {} changes initialization and the predicted address relative to portable; portable is the recommended default and the only variant eligible for artifact retargeting",
            variant.as_str()
        ));
        if variant == SafeVariant::L1 && target_chain_id.is_some_and(|chain_id| chain_id != 1) {
            warnings.push(format!(
                "effective l1 variant on target chain {} retains the L1 singleton and does not provide the expected SafeL2 events and behavior",
                target_chain_id.unwrap_or_default()
            ));
        }
    }
    if chain_specific {
        warnings.push(
            "effective chain-specific mode binds the salt to the target chain ID, changes the predicted address, and prevents cross-chain artifact retargeting"
                .to_owned(),
        );
    }
    warnings
}

async fn generate_command<P: Provider>(
    provider: &P,
    source: ConfigSource,
    output_dir: &std::path::Path,
    variant: SafeVariant,
    chain_specific: bool,
    expected_chain_id: u64,
    json_output: bool,
) -> Result<()> {
    let config = resolve_config(provider, source).await?;
    let seed = generate_seed()?;
    let prediction = predict_for_target(
        provider,
        &config,
        seed,
        variant,
        chain_specific,
        expected_chain_id,
        "generate",
    )
    .await?;
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
    expected_chain_id: u64,
    json_output: bool,
) -> Result<()> {
    let config = resolve_config(provider, source).await?;
    let prediction = predict_for_target(
        provider,
        &config,
        parse_seed(seed)?,
        variant,
        chain_specific,
        expected_chain_id,
        "predict",
    )
    .await?;
    let occupied = !provider.get_code_at(prediction.address).await?.is_empty();
    print_prediction(&prediction, &config, occupied, None, json_output)
}

async fn verify_command<P: Provider>(
    provider: &P,
    primary_endpoint: &RpcEndpoint,
    artifact: DeploymentArtifact,
    expected_chain_id: u64,
    cross_check_endpoint: Option<&RpcEndpoint>,
    show_owners: bool,
    json_output: bool,
) -> Result<()> {
    let config = artifact.config()?;
    let variant = artifact.safe_variant()?;
    let prediction = predict_for_target(
        provider,
        &config,
        artifact.seed,
        variant,
        artifact.chain_specific,
        expected_chain_id,
        "verify",
    )
    .await?;
    artifact.verify_prediction_for_target(&prediction)?;
    validate_prediction_state(
        provider,
        primary_endpoint,
        cross_check_endpoint,
        &config,
        &prediction,
        expected_chain_id,
    )
    .await?;
    print_verification(&artifact, &prediction, &config, show_owners, json_output)
}

#[allow(clippy::too_many_arguments)]
async fn predict_for_target<P: Provider>(
    provider: &P,
    config: &SafeConfig,
    seed: B256,
    variant: SafeVariant,
    chain_specific: bool,
    expected_chain_id: u64,
    phase: &str,
) -> Result<Prediction> {
    let prediction = predict_safe(provider, config, seed, variant, chain_specific).await?;
    ensure_prediction_chain(&prediction, expected_chain_id, phase)?;
    Ok(prediction)
}

fn ensure_prediction_chain(
    prediction: &Prediction,
    expected_chain_id: u64,
    phase: &str,
) -> Result<()> {
    ensure!(
        prediction.chain_id == expected_chain_id,
        "{phase} prediction chain ID {} does not match pinned target chain ID {expected_chain_id}",
        prediction.chain_id
    );
    Ok(())
}

fn validate_artifact_options(
    artifact: &DeploymentArtifact,
    requested_variant: Option<VariantArg>,
    requested_chain_specific: bool,
) -> Result<()> {
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
    Ok(())
}

fn confirm_address_matches(confirmed: Address, predicted: Address) -> Result<()> {
    ensure!(
        confirmed == predicted,
        "confirmed address {} does not match predicted address {}",
        confirmed.to_checksum(None),
        predicted.to_checksum(None)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn deploy_command<P: Provider>(
    read_provider: &P,
    primary_endpoint: &RpcEndpoint,
    source: DeployConfigSource,
    seed: Option<&str>,
    artifact: Option<DeploymentArtifact>,
    requested_variant: Option<VariantArg>,
    requested_chain_specific: bool,
    expected_chain_id: u64,
    confirmed_address: Address,
    cross_check_endpoint: Option<&RpcEndpoint>,
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
    let prediction = predict_for_target(
        read_provider,
        &config,
        seed,
        variant,
        chain_specific,
        expected_chain_id,
        "deploy",
    )
    .await?;
    if let Some(artifact) = &artifact {
        artifact.verify_prediction_for_target(&prediction)?;
        eprintln!(
            "artifact fields match recomputation for {}",
            prediction.address
        );
    }
    confirm_address_matches(confirmed_address, prediction.address).context(
        "deployment confirmation does not match the recomputed address; refusing before signer access",
    )?;

    validate_prediction_state(
        read_provider,
        primary_endpoint,
        cross_check_endpoint,
        &config,
        &prediction,
        expected_chain_id,
    )
    .await?;

    let (wallet, deployer, signer_description) =
        deployment_wallet(deployer_signer, prediction.chain_id).await?;
    eprintln!(
        "deploying Safe v{SAFE_VERSION} at {} on chain {} from {deployer} using {signer_description}",
        prediction.address, prediction.chain_id,
    );
    let signed_provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(primary_endpoint.url.clone());
    // `deploy_safe` rederives through this signing provider and requires its
    // chain ID to equal the already-pinned `prediction.chain_id` before it
    // simulates or sends the factory call.
    let receipt = deploy_safe(&signed_provider, &config, &prediction).await?;
    print_deployment(&prediction, &config, &receipt, json_output)
}

async fn validate_prediction_state<P: Provider>(
    primary_provider: &P,
    primary_endpoint: &RpcEndpoint,
    cross_check_endpoint: Option<&RpcEndpoint>,
    config: &SafeConfig,
    prediction: &Prediction,
    expected_chain_id: u64,
) -> Result<()> {
    if let Some(cross_check_endpoint) = cross_check_endpoint {
        return cross_check_prediction(
            primary_provider,
            primary_endpoint,
            cross_check_endpoint,
            config,
            prediction,
            expected_chain_id,
        )
        .await;
    }
    let existing = primary_provider
        .get_code_at(prediction.address)
        .await
        .context("failed to check predicted address occupancy")?;
    ensure!(
        existing.is_empty(),
        "predicted address {} already contains code",
        prediction.address
    );
    Ok(())
}

async fn cross_check_prediction<P: Provider>(
    primary_provider: &P,
    primary_endpoint: &RpcEndpoint,
    cross_check_endpoint: &RpcEndpoint,
    config: &SafeConfig,
    primary: &Prediction,
    expected_chain_id: u64,
) -> Result<()> {
    ensure_prediction_chain(primary, expected_chain_id, "primary cross-check")?;
    ensure!(
        !primary_endpoint.same_endpoint(cross_check_endpoint),
        "--cross-check-rpc-url resolves to the same endpoint as the primary RPC URL"
    );
    let secondary = ProviderBuilder::new().connect_http(cross_check_endpoint.url.clone());
    let secondary_chain_id = secondary
        .get_chain_id()
        .await
        .context("failed to query cross-check RPC chain ID")?;
    ensure!(
        secondary_chain_id == expected_chain_id,
        "cross-check RPC chain ID {secondary_chain_id} does not match pinned target chain ID {expected_chain_id}"
    );

    let corroborating = predict_for_target(
        &secondary,
        config,
        primary.seed,
        primary.variant,
        primary.chain_specific,
        expected_chain_id,
        "cross-check",
    )
    .await
    .context("cross-check RPC prediction failed")?;
    ensure_predictions_match(primary, &corroborating)?;

    eprintln!(
        "warning: checking occupancy will disclose predicted address {} to the cross-check RPC",
        primary.address.to_checksum(None)
    );
    let (primary_code, secondary_code) = tokio::try_join!(
        primary_provider.get_code_at(primary.address),
        secondary.get_code_at(primary.address),
    )
    .context("failed to cross-check predicted address occupancy")?;
    let primary_occupied = !primary_code.is_empty();
    let secondary_occupied = !secondary_code.is_empty();
    ensure!(
        primary_occupied == secondary_occupied,
        "RPCs disagree about occupancy of {} (primary: {primary_occupied}, cross-check: {secondary_occupied})",
        primary.address
    );
    ensure!(
        !primary_occupied,
        "predicted address {} already contains code",
        primary.address
    );
    eprintln!(
        "cross-check RPC corroborated the target chain, prediction, and empty address; this does not authenticate either RPC"
    );
    Ok(())
}

fn ensure_predictions_match(primary: &Prediction, corroborating: &Prediction) -> Result<()> {
    ensure!(
        corroborating.chain_id == primary.chain_id,
        "cross-check prediction chain ID mismatch"
    );
    ensure!(
        corroborating.seed == primary.seed,
        "cross-check prediction seed mismatch"
    );
    ensure!(
        corroborating.address == primary.address,
        "cross-check prediction address {} does not match primary prediction {}",
        corroborating.address,
        primary.address
    );
    ensure!(
        corroborating.variant == primary.variant,
        "cross-check prediction Safe variant mismatch"
    );
    ensure!(
        corroborating.chain_specific == primary.chain_specific,
        "cross-check prediction chain-specific setting mismatch"
    );
    ensure!(
        corroborating.singleton == primary.singleton,
        "cross-check prediction singleton mismatch"
    );
    ensure!(
        corroborating.expected_runtime_singleton == primary.expected_runtime_singleton,
        "cross-check prediction runtime singleton mismatch"
    );
    ensure!(
        corroborating.initializer == primary.initializer,
        "cross-check prediction initializer mismatch"
    );
    ensure!(
        corroborating.salt == primary.salt,
        "cross-check prediction CREATE2 salt mismatch"
    );
    Ok(())
}

#[cfg(feature = "ledger")]
fn ledger_live_path(account: usize) -> Result<LedgerHDPath> {
    ensure!(
        account <= MAX_LEDGER_ACCOUNT,
        "Ledger account index must be at most {MAX_LEDGER_ACCOUNT}"
    );
    Ok(LedgerHDPath::LedgerLive(account))
}

#[cfg(feature = "trezor")]
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

#[cfg_attr(
    not(any(feature = "ledger", feature = "trezor")),
    allow(clippy::unused_async)
)]
async fn deployment_wallet(
    deployer_signer: DeployerSigner,
    chain_id: u64,
) -> Result<(EthereumWallet, Address, String)> {
    match deployer_signer {
        DeployerSigner::Ledger { account } => {
            #[cfg(feature = "ledger")]
            {
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
            #[cfg(not(feature = "ledger"))]
            {
                let _ = (account, chain_id);
                anyhow::bail!(
                    "this incognito-safe binary was built without Ledger support; rebuild with --features ledger"
                )
            }
        }
        DeployerSigner::Trezor { index } => {
            #[cfg(feature = "trezor")]
            {
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
            #[cfg(not(feature = "trezor"))]
            {
                let _ = (index, chain_id);
                anyhow::bail!(
                    "this incognito-safe binary was built without Trezor support; rebuild with --features trezor"
                )
            }
        }
        DeployerSigner::PrivateKeyEnv(env_name) => {
            validate_env_name(&env_name)?;
            let secret = Zeroizing::new(env::var(&env_name).with_context(|| {
                format!("private-key environment variable `{env_name}` is not set")
            })?);
            let signer = PrivateKeySigner::from_str(&secret)
                .with_context(|| format!("`{env_name}` is not a valid secp256k1 private key"))?;
            let signer = pin_private_key_signer(signer, chain_id);
            let deployer = signer.address();
            Ok((
                EthereumWallet::from(signer),
                deployer,
                format!("private key from `{env_name}`"),
            ))
        }
    }
}

fn pin_private_key_signer(signer: PrivateKeySigner, chain_id: u64) -> PrivateKeySigner {
    signer.with_chain_id(Some(chain_id))
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
            serde_json::to_string_pretty(&prediction_json(
                prediction,
                config,
                occupied,
                deployment_file,
            ))?
        );
    } else {
        println!(
            "{}",
            prediction_human(prediction, config, occupied, deployment_file)
        );
    }
    Ok(())
}

fn prediction_json(
    prediction: &Prediction,
    config: &SafeConfig,
    occupied: bool,
    deployment_file: Option<&std::path::Path>,
) -> serde_json::Value {
    json!({
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
    })
}

fn prediction_human(
    prediction: &Prediction,
    config: &SafeConfig,
    occupied: bool,
    deployment_file: Option<&std::path::Path>,
) -> String {
    let mut lines = vec![format!(
        "Safe v{SAFE_VERSION} predicted address: {}",
        prediction.address.to_checksum(None)
    )];
    if deployment_file.is_none() {
        lines.push(format!(
            "Seed (keep private until deployment): {}",
            format_b256(prediction.seed)
        ));
    }
    lines.extend([
        format!("Chain ID: {}", prediction.chain_id),
        format!("Variant: {}", prediction.variant.as_str()),
        format!("Chain-specific salt: {}", prediction.chain_specific),
        format!(
            "Threshold: {} of {}",
            config.threshold,
            config.signers.len()
        ),
        format!("Address already occupied: {occupied}"),
    ]);
    if let Some(path) = deployment_file {
        lines.push(format!("Deployment file: {}", path.display()));
        lines.push(
            "Seed omitted from terminal output; protect and back up the deployment file".to_owned(),
        );
    }
    lines.join("\n")
}

fn print_verification(
    artifact: &DeploymentArtifact,
    prediction: &Prediction,
    config: &SafeConfig,
    show_owners: bool,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&verification_json(
                artifact,
                prediction,
                config,
                show_owners,
            ))?
        );
    } else {
        println!(
            "{}",
            verification_human(artifact, prediction, config, show_owners)
        );
    }
    Ok(())
}

fn verification_json(
    artifact: &DeploymentArtifact,
    prediction: &Prediction,
    config: &SafeConfig,
    show_owners: bool,
) -> serde_json::Value {
    let mut output = json!({
        "safe_version": SAFE_VERSION,
        "address": prediction.address.to_checksum(None),
        "origin_chain_id": artifact.chain_id,
        "target_chain_id": prediction.chain_id,
        "variant": prediction.variant.as_str(),
        "chain_specific": prediction.chain_specific,
        "owner_count": config.signers.len(),
        "threshold": config.threshold,
        "occupied": false,
    });
    if show_owners {
        output["owners"] = json!(
            config
                .signers
                .iter()
                .map(|owner| owner.to_checksum(None))
                .collect::<Vec<_>>()
        );
    }
    output
}

fn verification_human(
    artifact: &DeploymentArtifact,
    prediction: &Prediction,
    config: &SafeConfig,
    show_owners: bool,
) -> String {
    let mut lines = vec![
        format!(
            "Recomputed Safe v{SAFE_VERSION} address: {}",
            prediction.address.to_checksum(None)
        ),
        format!("Origin chain ID: {}", artifact.chain_id),
        format!("Target chain ID: {}", prediction.chain_id),
        format!("Variant: {}", prediction.variant.as_str()),
        format!("Chain-specific salt: {}", prediction.chain_specific),
        format!(
            "Threshold: {} of {}",
            config.threshold,
            config.signers.len()
        ),
        "Address already occupied: false".to_owned(),
        "Artifact fields match recomputation; this does not authenticate the file".to_owned(),
    ];
    if show_owners {
        lines.push("Owners:".to_owned());
        lines.extend(
            config
                .signers
                .iter()
                .map(|owner| format!("  - {}", owner.to_checksum(None))),
        );
    }
    lines.join("\n")
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
    use alloy::primitives::{address, b256, bytes};
    use clap::CommandFactory;

    use super::*;

    const TEST_SEED: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
    const TEST_ADDRESS: &str = "0x2222222222222222222222222222222222222222";
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
            "--confirm-address".to_owned(),
            TEST_ADDRESS.to_owned(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args
    }

    fn output_fixture() -> (SafeConfig, Prediction, DeploymentArtifact) {
        let config = SafeConfig {
            signers: vec![
                address!("1111111111111111111111111111111111111111"),
                address!("3333333333333333333333333333333333333333"),
            ],
            threshold: 2,
        };
        let prediction = Prediction {
            address: address!("2222222222222222222222222222222222222222"),
            chain_id: 480,
            seed: b256!("0101010101010101010101010101010101010101010101010101010101010101"),
            singleton: address!("Ff51A5898e281Db6DfC7855790607438dF2ca44b"),
            expected_runtime_singleton: address!("Edd160fEBBD92E350D4D398fb636302fccd67C7e"),
            initializer: bytes!("1234"),
            salt: b256!("0202020202020202020202020202020202020202020202020202020202020202"),
            variant: SafeVariant::Portable,
            chain_specific: false,
        };
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        (config, prediction, artifact)
    }

    #[test]
    #[cfg(feature = "ledger")]
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
    #[cfg(feature = "trezor")]
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
    fn every_deploy_mode_requires_address_confirmation() {
        let seed_deploy = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "deploy",
            "--seed",
            TEST_SEED,
            "--config",
            "safe.yml",
        ]);
        assert!(seed_deploy.is_err());

        let file_deploy = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "deploy",
            "--file",
            "deployment.json",
        ]);
        assert!(file_deploy.is_err());
        assert!(Cli::try_parse_from(deploy_args(&[])).is_ok());
    }

    #[test]
    fn verify_and_cross_check_options_are_scoped_and_parsed() {
        let verify = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "verify",
            "--file",
            "deployment.json",
            "--show-owners",
            "--cross-check-rpc-url",
            "http://127.0.0.1:9545",
        ])
        .unwrap();
        assert!(matches!(
            verify.command,
            Command::Verify {
                show_owners: true,
                cross_check_rpc_url: Some(_),
                ..
            }
        ));

        let deploy = Cli::try_parse_from(deploy_args(&[
            "--cross-check-rpc-url",
            "http://127.0.0.1:9545",
        ]))
        .unwrap();
        assert!(matches!(
            deploy.command,
            Command::Deploy {
                cross_check_rpc_url: Some(_),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "incognito-safe",
                "--rpc-url",
                "http://127.0.0.1:8545",
                "verify"
            ])
            .is_err()
        );
    }

    #[test]
    fn confirmation_compares_addresses_semantically() {
        let predicted = Address::from_str(TEST_ADDRESS).unwrap();
        confirm_address_matches(predicted, predicted).unwrap();
        assert!(
            confirm_address_matches(
                address!("4444444444444444444444444444444444444444"),
                predicted
            )
            .is_err()
        );
    }

    #[test]
    fn file_confirmation_is_rejected_during_local_preparation() {
        let (_, _, artifact) = output_fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = write_unique_artifact(directory.path(), &artifact).unwrap();
        let cli = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "deploy",
            "--file",
            path.to_str().unwrap(),
            "--confirm-address",
            "0x4444444444444444444444444444444444444444",
        ])
        .unwrap();
        let error = prepare_execution(&cli).unwrap_err();
        assert!(error.to_string().contains("refusing before RPC access"));
    }

    #[test]
    fn local_preparation_allows_only_portable_non_chain_specific_retargeting() {
        let (_, mut prediction, artifact) = output_fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = write_unique_artifact(directory.path(), &artifact).unwrap();
        let portable = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "--chain",
            "base",
            "verify",
            "--file",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let (_, rpc, _) = prepare_execution(&portable).unwrap();
        assert_eq!(rpc.expected_chain_id, Some(8_453));

        prediction.chain_specific = true;
        let (config, _, _) = output_fixture();
        let chain_specific = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let other_directory = tempfile::tempdir().unwrap();
        let other_path = write_unique_artifact(other_directory.path(), &chain_specific).unwrap();
        let forbidden = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "--chain",
            "base",
            "verify",
            "--file",
            other_path.to_str().unwrap(),
        ])
        .unwrap();
        assert!(prepare_execution(&forbidden).is_err());
    }

    #[test]
    fn explicit_address_changing_options_have_loud_policy_warnings() {
        assert!(option_warnings(SafeVariant::Portable, false, Some(480)).is_empty());

        let l1 = option_warnings(SafeVariant::L1, false, Some(480));
        assert_eq!(l1.len(), 2);
        assert!(l1[0].contains("predicted address"));
        assert!(l1[0].contains("portable"));
        assert!(l1[1].contains("SafeL2"));

        let l2 = option_warnings(SafeVariant::L2, false, Some(480));
        assert_eq!(l2.len(), 1);
        assert!(l2[0].contains("artifact retargeting"));

        let chain_specific = option_warnings(SafeVariant::Portable, true, Some(480));
        assert_eq!(chain_specific.len(), 1);
        assert!(chain_specific[0].contains("changes the predicted address"));
    }

    #[test]
    fn artifact_values_drive_effective_warnings() {
        let (config, mut prediction, _) = output_fixture();
        prediction.variant = SafeVariant::L1;
        prediction.chain_specific = true;
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let cli = Cli::try_parse_from([
            "incognito-safe",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "verify",
            "--file",
            "deployment.json",
        ])
        .unwrap();

        let (variant, chain_specific) = effective_options(&cli, Some(&artifact)).unwrap();
        assert_eq!(variant, SafeVariant::L1);
        assert!(chain_specific);
        let warnings = option_warnings(variant, chain_specific, Some(480));
        assert_eq!(warnings.len(), 3);
        assert!(warnings[0].contains("variant l1"));
        assert!(warnings[1].contains("SafeL2"));
        assert!(warnings[2].contains("chain-specific"));
    }

    #[test]
    fn every_prediction_phase_rejects_chain_drift() {
        let (_, prediction, _) = output_fixture();
        for phase in [
            "generate",
            "predict",
            "verify",
            "deploy",
            "primary cross-check",
            "cross-check",
        ] {
            ensure_prediction_chain(&prediction, 480, phase).unwrap();
            let error = ensure_prediction_chain(&prediction, 1, phase).unwrap_err();
            assert!(error.to_string().contains("pinned target chain ID 1"));
            assert!(error.to_string().contains(phase));
        }
    }

    #[test]
    fn cross_check_rpc_has_environment_binding() {
        let command = Cli::command();
        let primary = command
            .get_arguments()
            .find(|argument| argument.get_id() == "rpc_url")
            .expect("primary RPC argument");
        assert_eq!(primary.get_env(), Some(std::ffi::OsStr::new("ETH_RPC_URL")));
        assert!(primary.is_hide_env_values_set());

        for subcommand in ["verify", "deploy"] {
            let argument = command
                .find_subcommand(subcommand)
                .expect("RPC-capable subcommand")
                .get_arguments()
                .find(|argument| argument.get_id() == "cross_check_rpc_url")
                .expect("cross-check RPC argument");
            assert_eq!(
                argument.get_env(),
                Some(std::ffi::OsStr::new("CROSS_CHECK_RPC_URL"))
            );
            assert!(argument.is_hide_env_values_set());
        }
    }

    #[test]
    fn endpoint_identity_normalizes_common_equivalent_urls() {
        let primary = RpcEndpoint::parse("HTTPS://RPC.Example.COM:443/v2/", "primary").unwrap();
        for equivalent in [
            "https://rpc.example.com/v2",
            "https://rpc.example.com:443/v2/#ignored-fragment",
        ] {
            let secondary = RpcEndpoint::parse(equivalent, "cross-check").unwrap();
            assert!(primary.same_endpoint(&secondary));
        }

        let root = RpcEndpoint::parse("http://RPC.Example.COM:80", "primary").unwrap();
        let root_with_fragment =
            RpcEndpoint::parse("http://rpc.example.com/#ignored", "cross-check").unwrap();
        assert!(root.same_endpoint(&root_with_fragment));

        let different_path =
            RpcEndpoint::parse("https://rpc.example.com/v3", "cross-check").unwrap();
        assert!(!primary.same_endpoint(&different_path));

        let encoded =
            RpcEndpoint::parse("https://rpc.example.com/v2/%2Fsecret/", "primary").unwrap();
        assert_eq!(
            encoded.url.as_str(),
            "https://rpc.example.com/v2/%2Fsecret/"
        );
        assert!(!encoded.identity.contains("%252F"));
    }

    #[test]
    fn canonical_same_endpoint_is_rejected_before_rpc_access() {
        let cli = Cli::try_parse_from(deploy_args(&[
            "--cross-check-rpc-url",
            "HTTP://127.0.0.1:8545/#ignored",
        ]))
        .unwrap();
        let error = prepare_execution(&cli).unwrap_err();
        assert!(error.to_string().contains("same endpoint"));
        assert!(!error.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn rpc_error_redaction_removes_urls_and_credential_components() {
        let primary_raw = "HTTPS://alice:primary-pass@RPC.Example.COM:443/v2/primary-key/?token=primary-query#primary-fragment";
        let secondary_raw =
            "https://bob:secondary-pass@other.example/rpc/secondary-key?auth=secondary-query";
        let primary = RpcEndpoint::parse(primary_raw, "primary").unwrap();
        let secondary = RpcEndpoint::parse(secondary_raw, "cross-check").unwrap();
        let source =
            anyhow::anyhow!("request failed for url ({secondary_raw}): credential secondary-pass");
        let error = source.context(format!("primary transport failed at {primary_raw}"));
        let redacted = redact_rpc_error(&error, &[primary, secondary]).to_string();

        assert!(
            redacted.contains("<redacted-rpc-url>"),
            "redacted error: {redacted}"
        );
        for secret in [
            primary_raw,
            secondary_raw,
            "alice",
            "primary-pass",
            "primary-key",
            "primary-query",
            "primary-fragment",
            "bob",
            "secondary-pass",
            "secondary-key",
            "secondary-query",
        ] {
            assert!(!redacted.contains(secret), "leaked RPC secret: {secret}");
        }
    }

    #[test]
    fn rpc_error_redaction_protects_marker_and_complete_ipv6_url() {
        let raw = "https://[2001:db8::1]:8545/RPC/URL/INC/SAFE";
        let endpoint = RpcEndpoint::parse(raw, "primary").unwrap();
        let source = anyhow::anyhow!(
            "transport failed for ({raw}); RPC URL INC SAFE diagnostics remain useful"
        );
        let redacted = redact_rpc_error(&source, &[endpoint]).to_string();

        assert_eq!(redacted.matches(REDACTED_RPC_URL).count(), 1);
        assert!(!redacted.contains("2001:db8::1"));
        assert!(!redacted.contains('\0'));
        assert!(redacted.contains("RPC URL INC SAFE diagnostics remain useful"));
    }

    #[test]
    fn rpc_error_redaction_keeps_valid_punctuation_inside_url_range() {
        for (raw, suffix) in [
            (
                "https://example.com/rpc/key(OPEN_PAREN_SECRET",
                "OPEN_PAREN_SECRET",
            ),
            (
                "https://example.com/rpc/key)CLOSE_PAREN_SECRET",
                "CLOSE_PAREN_SECRET",
            ),
            (
                "https://example.com/rpc?token=base;SEMICOLON_SECRET",
                "SEMICOLON_SECRET",
            ),
            ("https://example.com/rpc/key,COMMA_SECRET", "COMMA_SECRET"),
            (
                "https://example.com/rpc/key'APOSTROPHE_SECRET",
                "APOSTROPHE_SECRET",
            ),
            ("https://example.com/rpc/{BRACE_SECRET}", "BRACE_SECRET"),
        ] {
            let endpoint = RpcEndpoint::parse(raw, "primary").unwrap();
            let source = anyhow::anyhow!("transport failed at {raw} END");
            let redacted = redact_rpc_error(&source, &[endpoint]).to_string();

            assert_eq!(
                redacted,
                format!("transport failed at {REDACTED_RPC_URL} END")
            );
            assert!(!redacted.contains(suffix), "leaked URL suffix: {suffix}");
        }
    }

    #[test]
    fn short_credentials_use_fixed_error_without_global_replacement() {
        for raw in [
            "https://a@example.com/rpc",
            "https://ab@example.com/rpc",
            "https://user:b@example.com/rpc",
            "https://user:bc@example.com/rpc",
            "https://example.com/rpc?token=x",
            "https://example.com/rpc?token=xy",
        ] {
            let endpoint = RpcEndpoint::parse(raw, "primary").unwrap();
            let source = anyhow::anyhow!("transport failed at {raw}: x is unavailable");
            let redacted = redact_rpc_error(&source, &[endpoint]).to_string();
            assert_eq!(redacted, GENERIC_SHORT_CREDENTIAL_RPC_ERROR);
            assert!(!redacted.contains('\0'));
        }
    }

    #[test]
    fn empty_credentials_and_short_routes_preserve_non_url_diagnostics() {
        let raw = "https://example.com/x?token=&empty";
        let endpoint = RpcEndpoint::parse(raw, "primary").unwrap();
        assert!(!endpoint.has_short_credential);
        let source = anyhow::anyhow!("transport failed at {raw}; route x returned RPC error");
        let redacted = redact_rpc_error(&source, &[endpoint]).to_string();

        assert_eq!(
            redacted,
            format!("transport failed at {REDACTED_RPC_URL} route x returned RPC error")
        );
        assert!(!redacted.contains('\0'));
    }

    #[test]
    fn private_key_signer_is_pinned_to_selected_chain() {
        let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
        let signer = pin_private_key_signer(signer, 480);
        assert_eq!(signer.chain_id(), Some(480));
    }

    #[tokio::test]
    #[cfg(not(feature = "ledger"))]
    async fn ledger_flag_fails_cleanly_without_ledger_feature() {
        let error = deployment_wallet(DeployerSigner::Ledger { account: 0 }, 480)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("built without Ledger support"));
    }

    #[tokio::test]
    #[cfg(not(feature = "trezor"))]
    async fn trezor_flag_fails_cleanly_without_trezor_feature() {
        let error = deployment_wallet(DeployerSigner::Trezor { index: 0 }, 480)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("built without Trezor support"));
    }

    #[test]
    fn generated_human_output_omits_seed_but_json_and_predict_retain_it() {
        let (config, prediction, _) = output_fixture();
        let path = std::path::Path::new("private/deployment.json");
        let generated = prediction_human(&prediction, &config, false, Some(path));
        assert!(!generated.contains(&format_b256(prediction.seed)));
        assert!(generated.contains("Deployment file: private/deployment.json"));

        let predicted = prediction_human(&prediction, &config, false, None);
        assert!(predicted.contains(&format_b256(prediction.seed)));
        let generated_json = prediction_json(&prediction, &config, false, Some(path));
        assert_eq!(generated_json["seed"], format_b256(prediction.seed));
    }

    #[test]
    fn verification_output_is_secret_free_and_owners_are_opt_in() {
        let (config, prediction, artifact) = output_fixture();
        let default = verification_json(&artifact, &prediction, &config, false);
        let object = default.as_object().unwrap();
        for forbidden in [
            "seed",
            "initializer",
            "salt",
            "owners",
            "verified",
            "authentic",
            "authenticity",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "unexpected key: {forbidden}"
            );
        }
        assert_eq!(default["address"], prediction.address.to_checksum(None));
        assert_eq!(default["origin_chain_id"], 480);
        assert_eq!(default["target_chain_id"], 480);
        assert_eq!(default["variant"], "portable");
        assert_eq!(default["chain_specific"], false);
        assert_eq!(default["threshold"], 2);
        assert_eq!(default["owner_count"], 2);
        assert_eq!(default["occupied"], false);

        let with_owners = verification_json(&artifact, &prediction, &config, true);
        assert_eq!(with_owners["owners"].as_array().unwrap().len(), 2);
        let default_human = verification_human(&artifact, &prediction, &config, false);
        assert!(!default_human.contains(&config.signers[0].to_checksum(None)));
        assert!(default_human.contains("does not authenticate the file"));
    }

    #[test]
    fn cross_check_requires_every_prediction_field_to_match() {
        let (_, primary, _) = output_fixture();
        ensure_predictions_match(&primary, &primary).unwrap();

        let mut changed = primary.clone();
        changed.expected_runtime_singleton = address!("4444444444444444444444444444444444444444");
        assert!(ensure_predictions_match(&primary, &changed).is_err());
        changed = primary.clone();
        changed.salt = B256::ZERO;
        assert!(ensure_predictions_match(&primary, &changed).is_err());
        changed = primary.clone();
        changed.address = address!("4444444444444444444444444444444444444444");
        assert!(ensure_predictions_match(&primary, &changed).is_err());
        changed = primary.clone();
        changed.chain_id = 1;
        assert!(ensure_predictions_match(&primary, &changed).is_err());
    }

    #[test]
    fn built_in_public_rpc_requires_explicit_opt_in() {
        assert!(select_rpc(None, None, None, false).is_err());
        let selected = select_rpc(None, None, None, true).unwrap();
        assert_eq!(
            selected.endpoint.url.as_str(),
            "https://ethereum-rpc.publicnode.com/"
        );
        assert_eq!(selected.expected_chain_id, Some(1));
    }

    #[test]
    fn custom_rpc_can_be_pinned_to_a_named_chain() {
        let selected = select_rpc(
            Some("https://rpc.example"),
            Some(ChainArg::World),
            None,
            false,
        )
        .unwrap();
        assert_eq!(selected.endpoint.url.as_str(), "https://rpc.example/");
        assert_eq!(selected.expected_chain_id, Some(480));

        let unpinned = select_rpc(Some("https://rpc.example"), None, None, false).unwrap();
        assert_eq!(unpinned.expected_chain_id, None);
    }

    #[test]
    fn deployment_artifact_selects_and_pins_its_chain() {
        let selected = select_rpc(None, None, Some(480), true).unwrap();
        assert_eq!(
            selected.endpoint.url.as_str(),
            "https://worldchain-mainnet.g.alchemy.com/public"
        );
        assert_eq!(selected.expected_chain_id, Some(480));

        assert!(select_rpc(None, None, Some(999_999), true).is_err());

        let custom = select_rpc(Some("https://rpc.example"), None, Some(999_999), false).unwrap();
        assert_eq!(custom.expected_chain_id, Some(999_999));

        let retargeted = select_rpc(None, Some(ChainArg::Base), Some(8_453), true).unwrap();
        assert_eq!(retargeted.expected_chain_id, Some(8_453));
        assert_eq!(
            retargeted.endpoint.url.as_str(),
            "https://mainnet.base.org/"
        );
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
            "--confirm-address",
            TEST_ADDRESS,
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
            "--confirm-address",
            TEST_ADDRESS,
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
