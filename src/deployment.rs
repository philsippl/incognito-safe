//! Safe v1.5.0 initialization, CREATE2 prediction, deployment, and verification.

use std::str::FromStr;

use alloy::{
    primitives::{Address, B256, Bytes, U256, address, b256, keccak256},
    providers::Provider,
    sol_types::SolCall,
};
use anyhow::{Context, Result, bail, ensure};

use crate::{
    config::{MAX_SIGNERS, SafeConfig},
    contracts::{ISafe, ISafeProxy, ISafeProxyFactory, ISafeToL2Setup},
};

pub const SAFE_VERSION: &str = "1.5.0";

pub const SAFE_PROXY_FACTORY: Address = address!("14F2982D601c9458F93bd70B218933A6f8165e7b");

const FACTORY: ContractSpec = ContractSpec {
    address: SAFE_PROXY_FACTORY,
    code_hash: b256!("967dae4cda22b0c9ef7f31b010bdc1ceb0af9904b0c3dc060b5302e4c18a4529"),
    name: "SafeProxyFactory v1.5.0",
};
const L1_SINGLETON: ContractSpec = ContractSpec {
    address: address!("Ff51A5898e281Db6DfC7855790607438dF2ca44b"),
    code_hash: b256!("dda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2"),
    name: "Safe v1.5.0",
};
const L2_SINGLETON: ContractSpec = ContractSpec {
    address: address!("Edd160fEBBD92E350D4D398fb636302fccd67C7e"),
    code_hash: b256!("180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc"),
    name: "SafeL2 v1.5.0",
};
const SAFE_TO_L2_SETUP: ContractSpec = ContractSpec {
    address: address!("900C7589200010D6C6eCaaE5B06EBe653bc2D82a"),
    code_hash: b256!("f6034d841bcbff8912aa55526b0f1609212536aaf60bb16f5e8a269a4ab38f18"),
    name: "SafeToL2Setup v1.5.0",
};
const FALLBACK_HANDLER: ContractSpec = ContractSpec {
    address: address!("3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4"),
    code_hash: b256!("3c6a85bcf7b563daa624b884b4e9a1b9fa5371edde7be945d998071a48f28bbc"),
    name: "CompatibilityFallbackHandler v1.5.0",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContractSpec {
    address: Address,
    code_hash: B256,
    name: &'static str,
}

/// Selects how the proxy singleton is initialized.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SafeVariant {
    /// Official cross-chain setup: L1 singleton on chain 1, L2 singleton elsewhere.
    #[default]
    Portable,
    /// Always retain the L1 singleton.
    L1,
    /// Initialize directly against the L2 singleton.
    L2,
}

impl SafeVariant {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::L1 => "l1",
            Self::L2 => "l2",
        }
    }
}

/// Returns the singleton that a deployed proxy must use on the target chain.
#[must_use]
pub const fn expected_runtime_singleton(chain_id: u64, variant: SafeVariant) -> Address {
    match variant {
        SafeVariant::Portable if chain_id != 1 => L2_SINGLETON.address,
        SafeVariant::Portable | SafeVariant::L1 => L1_SINGLETON.address,
        SafeVariant::L2 => L2_SINGLETON.address,
    }
}

/// All deterministic inputs and results needed to deploy a Safe.
#[derive(Clone, Debug)]
pub struct Prediction {
    pub address: Address,
    pub chain_id: u64,
    pub seed: B256,
    pub singleton: Address,
    pub expected_runtime_singleton: Address,
    pub initializer: Bytes,
    pub salt: B256,
    pub variant: SafeVariant,
    pub chain_specific: bool,
}

/// Confirmed transaction details returned after post-deployment verification.
#[derive(Clone, Debug)]
pub struct DeploymentReceipt {
    pub address: Address,
    pub transaction_hash: B256,
    pub block_number: u64,
    pub runtime_singleton: Address,
}

/// Obtains a cryptographically secure, full-width CREATE2 nonce.
///
/// # Errors
///
/// Returns an error if the operating system CSPRNG is unavailable.
pub fn generate_seed() -> Result<B256> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS randomness failed: {error}"))?;
    Ok(B256::from(bytes))
}

/// Parses the exact 32-byte hex representation emitted by `generate`.
///
/// # Errors
///
/// Returns an error unless `input` is a nonzero, full-width 32-byte hex value.
pub fn parse_seed(input: &str) -> Result<B256> {
    ensure!(
        input.len() == 66 && input.starts_with("0x"),
        "seed must be exactly 32 bytes encoded as 0x followed by 64 hex characters"
    );
    let seed = B256::from_str(input).context("seed contains invalid hexadecimal")?;
    ensure!(seed != B256::ZERO, "the all-zero seed is forbidden");
    Ok(seed)
}

/// Reads owners and threshold from an already-deployed Safe-compatible contract.
///
/// # Errors
///
/// Returns an error for missing code, failed RPC/ABI calls, or an owner
/// configuration that violates the local Safe invariants.
pub async fn fetch_safe_config<P: Provider>(
    provider: &P,
    safe_address: Address,
) -> Result<SafeConfig> {
    ensure!(
        safe_address != Address::ZERO,
        "source Safe address cannot be zero"
    );
    let code = provider
        .get_code_at(safe_address)
        .await
        .with_context(|| format!("failed to read source Safe code at {safe_address}"))?;
    ensure!(
        !code.is_empty(),
        "source Safe has no contract code at {safe_address}"
    );

    let safe = ISafe::new(safe_address, provider);
    let signers = safe
        .getOwners()
        .call()
        .await
        .with_context(|| format!("{safe_address} does not expose Safe getOwners()"))?;
    ensure!(
        signers.len() <= MAX_SIGNERS,
        "source Safe has too many signers (maximum {MAX_SIGNERS})"
    );
    let raw_threshold = safe
        .getThreshold()
        .call()
        .await
        .with_context(|| format!("{safe_address} does not expose Safe getThreshold()"))?;
    let threshold = u64::try_from(raw_threshold).context("source threshold does not fit in u64")?;

    let config = SafeConfig { signers, threshold };
    config
        .validate()
        .context("source Safe returned an invalid owner configuration")?;
    Ok(config)
}

/// Verifies the official contracts on the selected RPC and predicts the counterfactual address.
///
/// # Errors
///
/// Returns an error for invalid inputs, RPC failures, missing or hash-mismatched
/// official contracts, an invalid factory response, or a self-owning prediction.
pub async fn predict_safe<P: Provider>(
    provider: &P,
    config: &SafeConfig,
    seed: B256,
    variant: SafeVariant,
    chain_specific: bool,
) -> Result<Prediction> {
    config.validate()?;
    ensure!(seed != B256::ZERO, "the all-zero seed is forbidden");

    let chain_id = provider
        .get_chain_id()
        .await
        .context("failed to query chain ID")?;
    verify_required_contracts(provider, variant).await?;

    let singleton = match variant {
        SafeVariant::Portable | SafeVariant::L1 => L1_SINGLETON.address,
        SafeVariant::L2 => L2_SINGLETON.address,
    };
    let expected_runtime_singleton = expected_runtime_singleton(chain_id, variant);
    let initializer = build_initializer(config, variant);
    let factory = ISafeProxyFactory::new(FACTORY.address, provider);
    let proxy_creation_code = factory
        .proxyCreationCode()
        .call()
        .await
        .context("verified factory failed to return proxy creation code")?;
    ensure!(
        !proxy_creation_code.is_empty(),
        "factory returned empty proxy creation code"
    );

    let salt = safe_salt(&initializer, seed, chain_specific.then_some(chain_id));
    let address = safe_create2_address(FACTORY.address, singleton, &proxy_creation_code, salt);
    config.validate_predicted_address(address)?;

    // Do not simulate the factory deployment here: its calldata would disclose
    // the secret seed and complete owner initializer to the RPC. `deploy_safe`
    // performs that validation immediately before signing instead.
    Ok(Prediction {
        address,
        chain_id,
        seed,
        singleton,
        expected_runtime_singleton,
        initializer,
        salt,
        variant,
        chain_specific,
    })
}

/// Sends the factory call and verifies the deployed Safe before returning success.
///
/// # Errors
///
/// Returns an error if the chain changes, the target is occupied, simulation or
/// submission fails, the transaction reverts, or final Safe verification fails.
pub async fn deploy_safe<P: Provider>(
    provider: &P,
    config: &SafeConfig,
    prediction: &Prediction,
) -> Result<DeploymentReceipt> {
    // Repeat every derivation and bytecode check through the signing provider to
    // close the gap between a read-only prediction and the state used to send.
    let rederived = predict_safe(
        provider,
        config,
        prediction.seed,
        prediction.variant,
        prediction.chain_specific,
    )
    .await
    .context("pre-send revalidation failed")?;
    ensure_rederived_prediction(prediction, &rederived)?;
    let existing = provider
        .get_code_at(prediction.address)
        .await
        .context("failed to check predicted address occupancy")?;
    ensure!(
        existing.is_empty(),
        "predicted address {} already contains code; refusing to send",
        prediction.address
    );

    let factory = ISafeProxyFactory::new(FACTORY.address, provider);
    let nonce = U256::from_be_bytes(prediction.seed.0);
    let pending = if prediction.chain_specific {
        let call = factory
            .createChainSpecificProxyWithNonceL2(
                prediction.singleton,
                prediction.initializer.clone(),
                nonce,
            )
            .chain_id(prediction.chain_id);
        let simulated = call
            .call()
            .await
            .context("deployment simulation reverted")?;
        ensure!(
            simulated == prediction.address,
            "factory simulation returned {simulated}, expected {}",
            prediction.address
        );
        call.send()
            .await
            .context("failed to submit deployment transaction")?
    } else {
        let call = factory
            .createProxyWithNonceL2(prediction.singleton, prediction.initializer.clone(), nonce)
            .chain_id(prediction.chain_id);
        let simulated = call
            .call()
            .await
            .context("deployment simulation reverted")?;
        ensure!(
            simulated == prediction.address,
            "factory simulation returned {simulated}, expected {}",
            prediction.address
        );
        call.send()
            .await
            .context("failed to submit deployment transaction")?
    };

    let receipt = pending
        .get_receipt()
        .await
        .context("deployment transaction was not confirmed")?;
    ensure!(
        receipt.status(),
        "deployment transaction reverted: {}",
        receipt.transaction_hash
    );

    let runtime_singleton = verify_deployed_safe(provider, config, prediction).await?;
    let block_number = receipt
        .block_number
        .context("confirmed receipt did not contain a block number")?;
    Ok(DeploymentReceipt {
        address: prediction.address,
        transaction_hash: receipt.transaction_hash,
        block_number,
        runtime_singleton,
    })
}

fn ensure_rederived_prediction(expected: &Prediction, rederived: &Prediction) -> Result<()> {
    ensure!(
        rederived.chain_id == expected.chain_id,
        "RPC chain changed from {} to {} before deployment",
        expected.chain_id,
        rederived.chain_id
    );
    ensure!(
        rederived.address == expected.address
            && rederived.singleton == expected.singleton
            && rederived.expected_runtime_singleton == expected.expected_runtime_singleton
            && rederived.initializer == expected.initializer
            && rederived.salt == expected.salt,
        "deployment inputs changed during pre-send revalidation"
    );
    Ok(())
}

/// Verifies code, singleton, version, owners, and threshold after deployment.
///
/// # Errors
///
/// Returns an error on an RPC/ABI failure or any mismatch with the prediction
/// and requested Safe configuration.
pub async fn verify_deployed_safe<P: Provider>(
    provider: &P,
    config: &SafeConfig,
    prediction: &Prediction,
) -> Result<Address> {
    let code = provider
        .get_code_at(prediction.address)
        .await
        .context("failed to read deployed Safe code")?;
    ensure!(
        !code.is_empty(),
        "transaction succeeded but predicted address has no code"
    );

    let proxy = ISafeProxy::new(prediction.address, provider);
    let runtime_singleton = proxy
        .masterCopy()
        .call()
        .await
        .context("masterCopy() check failed")?;
    ensure!(
        runtime_singleton == prediction.expected_runtime_singleton,
        "unexpected runtime singleton {runtime_singleton}; expected {}",
        prediction.expected_runtime_singleton
    );

    let safe = ISafe::new(prediction.address, provider);
    let version = safe
        .VERSION()
        .call()
        .await
        .context("Safe VERSION() check failed")?;
    ensure!(
        version == SAFE_VERSION,
        "unexpected Safe version {version}; expected {SAFE_VERSION}"
    );
    let owners = safe
        .getOwners()
        .call()
        .await
        .context("post-deployment getOwners() failed")?;
    ensure!(
        owners == config.signers,
        "deployed owner list does not exactly match the requested order"
    );
    let threshold = safe
        .getThreshold()
        .call()
        .await
        .context("post-deployment getThreshold() failed")?;
    ensure!(
        threshold == U256::from(config.threshold),
        "deployed threshold {threshold} does not match requested threshold {}",
        config.threshold
    );
    Ok(runtime_singleton)
}

/// Builds the exact initializer passed atomically by `SafeProxyFactory`.
#[must_use]
pub fn build_initializer(config: &SafeConfig, variant: SafeVariant) -> Bytes {
    let (to, data) = if variant == SafeVariant::Portable {
        let data = ISafeToL2Setup::setupToL2Call {
            l2Singleton: L2_SINGLETON.address,
        }
        .abi_encode();
        (SAFE_TO_L2_SETUP.address, Bytes::from(data))
    } else {
        (Address::ZERO, Bytes::new())
    };

    Bytes::from(
        ISafe::setupCall {
            owners: config.signers.clone(),
            threshold: U256::from(config.threshold),
            to,
            data,
            fallbackHandler: FALLBACK_HANDLER.address,
            paymentToken: Address::ZERO,
            payment: U256::ZERO,
            paymentReceiver: Address::ZERO,
        }
        .abi_encode(),
    )
}

/// Implements `SafeProxyFactory`'s salt formula exactly.
#[must_use]
pub fn safe_salt(initializer: &[u8], seed: B256, chain_id: Option<u64>) -> B256 {
    let mut packed = Vec::with_capacity(if chain_id.is_some() { 96 } else { 64 });
    packed.extend_from_slice(keccak256(initializer).as_slice());
    packed.extend_from_slice(seed.as_slice());
    if let Some(chain_id) = chain_id {
        packed.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    }
    keccak256(packed)
}

/// Computes the Safe proxy CREATE2 address from factory-returned proxy creation code.
#[must_use]
pub fn safe_create2_address(
    factory: Address,
    singleton: Address,
    proxy_creation_code: &[u8],
    salt: B256,
) -> Address {
    let mut deployment_data = Vec::with_capacity(proxy_creation_code.len() + 32);
    deployment_data.extend_from_slice(proxy_creation_code);
    deployment_data
        .extend_from_slice(&U256::from_be_slice(singleton.as_slice()).to_be_bytes::<32>());
    create2_address(factory, salt, &deployment_data)
}

/// The EIP-1014 CREATE2 formula, exposed for independent test vectors.
#[must_use]
pub fn create2_address(deployer: Address, salt: B256, init_code: &[u8]) -> Address {
    let mut preimage = Vec::with_capacity(85);
    preimage.push(0xff);
    preimage.extend_from_slice(deployer.as_slice());
    preimage.extend_from_slice(salt.as_slice());
    preimage.extend_from_slice(keccak256(init_code).as_slice());
    let hash = keccak256(preimage);
    Address::from_slice(&hash[12..])
}

async fn verify_required_contracts<P: Provider>(provider: &P, variant: SafeVariant) -> Result<()> {
    verify_contract(provider, FACTORY).await?;
    verify_contract(provider, FALLBACK_HANDLER).await?;
    match variant {
        SafeVariant::Portable => {
            verify_contract(provider, L1_SINGLETON).await?;
            verify_contract(provider, L2_SINGLETON).await?;
            verify_contract(provider, SAFE_TO_L2_SETUP).await?;
        }
        SafeVariant::L1 => verify_contract(provider, L1_SINGLETON).await?,
        SafeVariant::L2 => verify_contract(provider, L2_SINGLETON).await?,
    }
    Ok(())
}

async fn verify_contract<P: Provider>(provider: &P, spec: ContractSpec) -> Result<()> {
    let code = provider
        .get_code_at(spec.address)
        .await
        .with_context(|| format!("failed to read {} at {}", spec.name, spec.address))?;
    if code.is_empty() {
        bail!(
            "{} is not deployed at {} on this chain; Safe v{SAFE_VERSION} is unsupported by this RPC",
            spec.name,
            spec.address
        );
    }
    let actual = keccak256(&code);
    ensure!(
        actual == spec.code_hash,
        "{} bytecode hash mismatch at {}: got {actual}, expected {}; refusing an unverified deployment",
        spec.name,
        spec.address,
        spec.code_hash
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prediction_fixture() -> Prediction {
        Prediction {
            address: address!("2222222222222222222222222222222222222222"),
            chain_id: 480,
            seed: b256!("0101010101010101010101010101010101010101010101010101010101010101"),
            singleton: L1_SINGLETON.address,
            expected_runtime_singleton: L2_SINGLETON.address,
            initializer: Bytes::from_static(b"initializer"),
            salt: b256!("0202020202020202020202020202020202020202020202020202020202020202"),
            variant: SafeVariant::Portable,
            chain_specific: false,
        }
    }

    #[test]
    fn matches_eip_1014_vectors() {
        assert_eq!(
            create2_address(Address::ZERO, B256::ZERO, &[0]),
            address!("4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38")
        );
        assert_eq!(
            create2_address(Address::ZERO, B256::ZERO, &[0xde, 0xad, 0xbe, 0xef]),
            address!("70f2b2914A2a4b783FaEFb75f459A580616Fcb5e")
        );
    }

    #[test]
    fn safe_salt_separates_initializer_seed_and_chain() {
        let seed = b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let base = safe_salt(b"initializer", seed, None);
        assert_ne!(base, safe_salt(b"initializer2", seed, None));
        assert_ne!(base, safe_salt(b"initializer", B256::ZERO, None));
        assert_ne!(base, safe_salt(b"initializer", seed, Some(1)));
        assert_ne!(
            safe_salt(b"initializer", seed, Some(1)),
            safe_salt(b"initializer", seed, Some(10))
        );
    }

    #[test]
    fn initializer_is_deterministic_and_variant_sensitive() {
        let config = SafeConfig {
            signers: vec![address!("1111111111111111111111111111111111111111")],
            threshold: 1,
        };
        assert_eq!(
            build_initializer(&config, SafeVariant::Portable),
            build_initializer(&config, SafeVariant::Portable)
        );
        assert_ne!(
            build_initializer(&config, SafeVariant::Portable),
            build_initializer(&config, SafeVariant::L1)
        );
        assert_eq!(
            build_initializer(&config, SafeVariant::L1),
            build_initializer(&config, SafeVariant::L2)
        );
    }

    #[test]
    fn runtime_singleton_depends_on_effective_variant_and_chain() {
        assert_eq!(
            expected_runtime_singleton(1, SafeVariant::Portable),
            L1_SINGLETON.address
        );
        assert_eq!(
            expected_runtime_singleton(480, SafeVariant::Portable),
            L2_SINGLETON.address
        );
        assert_eq!(
            expected_runtime_singleton(480, SafeVariant::L1),
            L1_SINGLETON.address
        );
        assert_eq!(
            expected_runtime_singleton(1, SafeVariant::L2),
            L2_SINGLETON.address
        );
    }

    #[test]
    fn pre_send_rederivation_checks_runtime_singleton_and_chain() {
        let expected = prediction_fixture();
        ensure_rederived_prediction(&expected, &expected).unwrap();

        let mut changed = expected.clone();
        changed.expected_runtime_singleton = L1_SINGLETON.address;
        assert!(ensure_rederived_prediction(&expected, &changed).is_err());

        changed = expected.clone();
        changed.chain_id = 1;
        assert!(ensure_rederived_prediction(&expected, &changed).is_err());
    }

    #[test]
    fn seed_parser_requires_full_width_nonzero_hex() {
        let good = "0x1111111111111111111111111111111111111111111111111111111111111111";
        assert!(parse_seed(good).is_ok());
        assert!(parse_seed("0x01").is_err());
        assert!(parse_seed(&format!("0x{}", "0".repeat(64))).is_err());
        assert!(parse_seed(&format!("0x{}", "z".repeat(64))).is_err());
    }
}
