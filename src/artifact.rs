//! Durable, strict deployment artifacts for generated counterfactual Safes.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use alloy::primitives::{Address, B256, Bytes};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tempfile::Builder;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{
    config::SafeConfig,
    deployment::{Prediction, SAFE_PROXY_FACTORY, SAFE_VERSION, SafeVariant},
};

const ARTIFACT_FORMAT: &str = "incognito-safe-deployment";
const ARTIFACT_FORMAT_VERSION: u32 = 2;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024;

/// Every deterministic input and expected output needed to deploy one Safe.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentArtifact {
    pub format: String,
    pub format_version: u32,
    pub created_at: String,
    pub safe_version: String,
    pub chain_id: u64,
    pub variant: String,
    pub chain_specific: bool,
    pub seed: B256,
    pub predicted_address: Address,
    pub factory: Address,
    pub singleton: Address,
    pub expected_runtime_singleton: Address,
    pub initializer: Bytes,
    pub salt: B256,
    pub signers: Vec<Address>,
    pub threshold: u64,
}

impl DeploymentArtifact {
    /// Creates a new artifact stamped with the current UTC time.
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp cannot be formatted as RFC 3339.
    pub fn from_prediction(config: &SafeConfig, prediction: &Prediction) -> Result<Self> {
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format artifact creation timestamp")?;
        Ok(Self {
            format: ARTIFACT_FORMAT.to_owned(),
            format_version: ARTIFACT_FORMAT_VERSION,
            created_at,
            safe_version: SAFE_VERSION.to_owned(),
            chain_id: prediction.chain_id,
            variant: prediction.variant.as_str().to_owned(),
            chain_specific: prediction.chain_specific,
            seed: prediction.seed,
            predicted_address: prediction.address,
            factory: SAFE_PROXY_FACTORY,
            singleton: prediction.singleton,
            expected_runtime_singleton: prediction.expected_runtime_singleton,
            initializer: prediction.initializer.clone(),
            salt: prediction.salt,
            signers: config.signers.clone(),
            threshold: config.threshold,
        })
    }

    /// Returns and validates the Safe owner configuration embedded in the artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner configuration violates Safe invariants.
    pub fn config(&self) -> Result<SafeConfig> {
        let config = SafeConfig {
            signers: self.signers.clone(),
            threshold: self.threshold,
        };
        config.validate()?;
        config.validate_predicted_address(self.predicted_address)?;
        Ok(config)
    }

    /// Parses the initialization variant embedded in the artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact names an unsupported variant.
    pub fn safe_variant(&self) -> Result<SafeVariant> {
        match self.variant.as_str() {
            "portable" => Ok(SafeVariant::Portable),
            "l1" => Ok(SafeVariant::L1),
            "l2" => Ok(SafeVariant::L2),
            unknown => bail!("unsupported artifact Safe variant `{unknown}`"),
        }
    }

    /// Validates format-level invariants before any RPC operation is attempted.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported format/version or invalid deployment input.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == ARTIFACT_FORMAT,
            "unsupported deployment artifact format `{}`",
            self.format
        );
        ensure!(
            self.format_version == ARTIFACT_FORMAT_VERSION,
            "unsupported deployment artifact version {} (expected {ARTIFACT_FORMAT_VERSION})",
            self.format_version
        );
        ensure!(
            self.safe_version == SAFE_VERSION,
            "artifact Safe version {} is unsupported (expected {SAFE_VERSION})",
            self.safe_version
        );
        let created_at = OffsetDateTime::parse(&self.created_at, &Rfc3339)
            .context("artifact `created_at` is not a valid RFC 3339 timestamp")?;
        ensure!(
            created_at.offset() == UtcOffset::UTC,
            "artifact `created_at` timestamp must use UTC"
        );
        ensure!(
            created_at.format(&Rfc3339)? == self.created_at,
            "artifact `created_at` timestamp is not canonical RFC 3339"
        );
        ensure!(self.chain_id != 0, "artifact chain ID cannot be zero");
        ensure!(self.seed != B256::ZERO, "artifact seed cannot be zero");
        ensure!(
            self.predicted_address != Address::ZERO,
            "artifact predicted address cannot be zero"
        );
        ensure!(
            self.factory == SAFE_PROXY_FACTORY,
            "artifact factory {} does not match Safe v{SAFE_VERSION} factory {SAFE_PROXY_FACTORY}",
            self.factory
        );
        ensure!(
            self.singleton != Address::ZERO && self.expected_runtime_singleton != Address::ZERO,
            "artifact singleton addresses cannot be zero"
        );
        ensure!(
            !self.initializer.is_empty(),
            "artifact initializer cannot be empty"
        );
        self.safe_variant()?;
        self.config()?;
        Ok(())
    }

    /// Verifies that a fresh prediction exactly matches every redundant artifact field.
    ///
    /// # Errors
    ///
    /// Returns an error when any recomputed field differs from the saved artifact.
    pub fn verify_prediction(&self, prediction: &Prediction) -> Result<()> {
        ensure!(prediction.seed == self.seed, "artifact seed mismatch");
        ensure!(
            prediction.address == self.predicted_address,
            "artifact predicted address {} does not match recomputed address {}",
            self.predicted_address,
            prediction.address
        );
        ensure!(
            prediction.chain_id == self.chain_id,
            "artifact chain ID mismatch"
        );
        ensure!(
            prediction.variant.as_str() == self.variant,
            "artifact Safe variant mismatch"
        );
        ensure!(
            prediction.chain_specific == self.chain_specific,
            "artifact chain-specific setting mismatch"
        );
        ensure!(
            prediction.singleton == self.singleton,
            "artifact singleton mismatch"
        );
        ensure!(
            prediction.expected_runtime_singleton == self.expected_runtime_singleton,
            "artifact runtime singleton mismatch"
        );
        ensure!(
            prediction.initializer == self.initializer,
            "artifact initializer mismatch"
        );
        ensure!(
            prediction.salt == self.salt,
            "artifact CREATE2 salt mismatch"
        );
        Ok(())
    }
}

/// Writes an artifact with owner-only permissions and refuses to replace any file.
///
/// # Errors
///
/// Returns an error for invalid artifacts, unsafe output paths, serialization or I/O
/// failures, or an existing artifact with the same predicted-address filename.
pub fn write_unique_artifact(output_dir: &Path, artifact: &DeploymentArtifact) -> Result<PathBuf> {
    artifact.validate()?;
    let output_dir = fs::canonicalize(output_dir).with_context(|| {
        format!(
            "failed to resolve output directory {}",
            output_dir.display()
        )
    })?;
    ensure!(
        output_dir.is_dir(),
        "artifact output path is not a directory: {}",
        output_dir.display()
    );
    let filename = format!(
        "incognito-safe-deployment-{:#x}.json",
        artifact.predicted_address
    );
    let path = output_dir.join(filename);

    let mut temporary = Builder::new()
        .prefix(".incognito-safe-artifact-")
        .tempfile_in(&output_dir)
        .with_context(|| {
            format!(
                "failed to create temporary artifact in {}",
                output_dir.display()
            )
        })?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), artifact)
        .context("failed to serialize deployment artifact")?;
    temporary
        .write_all(b"\n")
        .context("failed to finish deployment artifact")?;
    temporary
        .as_file()
        .sync_all()
        .context("failed to sync deployment artifact")?;
    temporary.persist_noclobber(&path).map_err(|error| {
        anyhow::anyhow!(
            "refusing to overwrite deployment artifact {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(path)
}

/// Loads a strict, size-limited, owner-readable deployment artifact.
///
/// # Errors
///
/// Returns an error for unsafe file types/permissions, oversized or invalid JSON,
/// unsupported schemas, or invalid embedded deployment inputs.
pub fn load_artifact(path: &Path) -> Result<DeploymentArtifact> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect deployment artifact {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "deployment artifact is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_ARTIFACT_BYTES,
        "deployment artifact exceeds the {MAX_ARTIFACT_BYTES}-byte limit"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        ensure!(
            mode.trailing_zeros() >= 6,
            "deployment artifact is accessible by other users; run `chmod 600 {}`",
            path.display()
        );
    }

    let input = fs::read(path)
        .with_context(|| format!("failed to read deployment artifact {}", path.display()))?;
    let artifact: DeploymentArtifact =
        serde_json::from_slice(&input).context("invalid deployment artifact JSON")?;
    artifact.validate()?;
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, b256, bytes};

    use super::*;

    fn fixture() -> (SafeConfig, Prediction) {
        let config = SafeConfig {
            signers: vec![address!("1111111111111111111111111111111111111111")],
            threshold: 1,
        };
        let prediction = Prediction {
            address: address!("2222222222222222222222222222222222222222"),
            chain_id: 1,
            seed: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            singleton: address!("Ff51A5898e281Db6DfC7855790607438dF2ca44b"),
            expected_runtime_singleton: address!("Ff51A5898e281Db6DfC7855790607438dF2ca44b"),
            initializer: bytes!("1234"),
            salt: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            variant: SafeVariant::Portable,
            chain_specific: false,
        };
        (config, prediction)
    }

    #[test]
    fn secure_round_trip_and_no_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let path = write_unique_artifact(directory.path(), &artifact).unwrap();
        let loaded = load_artifact(&path).unwrap();
        loaded.verify_prediction(&prediction).unwrap();
        assert_eq!(loaded.config().unwrap(), config);
        assert!(write_unique_artifact(directory.path(), &artifact).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_and_changed_prediction() {
        let (config, prediction) = fixture();
        let mut artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let mut invalid_timestamp = artifact.clone();
        invalid_timestamp.created_at = "2026-08-25T12:00:00+02:00".to_owned();
        assert!(invalid_timestamp.validate().is_err());

        artifact.salt = B256::ZERO;
        assert!(artifact.verify_prediction(&prediction).is_err());

        let encoded = serde_json::to_string(&artifact).unwrap();
        let with_unknown = encoded.replacen('{', "{\"unknown\":true,", 1);
        assert!(serde_json::from_str::<DeploymentArtifact>(&with_unknown).is_err());
    }
}
