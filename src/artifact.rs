//! Durable, strict deployment artifacts for generated counterfactual Safes.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use alloy::primitives::{Address, B256, Bytes};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tempfile::Builder;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{
    config::SafeConfig,
    deployment::{
        Prediction, SAFE_PROXY_FACTORY, SAFE_VERSION, SafeVariant, expected_runtime_singleton,
    },
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
        let variant = self.safe_variant()?;
        ensure!(
            self.expected_runtime_singleton == expected_runtime_singleton(self.chain_id, variant),
            "artifact runtime singleton is not canonical for chain {} and variant {}",
            self.chain_id,
            self.variant
        );
        self.config()?;
        Ok(())
    }

    /// Verifies that a fresh prediction exactly matches every redundant artifact field.
    ///
    /// # Errors
    ///
    /// Returns an error when any recomputed field differs from the saved artifact.
    pub fn verify_prediction(&self, prediction: &Prediction) -> Result<()> {
        self.validate()?;
        self.verify_exact_prediction_fields(prediction)
    }

    fn verify_exact_prediction_fields(&self, prediction: &Prediction) -> Result<()> {
        self.verify_chain_independent_prediction_fields(prediction)?;
        ensure!(
            prediction.chain_id == self.chain_id,
            "artifact chain ID mismatch"
        );
        ensure!(
            prediction.expected_runtime_singleton == self.expected_runtime_singleton,
            "artifact runtime singleton mismatch"
        );
        Ok(())
    }

    /// Returns whether this artifact can target `chain_id` without changing its address.
    ///
    /// Artifacts always allow their original chain. Cross-chain reuse is limited to the
    /// portable variant with chain-specific salting disabled.
    #[must_use]
    pub fn allows_target_chain(&self, chain_id: u64) -> bool {
        if chain_id == 0 || self.chain_id == 0 {
            return false;
        }
        let Ok(variant) = self.safe_variant() else {
            return false;
        };
        chain_id == self.chain_id || (variant == SafeVariant::Portable && !self.chain_specific)
    }

    /// Verifies a prediction for either the artifact's original chain or a portable target.
    ///
    /// The original chain must match exactly. A cross-chain prediction may differ only in
    /// its chain ID and expected runtime singleton, which is chain-dependent for the
    /// portable variant.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is invalid, the target chain is not allowed, or
    /// any chain-independent prediction field differs from the saved artifact.
    pub fn verify_prediction_for_target(&self, prediction: &Prediction) -> Result<()> {
        self.validate()?;
        ensure!(
            self.allows_target_chain(prediction.chain_id),
            "artifact for chain {} cannot target chain {}; cross-chain reuse requires the portable variant with chain-specific salting disabled",
            self.chain_id,
            prediction.chain_id
        );
        ensure!(
            prediction.expected_runtime_singleton
                == expected_runtime_singleton(prediction.chain_id, prediction.variant),
            "target runtime singleton is not canonical for chain {} and variant {}",
            prediction.chain_id,
            prediction.variant.as_str()
        );
        if prediction.chain_id == self.chain_id {
            return self.verify_exact_prediction_fields(prediction);
        }
        self.verify_chain_independent_prediction_fields(prediction)
    }

    fn verify_chain_independent_prediction_fields(&self, prediction: &Prediction) -> Result<()> {
        ensure!(prediction.seed == self.seed, "artifact seed mismatch");
        ensure!(
            prediction.address == self.predicted_address,
            "artifact predicted address {} does not match recomputed address {}",
            self.predicted_address,
            prediction.address
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
/// The output directory's parent must be trusted and not attacker-writable. Final-component
/// validation and later path-based temporary-file operations are not one atomic filesystem
/// operation, so portable Rust APIs cannot close that replacement race without changing the
/// supported intermediate-symlink behavior.
///
/// File contents are synced before persistence. Parent/output directories are also synced on
/// Unix when the filesystem supports directory sync; other platforms and filesystems retain
/// their native directory-entry crash-durability limits.
///
/// # Errors
///
/// Returns an error for invalid artifacts, unsafe output paths, serialization or I/O
/// failures, or an existing artifact with the same predicted-address filename.
pub fn write_unique_artifact(output_dir: &Path, artifact: &DeploymentArtifact) -> Result<PathBuf> {
    artifact.validate()?;
    let output_dir = normalize_output_path_suffix(output_dir);
    match fs::symlink_metadata(&output_dir) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_dir(),
            "artifact output path is not a directory: {}",
            output_dir.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&output_dir).with_context(|| {
                format!(
                    "failed to create artifact output directory {}",
                    output_dir.display()
                )
            })?;
            let parent = output_dir
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            sync_directory(parent).with_context(|| {
                format!(
                    "created artifact output directory {} but failed to sync its parent {}",
                    output_dir.display(),
                    parent.display()
                )
            })?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect artifact output directory {}",
                    output_dir.display()
                )
            });
        }
    }
    let output_dir = fs::canonicalize(&output_dir).with_context(|| {
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
    let persisted = temporary.persist_noclobber(&path).map_err(|error| {
        anyhow::anyhow!(
            "refusing to overwrite deployment artifact {}: {}",
            path.display(),
            error.error
        )
    })?;
    drop(persisted);
    sync_directory(&output_dir).with_context(|| {
        format!(
            "artifact {} was persisted but its output directory could not be synced",
            path.display()
        )
    })?;
    Ok(path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    let directory = File::open(path)?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        // Some Unix filesystems do not implement directory fsync. The file itself was
        // synced before persistence, but crash durability of the directory entry is then
        // limited by that filesystem.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    // `std` does not expose a portable directory handle that can be synced on all targets.
    Ok(())
}

#[cfg(unix)]
fn normalize_output_path_suffix(path: &Path) -> PathBuf {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    if path.file_name().is_none() {
        return path.to_owned();
    }
    let bytes = path.as_os_str().as_bytes();
    let root_end = bytes.iter().take_while(|byte| **byte == b'/').count();
    let mut end = bytes.len();
    loop {
        while end > root_end && bytes[end - 1] == b'/' {
            end -= 1;
        }
        if end == root_end {
            break;
        }
        let component_start = bytes[..end]
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(0, |position| position + 1);
        if &bytes[component_start..end] != b"." || component_start == root_end {
            break;
        }
        end = component_start;
    }
    PathBuf::from(OsStr::from_bytes(&bytes[..end]))
}

#[cfg(windows)]
fn normalize_output_path_suffix(path: &Path) -> PathBuf {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };

    if path.file_name().is_none() {
        return path.to_owned();
    }
    let mut units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    loop {
        while units
            .last()
            .is_some_and(|unit| matches!(*unit, 0x2f | 0x5c))
        {
            units.pop();
        }
        let component_start = units
            .iter()
            .rposition(|unit| matches!(*unit, 0x2f | 0x5c))
            .map_or(0, |position| position + 1);
        if units[component_start..] != [0x2e] || component_start == 0 {
            break;
        }
        units.truncate(component_start);
    }
    PathBuf::from(OsString::from_wide(&units))
}

#[cfg(not(any(unix, windows)))]
fn normalize_output_path_suffix(path: &Path) -> PathBuf {
    path.to_owned()
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

/// Loads a strict, size-limited, owner-readable deployment artifact.
///
/// Metadata and contents are read from one opened handle. Unix opens use `O_NOFOLLOW`; on
/// non-Unix targets, final-symlink behavior follows the platform's standard file-open rules.
///
/// # Errors
///
/// Returns an error for unsafe file types/permissions, oversized or invalid JSON,
/// unsupported schemas, or invalid embedded deployment inputs.
pub fn load_artifact(path: &Path) -> Result<DeploymentArtifact> {
    let file = open_artifact_for_read(path)
        .with_context(|| format!("failed to open deployment artifact {}", path.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened deployment artifact {}",
            path.display()
        )
    })?;
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

    let mut input = Vec::new();
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut input)
        .with_context(|| format!("failed to read deployment artifact {}", path.display()))?;
    ensure!(
        input.len() as u64 <= MAX_ARTIFACT_BYTES,
        "deployment artifact exceeds the {MAX_ARTIFACT_BYTES}-byte limit"
    );
    let artifact: DeploymentArtifact =
        serde_json::from_slice(&input).context("invalid deployment artifact JSON")?;
    artifact.validate()?;
    Ok(artifact)
}

#[cfg(unix)]
fn open_artifact_for_read(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_artifact_for_read(path: &Path) -> std::io::Result<File> {
    File::open(path)
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

    fn artifact_for(prediction: &Prediction) -> DeploymentArtifact {
        let (config, _) = fixture();
        DeploymentArtifact::from_prediction(&config, prediction).unwrap()
    }

    fn portable_cross_chain_prediction(prediction: &Prediction) -> Prediction {
        let mut target = prediction.clone();
        target.chain_id = 480;
        target.expected_runtime_singleton = address!("Edd160fEBBD92E350D4D398fb636302fccd67C7e");
        target
    }

    #[test]
    fn creates_private_output_leaf_and_preserves_secure_no_clobber_file() {
        let parent = tempfile::tempdir().unwrap();
        let output_dir = parent.path().join("saved-safes");
        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let path = write_unique_artifact(&output_dir, &artifact).unwrap();
        let loaded = load_artifact(&path).unwrap();
        loaded.verify_prediction(&prediction).unwrap();
        assert_eq!(loaded.config().unwrap(), config);
        assert!(write_unique_artifact(&output_dir, &artifact).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let output_mode = fs::metadata(output_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(output_mode & !0o700, 0);
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn leaves_existing_output_directory_permissions_unchanged() {
        let parent = tempfile::tempdir().unwrap();
        let output_dir = parent.path().join("existing");
        fs::create_dir(&output_dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o751)).unwrap();
        }

        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        write_unique_artifact(&output_dir, &artifact).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(output_dir).unwrap().permissions().mode() & 0o777,
                0o751
            );
        }
    }

    #[test]
    fn output_directory_parent_must_exist_and_final_file_is_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let missing_parent = parent.path().join("missing");
        let nested_output = missing_parent.join("saved-safes");
        assert!(write_unique_artifact(&nested_output, &artifact).is_err());
        assert!(!missing_parent.exists());

        let file_output = parent.path().join("not-a-directory");
        fs::write(&file_output, b"not a directory").unwrap();
        assert!(write_unique_artifact(&file_output, &artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn final_output_directory_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real_output = parent.path().join("real");
        fs::create_dir(&real_output).unwrap();
        let linked_output = parent.path().join("linked");
        symlink(&real_output, &linked_output).unwrap();

        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        assert!(write_unique_artifact(&linked_output, &artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn final_output_directory_symlink_with_trailing_separator_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real_output = parent.path().join("real");
        fs::create_dir(&real_output).unwrap();
        let linked_output = parent.path().join("linked-dir");
        symlink(&real_output, &linked_output).unwrap();
        let mut linked_with_separator = linked_output.into_os_string();
        linked_with_separator.push("/");

        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        assert!(write_unique_artifact(Path::new(&linked_with_separator), &artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn final_output_directory_symlink_with_current_directory_suffix_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real_output = parent.path().join("real");
        fs::create_dir(&real_output).unwrap();
        let linked_output = parent.path().join("linked-dir");
        symlink(&real_output, &linked_output).unwrap();

        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        for suffix in ["/.", "/./", "/.//./"] {
            let mut linked_with_suffix = linked_output.as_os_str().to_os_string();
            linked_with_suffix.push(suffix);
            assert!(
                write_unique_artifact(Path::new(&linked_with_suffix), &artifact).is_err(),
                "final symlink unexpectedly accepted with suffix {suffix}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_path_suffix_normalization_does_not_collapse_parent_components() {
        assert_eq!(
            normalize_output_path_suffix(Path::new("linked-parent/../.")),
            Path::new("linked-parent/..")
        );
        assert_eq!(
            normalize_output_path_suffix(Path::new("linked-parent/./saved-safes/.//")),
            Path::new("linked-parent/./saved-safes")
        );
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_output_directory_symlink_remains_supported() {
        use std::{os::unix::fs::PermissionsExt, os::unix::fs::symlink};

        let parent = tempfile::tempdir().unwrap();
        let real_parent = parent.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        let linked_parent = parent.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let output_dir = linked_parent.join("saved-safes");

        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let path = write_unique_artifact(&output_dir, &artifact).unwrap();

        assert!(path.starts_with(fs::canonicalize(&real_parent).unwrap()));
        let output_mode = fs::metadata(real_parent.join("saved-safes"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(output_mode & !0o700, 0);
    }

    #[test]
    fn oversized_artifact_is_rejected_from_the_opened_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.json");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
        drop(file);

        let error = load_artifact(&path).unwrap_err().to_string();
        assert!(error.contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let output_dir = parent.path().join("saved-safes");
        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let artifact_path = write_unique_artifact(&output_dir, &artifact).unwrap();
        let symlink_path = parent.path().join("artifact-link.json");
        symlink(&artifact_path, &symlink_path).unwrap();

        assert!(load_artifact(&symlink_path).is_err());
        load_artifact(&artifact_path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_artifact_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let output_dir = parent.path().join("saved-safes");
        let (config, prediction) = fixture();
        let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        let path = write_unique_artifact(&output_dir, &artifact).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_artifact(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o604)).unwrap();
        assert!(load_artifact(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        load_artifact(&path).unwrap();
    }

    #[test]
    fn concurrent_writers_preserve_atomic_no_clobber() {
        use std::{
            sync::{Arc, Barrier},
            thread,
        };

        const WRITERS: usize = 8;
        let parent = tempfile::tempdir().unwrap();
        let output_dir = parent.path().join("saved-safes");
        fs::create_dir(&output_dir).unwrap();
        let (config, prediction) = fixture();
        let artifact = Arc::new(DeploymentArtifact::from_prediction(&config, &prediction).unwrap());
        let barrier = Arc::new(Barrier::new(WRITERS));

        let writers = (0..WRITERS)
            .map(|_| {
                let artifact = Arc::clone(&artifact);
                let barrier = Arc::clone(&barrier);
                let output_dir = output_dir.clone();
                thread::spawn(move || {
                    barrier.wait();
                    write_unique_artifact(&output_dir, &artifact)
                })
            })
            .collect::<Vec<_>>();
        let outcomes = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);

        let path = outcomes.into_iter().find_map(Result::ok).unwrap();
        let loaded = load_artifact(&path).unwrap();
        loaded.verify_prediction(&prediction).unwrap();
    }

    #[test]
    fn target_chain_policy_covers_all_variants_and_salt_modes() {
        let (config, base) = fixture();
        for variant in [SafeVariant::Portable, SafeVariant::L1, SafeVariant::L2] {
            for chain_specific in [false, true] {
                let mut prediction = base.clone();
                prediction.variant = variant;
                prediction.chain_specific = chain_specific;
                prediction.expected_runtime_singleton =
                    expected_runtime_singleton(prediction.chain_id, variant);
                let artifact = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
                assert!(artifact.allows_target_chain(prediction.chain_id));
                assert_eq!(
                    artifact.allows_target_chain(480),
                    variant == SafeVariant::Portable && !chain_specific
                );
                assert!(!artifact.allows_target_chain(0));
                artifact.verify_prediction_for_target(&prediction).unwrap();
            }
        }
    }

    #[test]
    fn portable_artifact_verifies_cross_chain_while_exact_verify_does_not() {
        let (_, prediction) = fixture();
        let artifact = artifact_for(&prediction);
        let target = portable_cross_chain_prediction(&prediction);

        artifact.verify_prediction_for_target(&target).unwrap();
        assert!(artifact.verify_prediction(&target).is_err());

        let mut same_origin_runtime_mutation = prediction.clone();
        same_origin_runtime_mutation.expected_runtime_singleton =
            address!("Edd160fEBBD92E350D4D398fb636302fccd67C7e");
        assert!(
            artifact
                .verify_prediction_for_target(&same_origin_runtime_mutation)
                .is_err()
        );
    }

    #[test]
    fn cross_chain_verification_rejects_every_chain_independent_mutation() {
        let (_, prediction) = fixture();
        let artifact = artifact_for(&prediction);
        let target = portable_cross_chain_prediction(&prediction);

        macro_rules! assert_mutation_rejected {
            ($field:ident, $value:expr) => {{
                let mut mutation = target.clone();
                mutation.$field = $value;
                assert!(
                    artifact.verify_prediction_for_target(&mutation).is_err(),
                    "{} mutation unexpectedly verified",
                    stringify!($field)
                );
            }};
        }

        assert_mutation_rejected!(
            seed,
            b256!("3333333333333333333333333333333333333333333333333333333333333333")
        );
        assert_mutation_rejected!(
            address,
            address!("3333333333333333333333333333333333333333")
        );
        assert_mutation_rejected!(variant, SafeVariant::L1);
        assert_mutation_rejected!(chain_specific, true);
        assert_mutation_rejected!(
            singleton,
            address!("Edd160fEBBD92E350D4D398fb636302fccd67C7e")
        );
        assert_mutation_rejected!(initializer, bytes!("5678"));
        assert_mutation_rejected!(
            salt,
            b256!("4444444444444444444444444444444444444444444444444444444444444444")
        );

        let mut allowed_differences = target.clone();
        allowed_differences.chain_id = 10;
        allowed_differences.expected_runtime_singleton =
            expected_runtime_singleton(allowed_differences.chain_id, allowed_differences.variant);
        artifact
            .verify_prediction_for_target(&allowed_differences)
            .unwrap();

        let mut invalid_runtime = target;
        invalid_runtime.expected_runtime_singleton =
            address!("3333333333333333333333333333333333333333");
        assert!(
            artifact
                .verify_prediction_for_target(&invalid_runtime)
                .is_err()
        );
    }

    #[test]
    fn cross_chain_verification_rejects_invalid_artifact_and_nonportable_modes() {
        let (config, prediction) = fixture();
        let target = portable_cross_chain_prediction(&prediction);

        let mut invalid = DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        invalid.format_version += 1;
        assert!(invalid.verify_prediction_for_target(&target).is_err());

        let mut invalid_origin_runtime =
            DeploymentArtifact::from_prediction(&config, &prediction).unwrap();
        invalid_origin_runtime.expected_runtime_singleton =
            address!("Edd160fEBBD92E350D4D398fb636302fccd67C7e");
        assert!(invalid_origin_runtime.validate().is_err());
        assert!(
            invalid_origin_runtime
                .verify_prediction_for_target(&target)
                .is_err()
        );

        for (variant, chain_specific) in [
            (SafeVariant::Portable, true),
            (SafeVariant::L1, false),
            (SafeVariant::L2, false),
        ] {
            let mut source = prediction.clone();
            source.variant = variant;
            source.chain_specific = chain_specific;
            source.expected_runtime_singleton =
                expected_runtime_singleton(source.chain_id, variant);
            let artifact = DeploymentArtifact::from_prediction(&config, &source).unwrap();
            let mut disallowed_target = source;
            disallowed_target.chain_id = 480;
            assert!(
                artifact
                    .verify_prediction_for_target(&disallowed_target)
                    .is_err()
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
