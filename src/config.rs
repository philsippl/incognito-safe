//! Strict Safe owner configuration loading and validation.

use std::{collections::HashSet, fs, path::Path, str::FromStr};

use alloy::primitives::{Address, address};
use anyhow::{Context, Result, bail, ensure};
use yaml_rust2::{
    Yaml, YamlLoader,
    parser::{Event, EventReceiver, Parser},
    yaml::Hash,
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub const MAX_SIGNERS: usize = 128;
const SENTINEL_OWNERS: Address = address!("0000000000000000000000000000000000000001");

/// The complete owner configuration used to initialize a Safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeConfig {
    pub signers: Vec<Address>,
    pub threshold: u64,
}

impl SafeConfig {
    /// Validates all invariants enforced by Safe's `setupOwners` implementation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/oversized owner set, an invalid threshold,
    /// a zero/sentinel owner, or a duplicate owner.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.signers.is_empty(),
            "the signer list must not be empty"
        );
        ensure!(
            self.signers.len() <= MAX_SIGNERS,
            "too many signers: maximum is {MAX_SIGNERS}"
        );
        ensure!(self.threshold > 0, "threshold must be at least 1");
        ensure!(
            usize::try_from(self.threshold).is_ok_and(|value| value <= self.signers.len()),
            "threshold {} exceeds signer count {}",
            self.threshold,
            self.signers.len()
        );

        let mut unique = HashSet::with_capacity(self.signers.len());
        for signer in &self.signers {
            ensure!(*signer != Address::ZERO, "zero address cannot be a signer");
            ensure!(
                *signer != SENTINEL_OWNERS,
                "Safe's sentinel address 0x0000000000000000000000000000000000000001 cannot be a signer"
            );
            ensure!(unique.insert(*signer), "duplicate signer: {signer}");
        }
        Ok(())
    }

    /// Validates the circular Safe invariant that the Safe itself cannot be an owner.
    ///
    /// # Errors
    ///
    /// Returns an error when `predicted` is also present in the signer list.
    pub fn validate_predicted_address(&self, predicted: Address) -> Result<()> {
        ensure!(
            !self.signers.contains(&predicted),
            "the predicted Safe address {predicted} cannot also be a signer"
        );
        Ok(())
    }
}

/// Loads the deliberately small YAML schema documented in `config.example.yml`.
///
/// # Errors
///
/// Returns an error if the file cannot be safely read or does not exactly match
/// the supported schema and Safe owner invariants.
pub fn load_config(path: &Path) -> Result<SafeConfig> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect config {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "config is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_CONFIG_BYTES,
        "config exceeds the {MAX_CONFIG_BYTES}-byte safety limit"
    );

    let input = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    reject_advanced_yaml(&input)?;
    let documents = YamlLoader::load_from_str(&input).context("invalid YAML config")?;
    ensure!(
        documents.len() == 1,
        "config must contain exactly one YAML document"
    );
    let root = documents[0]
        .as_hash()
        .context("config root must be a YAML mapping")?;
    reject_unknown_keys(root, &["signers", "threshold"])?;

    let signers_node = get_required(root, "signers")?;
    let signer_nodes = signers_node
        .as_vec()
        .context("`signers` must be a YAML sequence")?;
    let mut signers = Vec::with_capacity(signer_nodes.len());
    for (index, node) in signer_nodes.iter().enumerate() {
        let raw = node
            .as_str()
            .with_context(|| format!("signers[{index}] must be a quoted address string"))?;
        let signer = Address::from_str(raw)
            .with_context(|| format!("signers[{index}] is not a valid 20-byte EVM address"))?;
        signers.push(signer);
    }

    let threshold_node = get_required(root, "threshold")?;
    let threshold = match threshold_node {
        Yaml::Integer(value) => u64::try_from(*value).context("threshold must be positive")?,
        _ => bail!("`threshold` must be an integer"),
    };

    let config = SafeConfig { signers, threshold };
    config.validate()?;
    Ok(config)
}

/// Reject anchors, aliases, and tags before the object loader can expand them.
fn reject_advanced_yaml(input: &str) -> Result<()> {
    #[derive(Default)]
    struct StrictEvents {
        forbidden: bool,
    }

    impl EventReceiver for StrictEvents {
        fn on_event(&mut self, event: Event) {
            self.forbidden |= match event {
                Event::Alias(_) => true,
                Event::Scalar(_, _, anchor, tag)
                | Event::SequenceStart(anchor, tag)
                | Event::MappingStart(anchor, tag) => anchor != 0 || tag.is_some(),
                _ => false,
            };
        }
    }

    let mut events = StrictEvents::default();
    Parser::new_from_str(input)
        .load(&mut events, true)
        .context("invalid YAML config")?;
    ensure!(
        !events.forbidden,
        "YAML anchors, aliases, and custom tags are forbidden in signer configs"
    );
    Ok(())
}

fn get_required<'a>(map: &'a Hash, key: &str) -> Result<&'a Yaml> {
    map.get(&Yaml::String(key.to_owned()))
        .with_context(|| format!("missing required config key `{key}`"))
}

fn reject_unknown_keys(map: &Hash, allowed: &[&str]) -> Result<()> {
    for key in map.keys() {
        let key = key.as_str().context("config keys must be strings")?;
        ensure!(allowed.contains(&key), "unknown config key `{key}`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn parse(input: &str) -> Result<SafeConfig> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(input.as_bytes())?;
        load_config(file.path())
    }

    #[test]
    fn parses_valid_config_and_preserves_order() {
        let config = parse(
            r#"
signers:
  - "0x1111111111111111111111111111111111111111"
  - "0x2222222222222222222222222222222222222222"
threshold: 2
"#,
        )
        .unwrap();

        assert_eq!(config.threshold, 2);
        assert_eq!(
            config.signers[0],
            address!("1111111111111111111111111111111111111111")
        );
        assert_eq!(
            config.signers[1],
            address!("2222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn rejects_duplicates_zero_sentinel_bad_threshold_and_unknown_keys() {
        for invalid in [
            "signers: [\"0x1111111111111111111111111111111111111111\", \"0x1111111111111111111111111111111111111111\"]\nthreshold: 1\n",
            "signers: [\"0x0000000000000000000000000000000000000000\"]\nthreshold: 1\n",
            "signers: [\"0x0000000000000000000000000000000000000001\"]\nthreshold: 1\n",
            "signers: [\"0x1111111111111111111111111111111111111111\"]\nthreshold: 2\n",
            "signers: [\"0x1111111111111111111111111111111111111111\"]\nthreshold: 1\nsurprise: true\n",
            "signers: [\"0x1111111111111111111111111111111111111111\"]\nthreshold: 1\nthreshold: 1\n",
            "signers: &owners [\"0x1111111111111111111111111111111111111111\"]\nthreshold: 1\n",
            "signers: !owners [\"0x1111111111111111111111111111111111111111\"]\nthreshold: 1\n",
        ] {
            assert!(parse(invalid).is_err(), "unexpectedly accepted: {invalid}");
        }
    }
}
