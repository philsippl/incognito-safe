//! End-to-end CLI test against the real Safe v1.5.0 contracts on an Anvil fork.

use std::{fs, process::Command, str::FromStr};

use alloy::{
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, ext::AnvilApi},
};
use incognito_safe::deployment::fetch_safe_config;
use serde_json::Value;

const ANVIL_FIRST_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_FIRST_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

#[tokio::test]
#[ignore = "requires `anvil` in PATH and ANVIL_FORK_URL pointing to a Safe v1.5.0 chain"]
async fn generate_fund_deploy_and_verify_real_safe() {
    let fork_url = std::env::var("ANVIL_FORK_URL")
        .expect("set ANVIL_FORK_URL to an Ethereum RPC with Safe v1.5.0 deployments");
    let anvil = Anvil::new()
        .fork(fork_url)
        .mnemonic("test test test test test test test test test test test junk")
        .try_spawn()
        .expect("failed to spawn anvil; install Foundry and put anvil in PATH");
    let endpoint = anvil.endpoint();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("safe.yml");
    fs::write(
        &config_path,
        format!("signers:\n  - \"{ANVIL_FIRST_ADDRESS}\"\nthreshold: 1\n"),
    )
    .unwrap();

    let generated = run_cli(&[
        "--rpc-url",
        &endpoint,
        "--json",
        "generate",
        "--config",
        config_path.to_str().unwrap(),
        "--output-dir",
        temp.path().to_str().unwrap(),
    ]);
    let generated: Value = serde_json::from_slice(&generated.stdout).unwrap();
    let predicted = Address::from_str(generated["address"].as_str().unwrap()).unwrap();
    let deployment_file = generated["deployment_file"].as_str().unwrap();
    assert_eq!(generated["occupied"], false);
    assert_saved_artifact(deployment_file, predicted, &generated);

    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let funded_balance = U256::from(10).pow(U256::from(18));
    provider
        .anvil_set_balance(predicted, funded_balance)
        .await
        .unwrap();
    assert_eq!(
        provider.get_balance(predicted).await.unwrap(),
        funded_balance
    );
    assert!(provider.get_code_at(predicted).await.unwrap().is_empty());

    let deployed = Command::new(env!("CARGO_BIN_EXE_incognito-safe"))
        .args([
            "--rpc-url",
            &endpoint,
            "--json",
            "deploy",
            "--file",
            deployment_file,
        ])
        .env("INC_SAFE_PRIVATE_KEY", ANVIL_FIRST_KEY)
        .output()
        .expect("failed to execute deploy command");
    assert!(
        deployed.status.success(),
        "deploy failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&deployed.stdout),
        String::from_utf8_lossy(&deployed.stderr)
    );
    let deployed: Value = serde_json::from_slice(&deployed.stdout).unwrap();
    assert_eq!(deployed["address"], generated["address"]);
    assert_eq!(deployed["verified"], true);

    assert!(!provider.get_code_at(predicted).await.unwrap().is_empty());
    assert_eq!(
        provider.get_balance(predicted).await.unwrap(),
        funded_balance
    );
    let cloned = fetch_safe_config(&provider, predicted).await.unwrap();
    assert_eq!(cloned.threshold, 1);
    assert_eq!(
        cloned.signers,
        vec![Address::from_str(ANVIL_FIRST_ADDRESS).unwrap()]
    );

    let replicated = run_cli(&[
        "--rpc-url",
        &endpoint,
        "--json",
        "generate",
        "--from-safe",
        &predicted.to_checksum(None),
        "--output-dir",
        temp.path().to_str().unwrap(),
    ]);
    let replicated: Value = serde_json::from_slice(&replicated.stdout).unwrap();
    assert_eq!(replicated["signer_count"], 1);
    assert_eq!(replicated["threshold"], 1);
    assert_ne!(replicated["address"], generated["address"]);
}

fn assert_saved_artifact(path: &str, predicted: Address, generated: &Value) {
    let saved: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(
        Address::from_str(saved["predicted_address"].as_str().unwrap()).unwrap(),
        predicted
    );
    assert_eq!(saved["seed"], generated["seed"]);
    assert_eq!(saved["chain_id"], generated["chain_id"]);
    assert_eq!(saved["format_version"], 2);
    assert!(saved["created_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(saved["threshold"], 1);
    assert_eq!(
        Address::from_str(saved["signers"][0].as_str().unwrap()).unwrap(),
        Address::from_str(ANVIL_FIRST_ADDRESS).unwrap()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

fn run_cli(args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_incognito-safe"))
        .args(args)
        .output()
        .expect("failed to execute incognito-safe");
    assert!(
        output.status.success(),
        "command failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
