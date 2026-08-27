# incognito-safe

`incognito-safe` generates a counterfactual Safe address, lets it receive funds before a contract exists there, and deploys the Safe later. The signer list stays secret until deployment as long as the generated deployment file stays private.

The CLI uses Safe v1.5.0, Alloy, and the canonical Safe `CREATE2` proxy factory. It verifies the required contract bytecode before predicting or deploying.

> **Warning:** This is security-sensitive software and has not been independently audited. Test first, use a trusted RPC for material value, and independently verify the address before funding it.

## Install

```sh
cargo install --path . --locked
```

## Workflow

### 1. Configure the Safe

Create `safe.yml`:

```yaml
signers:
  - "0x1111111111111111111111111111111111111111"
  - "0x2222222222222222222222222222222222222222"
threshold: 2
```

Signer order affects the generated address. Instead of a YAML file, use `--from-safe 0x...` to copy the owners and threshold from an existing Safe. Modules, guards, policies, and balances are not copied.

### 2. Generate an address and deployment file

Ethereum is the default network. Select another built-in network with `--chain`:

```sh
mkdir -m 700 saved-safes

incognito-safe --chain base generate \
  --config safe.yml \
  --output-dir saved-safes
```

Built-in networks are `ethereum`, `ethereum-sepolia`, `world`, `optimism`, `optimism-sepolia`, `base`, `base-sepolia`, `gnosis`, and `polygon`.

The command prints the predicted address and creates a unique file named `incognito-safe-deployment-0x<ADDRESS>.json`. The file contains the seed, timestamp, signers, threshold, chain, and all deployment inputs. On Unix it is created with mode `0600` and is never overwritten.

Back up this file and keep it private. Anyone who obtains it can reveal the signers by deploying the Safe early.

The built-in RPC sees the predicted address during the occupancy check, but generation does not send it the seed or signer initializer.

### 3. Fund the predicted address

Independently verify the printed address, then send native assets or tokens to it. There is no contract code at the address yet.

### 4. Deploy the Safe

The deployment sender only pays gas and does not need to be one of the Safe signers.

With a software key:

```sh
export INC_SAFE_PRIVATE_KEY=0xYOUR_DEPLOYER_PRIVATE_KEY

incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json

unset INC_SAFE_PRIVATE_KEY
```

With a Ledger:

```sh
incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --ledger
```

Ledger uses the Ledger Live path `m/44'/60'/<account>'/0/0`. Account `0` is the default; use `--ledger-account 1` for another account.

With a Trezor:

```sh
incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --trezor
```

Trezor uses `m/44'/60'/0'/0/<index>`. Index `0` is the default; use `--trezor-index 1` for another address. Connect and unlock exactly one device, then follow its confirmation prompts.

Deployment selects the artifact's built-in chain automatically, checks that the address is still empty, simulates the exact factory call, submits it, and verifies the resulting Safe owners, threshold, version, and singleton.

## RPC configuration

The built-in public RPCs require no configuration. Override one with a trusted endpoint through the environment:

```sh
export ETH_RPC_URL=https://your-rpc.example
incognito-safe --chain base generate --config safe.yml --output-dir saved-safes
```

Keeping `--chain` verifies that the RPC reports the expected chain ID. Omit `--chain` when using an unlisted custom EVM chain. `--rpc-url` is also available, but URLs containing credentials may remain in shell history.

## Address modes

The default `portable` mode produces the same address across supported chains when the seed and Safe configuration are identical. On Ethereum it uses `Safe`; on other chains it switches to `SafeL2` during initialization.

Use `--chain-specific` only when you intentionally want a different address on each chain:

```sh
incognito-safe --chain base --chain-specific generate \
  --config safe.yml \
  --output-dir saved-safes
```

Advanced users can select `--variant l1` or `--variant l2` directly.

## Other commands

Recompute an address without deploying:

```sh
incognito-safe --chain base predict \
  --seed 0xYOUR_64_HEX_CHARACTER_SEED \
  --config safe.yml
```

Add `--json` to any command for machine-readable output.

## Tests and Anvil demo

```sh
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Install Foundry, then run the forked demo:

```sh
ANVIL_FORK_URL=https://ethereum-rpc.publicnode.com ./demo/anvil.sh
```

The demo generates an address, funds it with 1 test ETH, deploys the Safe from the saved artifact, and verifies that the balance remains. CI runs the same deployment flow as an ignored Anvil E2E test.

## Security

- Never fund an address unless its deployment file is backed up securely.
- Treat the deployment file as a secret until deployment.
- Use an independently trusted RPC and address calculation for high-value use.
- Deployment reveals the seed and signers in public transaction data.
- The CLI aborts if the predicted address already contains code.

See [SECURITY.md](SECURITY.md) for the threat model and release checklist.

## References

- [Safe smart-account v1.5.0](https://github.com/safe-fndn/safe-smart-account/tree/v1.5.0)
- [Safe deployment registry](https://github.com/safe-global/safe-deployments)
- [EIP-1014 CREATE2](https://eips.ethereum.org/EIPS/eip-1014)

## License

MIT
