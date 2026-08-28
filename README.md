# incognito-safe

`incognito-safe` generates a counterfactual Safe address, lets it receive funds before a contract exists there, and deploys the Safe later. The signer list stays off-chain until deployment; keep every local config and deployment-artifact copy private.

The CLI uses Safe v1.5.0, Alloy, and the canonical Safe `CREATE2` proxy factory. It verifies the required contract bytecode before predicting, verifying an artifact, or deploying.

> **Warning:** This is security-sensitive software and has not been independently audited. Test first, use a trusted RPC for material value, and independently verify the address before funding it.

## Install

```sh
cargo install --path . --locked
```

Default builds include both Ledger and Trezor support. `--no-default-features` builds the core CLI without either hardware transport; `--ledger` and `--trezor` remain visible, and selecting an omitted transport returns an explicit rebuild instruction if execution reaches wallet selection. Single-transport builds are supported with `--no-default-features --features ledger` or `--no-default-features --features trezor`.

## Workflow

### 1. Configure the Safe

Create `safe.yml`:

```yaml
signers:
  - "0x1111111111111111111111111111111111111111"
  - "0x2222222222222222222222222222222222222222"
threshold: 2
```

Signer order affects the generated address. Instead of a YAML file, use `--from-safe 0x...` to copy the owners and threshold from an existing Safe. Modules, guards, fallback configuration, policies, and balances are not copied.

Configuration files are read through one bounded handle (maximum 64 KiB), so metadata checks and contents refer to the same opened file. On Unix, the final file is opened with no-follow and nonblocking flags before regular-file validation; a final symlink or FIFO is rejected. Intermediate symlinks remain supported, and non-Unix builds lack the final no-follow guarantee. Keep the config private and load it from a trusted parent path.

### 2. Generate an address and deployment file

Ethereum is the default network. Select another built-in network with `--chain` and use a trusted RPC:

```sh
export ETH_RPC_URL=https://your-rpc.example

incognito-safe --chain base generate \
  --config safe.yml \
  --output-dir saved-safes
```

Built-in networks are `ethereum`, `ethereum-sepolia`, `world`, `optimism`, `optimism-sepolia`, `base`, `base-sepolia`, `gnosis`, and `polygon`.

The command prints the predicted address and creates a unique file named `incognito-safe-deployment-0x<ADDRESS>.json`. The file contains the seed, timestamp, signers, threshold, chain, and all deployment inputs. Human-readable output does not repeat the seed after the file is written. On Unix, a missing final output directory is requested with mode `0700` (a restrictive umask may make it stricter), and the artifact is created with mode `0600`. Existing directory permissions are not changed, missing parent directories remain an error, and the final output-directory component must be a real directory rather than a file or symlink. Artifacts are never overwritten.

Put the output directory under a trusted parent that other users cannot modify. If the directory already exists, secure it yourself (`chmod 700` on Unix); the CLI does not change its permissions. Final-component validation and later path-based file creation are not one atomic filesystem operation, so an attacker-writable parent—or an untrusted intermediate symlink target—can still race the write. Intermediate symlinks remain supported and are part of this trust requirement.

Back up the artifact and keep it private. Anyone who obtains it learns the owners immediately and can deploy the Safe early. The artifact alone does not grant Safe signing authority unless the holder also controls enough owners. The file contents are synced before persistence; on Unix the CLI also syncs relevant directory entries where the filesystem supports it. This improves crash durability but does not replace a separate backup.

`--json` output still contains the seed. If you redirect it to another file, protect that copy too; for example, set `umask 077` before redirection. Shell logs, CI logs, and terminal capture can also retain JSON output.

The selected RPC sees the predicted address during the occupancy check, but generation does not send it the seed or signer initializer.

### 3. Fund the predicted address

Before funding, retain the expected address through an independent trusted channel or reproduce it with an independent Safe implementation. You can inspect the saved artifact without sending a transaction:

```sh
incognito-safe --chain base verify \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json
```

`verify` validates the artifact schema, including the canonical runtime singleton for its recorded chain and variant, recomputes its deterministic fields for the selected target chain, checks the required Safe contract bytecode, and requires the predicted address to contain no code. Add `--show-owners` only when it is safe to print the owner list.

This is a consistency and RPC-state check, not artifact authentication. A replacement artifact can be internally valid. Compare the reported address with the independently retained address before funding, then send native assets or tokens only while the address has no code. Verification also cannot remove the race between an occupancy check and later funding or deployment.

### 4. Deploy the Safe

The deployment sender only pays gas and does not need to be one of the Safe signers.

With a software key:

```sh
export INC_SAFE_PRIVATE_KEY=0xYOUR_DEPLOYER_PRIVATE_KEY

incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --confirm-address 0xINDEPENDENTLY_RETAINED_ADDRESS

unset INC_SAFE_PRIVATE_KEY
```

With a Ledger:

```sh
incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --confirm-address 0xINDEPENDENTLY_RETAINED_ADDRESS \
  --ledger
```

Ledger uses the Ledger Live path `m/44'/60'/<account>'/0/0`. Account `0` is the default; use `--ledger-account 1` for another account.

With a Trezor:

```sh
incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --confirm-address 0xINDEPENDENTLY_RETAINED_ADDRESS \
  --trezor
```

Trezor uses `m/44'/60'/0'/0/<index>`. Index `0` is the default; use `--trezor-index 1` for another address. Connect and unlock exactly one device, then follow its confirmation prompts.

`--confirm-address` is required. Source it from the address you retained independently before funding, not from the deployment file currently being opened. Copying the value from the same artifact does not protect against wholesale file replacement.

Deployment uses the artifact's original chain unless you explicitly retarget an eligible portable artifact with `--chain`. It pins every prediction phase, the signer, and the transaction request to the selected target chain ID; then it recomputes the prediction, checks that the address is still empty, simulates the exact factory call, submits it, and verifies the resulting Safe owners, threshold, version, and singleton. This detects a provider that changes chains during the run, but a provider that consistently lies about its chain remains outside the trust boundary.

## RPC configuration

For material value, provide a trusted endpoint through the environment:

```sh
export ETH_RPC_URL=https://your-rpc.example
incognito-safe --chain base generate --config safe.yml --output-dir saved-safes
```

Keeping `--chain` verifies that the RPC reports the expected chain ID. Omit `--chain` when using an unlisted custom EVM chain. `--rpc-url` is also available.

Prefer `ETH_RPC_URL` for the primary endpoint and `CROSS_CHECK_RPC_URL` for the optional secondary endpoint, especially when URLs contain credentials. Passing either URL through `--rpc-url` or `--cross-check-rpc-url` can expose it in shell history and process arguments.

Generated help shows the environment-variable names but hides their current values. After endpoint preparation, the CLI flattens its full runtime error chain and range-redacts every case-insensitive HTTP(S) URL, including a complete bracketed IPv6 authority. A protected range ends only at whitespace, a double quote, a backtick, `<`, or `>`; parentheses, apostrophes, commas, semicolons, brackets, and braces remain protected and can cause adjacent unspaced wrapper punctuation to disappear from diagnostics. Parsed endpoint usernames, passwords, and query values of at least three Unicode characters are also redacted when repeated outside a URL. A nonempty one- or two-character value in any of those credential positions causes a fixed generic RPC failure that suppresses the original diagnostics. Standalone path segments and fragments are redacted only when they are at least six bytes, so ordinary short route words remain useful in errors. Invalid-URL and same-endpoint errors are generic and do not echo the input.

This is defense in depth, not a general secret scrubber: environment values can remain visible to sufficiently privileged local processes, command-line flags are already exposed through argv/history, and third-party tools, provider logs, crash reports, or transformed server-supplied secret text that is neither a URL nor a recorded endpoint component cannot be recognized. Short path and fragment text is intentionally not treated as a credential outside a URL. Use restricted, short-lived credentials and keep logs private.

The CLI does not use a built-in public RPC unless you explicitly accept it:

```sh
incognito-safe --chain base --allow-public-rpc generate \
  --config safe.yml \
  --output-dir saved-safes
```

`--allow-public-rpc` is consent to use the auto-selected convenience endpoint, not a claim that it is trustworthy or private. Explicit URLs may also be public or malicious. An RPC sees predicted-address occupancy checks, and selecting a named chain only checks the chain ID that the RPC reports.

For optional read-only corroboration during `verify` or `deploy`, provide a second endpoint:

```sh
export CROSS_CHECK_RPC_URL=https://another-rpc.example

incognito-safe --chain base verify \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json

incognito-safe deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --confirm-address 0xINDEPENDENTLY_RETAINED_ADDRESS
```

`CROSS_CHECK_RPC_URL` applies to both commands. `--cross-check-rpc-url` is also available on either command for non-secret URLs and overrides the environment value.

The second URL must differ from the primary URL and report the exact target chain ID. Before any RPC access, the CLI parses both HTTP(S) URLs, normalizes scheme and host case, removes explicit default ports and fragments, and trims trailing path slashes while preserving the root. Canonically equal endpoints are rejected. Userinfo, query, and non-trailing path differences remain distinct, and different URLs can still reach the same operator or backend.

The CLI checks the required Safe bytecode through the second endpoint, recomputes the prediction with the same local implementation, and requires both RPCs to agree that the address is empty. Disagreement or failure aborts before signer access. The occupancy check discloses the predicted address to both providers.

This is corroboration, not independent proof: two URLs can share an operator or backend, both predictions use this CLI's CREATE2 implementation, and neither RPC check removes the race before the transaction is sent.

## Address modes

The default `portable` mode produces the same address across supported chains when the seed and Safe configuration are identical. On Ethereum it uses `Safe`; on other chains it switches to `SafeL2` during initialization.

An artifact records the chain where it was generated. By default, `deploy --file` and `verify --file` use that original chain. A portable, non-chain-specific artifact can be explicitly retargeted without regenerating it:

```sh
export ETH_RPC_URL=https://trusted-ethereum-rpc.example

incognito-safe --chain ethereum verify \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json

incognito-safe --chain ethereum deploy \
  --file saved-safes/incognito-safe-deployment-0xADDRESS.json \
  --confirm-address 0xINDEPENDENTLY_RETAINED_ADDRESS
```

Retargeting changes the RPC target and expected runtime singleton, but it must reproduce the same address and all other address-defining fields. It is rejected for `l1`, `l2`, and `--chain-specific` artifacts. `verify` prints both the artifact's origin chain and the selected target chain. Review both: because the portable address is identical, `--confirm-address` cannot detect selection of the wrong target chain. The same address also does not prove that contract owners or other dependencies exist and work there; check them separately before funding.

Use `--chain-specific` only when you intentionally want a different address on each chain:

```sh
incognito-safe --chain base --chain-specific generate \
  --config safe.yml \
  --output-dir saved-safes
```

Advanced users can select `--variant l1` or `--variant l2` directly. These overrides are valid but easy to misuse: `l1` on an L2 omits `SafeL2` behavior and events, while either override gives up portable artifact retargeting. The CLI warns whenever the effective settings—from flags or a loaded artifact—use `l1`, `l2`, or chain-specific mode, and adds an L2-specific warning for `l1` on a non-Ethereum chain. Keep portable, non-chain-specific mode unless you require and have verified an override.

## Other commands

Recompute an address without deploying:

```sh
incognito-safe --chain base predict \
  --seed 0xYOUR_64_HEX_CHARACTER_SEED \
  --config safe.yml
```

Add `--json` to any command for machine-readable output.

## Tests and Anvil demo

Run core and software-key tests without hardware SDKs:

```sh
cargo test --all-targets --no-default-features --locked
cargo clippy --all-targets --no-default-features --locked -- -D warnings
```

The current core suite contains 64 unit tests; the forked Anvil integration test is separate and ignored unless explicitly requested.

On a host with the required Ledger/Trezor build dependencies, also protect the default release configuration:

```sh
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --all-features --locked
```

Install Foundry, then run the forked demo:

```sh
export ANVIL_FORK_URL=https://your-ethereum-fork-rpc.example
./demo/anvil.sh
unset ANVIL_FORK_URL
```

The demo uses the core `--no-default-features` build and a software key. It generates an address, verifies it before funding, funds it with 1 test ETH, deploys the confirmed Safe, and verifies that the balance remains. Anvil receives the fork URL as a process argument, so use a non-secret or short-lived endpoint and do not publish its logs. CI runs core and all-feature test matrices and invokes the ignored Anvil E2E explicitly with a public credential-free fork URL.

The extended fork scripts require caller-supplied trusted endpoints and have no embedded RPC credential fallbacks:

```sh
export ETH_RPC_URL=https://your-ethereum-rpc.example
export WORLD_RPC_URL=https://your-world-rpc.example
export OP_RPC_URL=https://your-op-rpc.example
./fork-tests/run.sh
```

`fork-tests/cli_e2e.sh` needs only `ETH_RPC_URL` and `WORLD_RPC_URL`; `fork-tests/run.sh` also needs `OP_RPC_URL`. These manual harnesses contain no project RPC credentials or public-RPC fallback. Load credential-bearing values from a protected environment or secret manager rather than pasting them into commands or shell history, keep test logs private, and remember that the underlying fork processes may expose upstream URLs in their process arguments.

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
