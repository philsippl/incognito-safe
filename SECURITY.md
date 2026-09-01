# Security policy and threat model

## Reporting

Do not open a public issue for a suspected vulnerability that could endanger funds. Report it privately to the repository maintainers and include a minimal reproduction, affected commit, and impact assessment.

## Intended security properties

- The generated nonce has 256 bits from the operating system CSPRNG.
- Owners are not placed on-chain by prediction or funding; they appear when deployment is broadcast.
- The predicted address commits to the complete initializer, seed, singleton proxy init code, and factory.
- Atomic initialization prevents an uninitialized-proxy takeover.
- Official v1.5.0 runtime bytecode hashes are checked before prediction and deployment.
- Generation, prediction, and artifact verification reveal the predicted address for an occupancy check but never send the secret seed or owner initializer to the RPC.
- `verify --file` performs the same deterministic artifact checks needed before deployment, checks required contract bytecode and target occupancy, and does not sign or send a transaction.
- Deployment requires `--confirm-address`, recomputes the artifact, simulates the transaction, checks target occupancy, and verifies final state. Prediction phases, software and hardware signers, and transaction requests are pinned to the selected target chain ID.
- Software deployer keys are read from an environment variable, never a CLI argument or YAML file, and their in-process string copy is zeroized on drop.
- Hardware-wallet deployer keys remain on-device. Ledger is restricted to Ledger Live paths (`m/44'/60'/<account>'/0/0`), and Trezor to standard Ethereum paths (`m/44'/60'/0'/0/<index>`); both indices are range-checked.
- Configuration loading uses one handle for regular-file metadata validation and a bounded 64-KiB-plus-one read. On Unix, it opens with `O_NOFOLLOW | O_NONBLOCK`, rejecting final symlinks and blocking special files before parsing.
- Generated deployment artifacts use a strict versioned schema, are atomically persisted without overwrite, and use mode `0600` on Unix. File contents are synced before persistence. On Unix, the parent is synced after output-directory creation and the output directory is synced after artifact persistence when directory syncing is supported.
- When the final output directory is missing and its parent exists, Unix creation requests mode `0700`; a restrictive umask may make it stricter, never broader. Existing directory permissions are not changed. A final output-directory file or symlink is rejected, including symlink paths written with trailing separators or `.` components.
- Artifact loading reads metadata and bounded contents through one file handle. On Unix, the handle is opened with `O_NOFOLLOW | O_NONBLOCK`, owner-only permissions are required, and final symlinks or blocking special files are rejected before parsing.
- Deployment and verification validate the artifact's canonical runtime singleton, recompute and compare every address-defining artifact field, and validate the target runtime singleton independently. A portable, non-chain-specific artifact may be retargeted with an explicit `--chain`; fixed variants and chain-specific salts remain bound to their artifact chain.
- Auto-selected built-in public RPCs require explicit `--allow-public-rpc` consent.

## Explicit non-goals and assumptions

- The seed hides a low-entropy or guessable signer configuration only while the seed remains secret. This tool does not provide anonymity after deployment.
- RPC integrity, availability, and mempool privacy are outside the trust boundary. A malicious RPC can lie, censor, or observe the signed deployment transaction. Cross-check high-value predictions with an independent RPC and an independent address calculation.
- Built-in public RPCs are convenience endpoints with no confidentiality, availability, or production-readiness guarantee. `--allow-public-rpc` only records consent to use one; it does not make the endpoint trustworthy. Explicit URLs can also be public or malicious. Use an independently trusted override for material value. Selecting a named chain checks the chain ID reported by the RPC but cannot establish canonical-chain truth.
- Keep credential-bearing primary and secondary URLs in `ETH_RPC_URL` and `CROSS_CHECK_RPC_URL`. Passing them through `--rpc-url` or `--cross-check-rpc-url` can expose credentials in shell history and process arguments. Generated help shows the variable names but hides current values. After endpoint preparation, the full formatted runtime error chain range-redacts every case-insensitive HTTP(S) URL, including complete bracketed IPv6 authorities. Ranges stop only at whitespace, double quotes, backticks, or angle brackets; other punctuation remains protected and may be conservatively consumed. Standalone parsed usernames, passwords, and query values of at least three Unicode characters are also redacted. Any nonempty one- or two-character value in those credential positions causes a fixed generic RPC failure instead of rendering the original diagnostics. Standalone path segments and fragments are redacted only at six bytes or longer. Invalid-URL and same-endpoint errors do not echo inputs.
- RPC providers can observe predicted-address occupancy checks and therefore learn which counterfactual address is being inspected, but they do not receive its seed or owner initializer until deployment.
- Deployment artifacts contain the secret seed and complete owner list. File permissions do not replace encrypted backups, host security, and independent retention of the expected address. Human-readable `generate` output omits the seed after a successful artifact write, but `generate --json` output contains it; use `umask 077` for redirection and protect logs and extra copies.
- Artifacts are self-consistency checked but are not signed or authenticated against wholesale replacement. `--confirm-address` is useful only when the value comes from an independently retained or funded record; copying it from the same artifact defeats the check. A backup acknowledgement is not an address-authentication substitute.
- `verify --file` establishes consistency with the selected RPC's reported chain, contract code, and current occupancy. It does not authenticate the artifact, prove canonical state, or eliminate the race before funding or deployment. Deployment repeats the checks immediately before sending.
- `CROSS_CHECK_RPC_URL` or `--cross-check-rpc-url` adds the same read-only corroboration to `verify` and `deploy`. It requires the exact target chain ID, checks required bytecode, repeats prediction with the same local implementation, and requires both providers to report the address empty. Failure or disagreement aborts. Canonicalized-equivalent endpoint URLs are rejected, but distinct URLs can still share an operator or backend. The check does not eliminate the deploy-time race. The secondary provider does not receive the seed or initializer, but its occupancy check does disclose the predicted address.
- Chain-ID pinning detects an RPC or load balancer that changes chains during an operation. It cannot detect a provider that consistently reports a false chain and state.
- Front-running cannot substitute different owners at the same address because the initializer hash changes the CREATE2 salt. It can reveal the intended initializer earlier by replaying the same deployment.
- The tool does not validate that owners can sign, that contract owners implement a particular interface, or that the threshold is operationally recoverable.
- Cloning copies owners and threshold only. Modules, guard, fallback configuration, policies, and balances are not cloned.
- Cross-chain artifact retargeting is limited to portable, non-chain-specific artifacts. Because the address is identical, `--confirm-address` cannot detect selection of the wrong target chain. Review the reported origin and target chain IDs. The identical address also does not imply that contract owners or other chain-local dependencies exist or remain operable there; check them before funding.
- `l1` and `l2` variants are valid advanced modes, but they disable artifact retargeting. In particular, `l1` on an L2 does not provide `SafeL2` events and behavior expected by L2 tooling. The CLI warns for effective non-portable or chain-specific settings, including settings inherited from a loaded artifact; warnings do not replace review of the reported mode and target chain.
- Artifact output must be under a trusted parent that is not attacker-writable. Final-component inspection, canonicalization, and later temporary-file operations are not one atomic handle-relative operation. An attacker who can replace the output path or an intermediate symlink target can still race artifact creation or persistence.
- Existing output-directory permissions are accepted unchanged. Operators must ensure the directory itself is private and not writable by untrusted users (`0700` on Unix is recommended).
- Configuration-file permissions are not enforced. Config paths and intermediate symlink targets must be trusted and kept private. Non-Unix builds use the platform's normal file open and do not provide the Unix final-symlink/nonblocking guarantee.
- Directory-entry crash durability depends on the platform and filesystem. Unsupported Unix directory `fsync` operations are tolerated, and non-Unix builds do not have a portable directory-sync operation. Keep an independent backup even after a successful write.
- Windows does not provide the Unix mode checks or the Unix `O_NOFOLLOW | O_NONBLOCK` artifact/config-open guarantees used here. Protect configs, artifacts, and output directories with restrictive ACLs, avoid reparse points and untrusted paths, and independently verify backups.
- RPC URL redaction applies only to the CLI's own formatted runtime errors. It does not remove secrets already present in argv, shell history, the process environment, third-party tool or provider logs, or crash reports. It cannot recognize server-created or transformed secret text that is neither a URL nor one of the recorded endpoint components; short path and fragment text is intentionally preserved outside URLs. Treat logs and local process access as sensitive.
- This repository has not been independently audited.
- Ledger/Trezor transport, firmware, host USB security, and the correctness of information shown by the device remain part of the hardware-wallet trust boundary.

## Release checklist

- Review Safe's current released version, deployment registry, ABI, salt formula, singleton split, and published code hashes.
- Run core tests and strict Clippy with `--no-default-features`; on a supported host, also run all-feature tests, strict Clippy, and a release build so Ledger/Trezor support remains protected.
- Run the ignored Anvil E2E and the trusted-endpoint Ethereum/World/OP fork scripts without logging RPC credentials.
- Exercise the wrong-address confirmation, public-RPC opt-in, portable-retargeting restrictions, artifact permissions, no-send verification, and secret-output regression tests.
- Reproduce a prediction with an independent Safe implementation.
- Review dependency changes and commit `Cargo.lock`.
