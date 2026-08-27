# Security policy and threat model

## Reporting

Do not open a public issue for a suspected vulnerability that could endanger funds. Report it privately to the repository maintainers and include a minimal reproduction, affected commit, and impact assessment.

## Intended security properties

- The generated nonce has 256 bits from the operating system CSPRNG.
- Owners are not placed on-chain by prediction or funding; they appear when deployment is broadcast.
- The predicted address commits to the complete initializer, seed, singleton proxy init code, and factory.
- Atomic initialization prevents an uninitialized-proxy takeover.
- Official v1.5.0 runtime bytecode hashes are checked before prediction and deployment.
- Generation and prediction reveal the predicted address for an occupancy check but never send the secret seed or owner initializer to the RPC.
- Deployment is simulated, target occupancy is checked, and final state is verified.
- Software deployer keys are read from an environment variable, never a CLI argument or YAML file, and their in-process string copy is zeroized on drop.
- Hardware-wallet deployer keys remain on-device. Ledger is restricted to Ledger Live paths (`m/44'/60'/<account>'/0/0`), and Trezor to standard Ethereum paths (`m/44'/60'/0'/0/<index>`); both indices are range-checked.
- Generated deployment artifacts use a strict versioned schema, are atomically persisted without overwrite, and use mode `0600` on Unix. Deployment recomputes and compares every deterministic prediction field before signing.

## Explicit non-goals and assumptions

- The seed hides a low-entropy or guessable signer configuration only while the seed remains secret. This tool does not provide anonymity after deployment.
- RPC integrity, availability, and mempool privacy are outside the trust boundary. A malicious RPC can lie, censor, or observe the signed deployment transaction. Cross-check high-value predictions with an independent RPC/implementation.
- Built-in public RPCs are convenience defaults with no confidentiality, availability, or production-readiness guarantee. Use an independently trusted override for material value; selecting a named chain pins the expected chain ID but cannot make the RPC trustworthy.
- RPC providers can observe predicted-address occupancy checks and therefore learn which counterfactual address is being inspected, but they do not receive its seed or owner initializer until deployment.
- Deployment artifacts contain the secret seed and complete owner list. File permissions do not replace encrypted backups, host security, and independent retention of the expected address. Artifacts are self-consistency checked but are not signed or authenticated against wholesale replacement.
- Front-running cannot substitute different owners at the same address because the initializer hash changes the CREATE2 salt. It can reveal the intended initializer earlier by replaying the same deployment.
- The tool does not validate that owners can sign, that contract owners implement a particular interface, or that the threshold is operationally recoverable.
- Cloning copies owners and threshold only. Modules, guard, fallback state, policies, and balances are not cloned.
- This repository has not been independently audited.
- Ledger/Trezor transport, firmware, host USB security, and the correctness of information shown by the device remain part of the hardware-wallet trust boundary.

## Release checklist

- Review Safe's current released version, deployment registry, ABI, salt formula, singleton split, and published code hashes.
- Run unit tests, strict Clippy, and the ignored Anvil fork E2E test.
- Reproduce a prediction with an independent Safe implementation.
- Review dependency changes and commit `Cargo.lock`.
