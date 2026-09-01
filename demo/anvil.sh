#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ANVIL_FORK_URL:-}" ]]; then
  echo "error: set ANVIL_FORK_URL to a chain RPC with official Safe v1.5.0 deployments" >&2
  exit 1
fi

# This is intentionally a single-local-RPC demo. The CLI calls below pass the
# local endpoint explicitly, so do not propagate unrelated production RPCs.
unset ETH_RPC_URL CROSS_CHECK_RPC_URL

for executable in anvil cargo curl jq; do
  if ! command -v "$executable" >/dev/null 2>&1; then
    echo "error: required executable not found: $executable" >&2
    exit 1
  fi
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$PROJECT_DIR/generated}"
ANVIL_PORT="${ANVIL_PORT:-8546}"
LOCAL_RPC="http://127.0.0.1:${ANVIL_PORT}"
ANVIL_LOG="$(mktemp -t incognito-safe-anvil.XXXXXX)"
(
  cd "$PROJECT_DIR"
  mkdir -p "$(dirname -- "$ARTIFACT_DIR")"
)

cleanup() {
  if [[ -n "${ANVIL_PID:-}" ]]; then
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true
    ANVIL_PID=""
  fi
  rm -f "$ANVIL_LOG"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "note: Anvil receives ANVIL_FORK_URL in its process arguments; use a non-secret or short-lived endpoint" >&2
anvil --silent --port "$ANVIL_PORT" --fork-url "$ANVIL_FORK_URL" >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
unset ANVIL_FORK_URL

for _ in {1..50}; do
  if curl --silent --fail \
    --header 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    "$LOCAL_RPC" >/dev/null; then
    break
  fi
  sleep 0.1
done

if ! kill -0 "$ANVIL_PID" 2>/dev/null; then
  echo "error: anvil failed to start" >&2
  sed -n '1,120p' "$ANVIL_LOG" >&2
  exit 1
fi

echo "1. Generating a counterfactual Safe address (owners remain off-chain)"
GENERATED="$({
  cd "$PROJECT_DIR"
  cargo run --quiet --no-default-features -- \
    --rpc-url "$LOCAL_RPC" \
    --json \
    generate --config "$SCRIPT_DIR/signers.yml" --output-dir "$ARTIFACT_DIR"
})"
echo "$GENERATED" | jq 'del(.seed)'
SAFE_ADDRESS="$(echo "$GENERATED" | jq -r .address)"
DEPLOYMENT_FILE="$(echo "$GENERATED" | jq -r .deployment_file)"
unset GENERATED
echo "   saved deployment artifact=$DEPLOYMENT_FILE"

echo "2. Verifying the saved artifact and empty address before funding"
VERIFIED="$({
  cd "$PROJECT_DIR"
  cargo run --quiet --no-default-features -- \
    --rpc-url "$LOCAL_RPC" \
    --json \
    verify --file "$DEPLOYMENT_FILE"
})"
echo "$VERIFIED" | jq .
VERIFIED_ADDRESS="$(echo "$VERIFIED" | jq -r .address)"
[[ "$VERIFIED_ADDRESS" == "$SAFE_ADDRESS" ]]
CODE_VERIFIED="$(curl --silent --fail \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$SAFE_ADDRESS\",\"latest\"]}" \
  "$LOCAL_RPC" | jq -r .result)"
[[ "$CODE_VERIFIED" == "0x" ]]
echo "   verified address=$VERIFIED_ADDRESS code=$CODE_VERIFIED"

echo "3. Sending 1 ETH to the verified address before it contains code"
FUNDING_RESPONSE="$(curl --silent --fail \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"0x70997970C51812dc3A010C7d01b50e0d17dc79C8\",\"to\":\"$SAFE_ADDRESS\",\"value\":\"0xde0b6b3a7640000\"}]}" \
  "$LOCAL_RPC")"
if [[ "$(echo "$FUNDING_RESPONSE" | jq -r '.error // empty')" != "" ]]; then
  echo "$FUNDING_RESPONSE" | jq . >&2
  exit 1
fi
BALANCE_BEFORE="$(curl --silent --fail \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"$SAFE_ADDRESS\",\"latest\"]}" \
  "$LOCAL_RPC" | jq -r .result)"
CODE_BEFORE="$(curl --silent --fail \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$SAFE_ADDRESS\",\"latest\"]}" \
  "$LOCAL_RPC" | jq -r .result)"
[[ "$BALANCE_BEFORE" == "0xde0b6b3a7640000" ]]
[[ "$CODE_BEFORE" == "0x" ]]
echo "   balance=$BALANCE_BEFORE code=$CODE_BEFORE"

echo "4. Deploying and atomically initializing the confirmed Safe"
export INC_SAFE_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEPLOYED="$({
  cd "$PROJECT_DIR"
  cargo run --quiet --no-default-features -- \
    --rpc-url "$LOCAL_RPC" \
    --json \
    deploy --file "$DEPLOYMENT_FILE" --confirm-address "$SAFE_ADDRESS"
})"
unset INC_SAFE_PRIVATE_KEY
echo "$DEPLOYED" | jq 'del(.seed)'
unset DEPLOYED

echo "5. Confirming that deployment preserved the prefunded balance"
BALANCE_AFTER="$(curl --silent --fail \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"$SAFE_ADDRESS\",\"latest\"]}" \
  "$LOCAL_RPC" | jq -r .result)"
CODE_AFTER="$(curl --silent --fail \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$SAFE_ADDRESS\",\"latest\"]}" \
  "$LOCAL_RPC" | jq -r .result)"
[[ "$BALANCE_AFTER" == "$BALANCE_BEFORE" ]]
[[ "$CODE_AFTER" != "0x" ]]
echo "   balance=$BALANCE_AFTER code_bytes=$(( (${#CODE_AFTER} - 2) / 2 ))"
echo "Demo complete: the funded counterfactual address is now a verified Safe."
echo "Deployment artifact retained at $DEPLOYMENT_FILE"
