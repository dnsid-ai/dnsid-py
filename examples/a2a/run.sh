#!/usr/bin/env bash
# Run the DNSid A2A example: starts the testnet, launches Bob, then sends one
# message from Alice to Bob and exits.
#
# Usage (from project root):
#   bash examples/a2a/run.sh
#
# Prerequisites: the `dnsid` CLI (from the dnsid-ai/dnsid repo) must be
# on PATH — or set DNSID_CLI=/path/to/dnsid — and Docker must be running.
# Extra Python deps (if not already installed):
#   pip install fastapi uvicorn dnspython a2a-sdk sse-starlette

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DNSID_CLI="${DNSID_CLI:-dnsid}"
BOB_PORT=3002
ALICE_PORT=3001
ZONE=dev.dnsid.test
BOB_CU="https://bob.${ZONE}/.well-known/agent-card.json"
ALICE_CU="https://alice.${ZONE}/.well-known/agent-card.json"
BOB_LOG=$(mktemp /tmp/dnsid-bob-XXXXXX.log)
BOB_PID=""

kill_our_agents() {
    # Only kill Python processes we know we started, identified by our specific script path.
    pkill -f "python.*examples/a2a/main.py" 2>/dev/null || true
}

cleanup() {
    if [[ -n "${BOB_PID}" ]]; then
        echo ""
        echo "--- shutting down Bob (pid ${BOB_PID}) ---"
        kill "${BOB_PID}" 2>/dev/null || true
        wait "${BOB_PID}" 2>/dev/null || true
    fi
    kill_our_agents
    echo "--- Bob output ---"
    cat "${BOB_LOG}"
    rm -f "${BOB_LOG}"
}
trap cleanup EXIT

# Kill any leftover agent processes from a previous run of this script.
kill_our_agents

# ---------------------------------------------------------------------------
# 1. Start the testnet (no-op if already running) and prepare identities
# ---------------------------------------------------------------------------
echo "==> starting testnet"
"${DNSID_CLI}" testnet up

# Submit each agent's operationally countersigned C2SP ISSUANCE entry.
# `dnsid log issue` is idempotent, so this is safe to rerun.
echo "==> preparing C2SP issuance for Bob and Alice"
"${DNSID_CLI}" testnet agent ensure bob --upstream "http://localhost:${BOB_PORT}" --cu "${BOB_CU}" -- \
    "${DNSID_CLI}" log issue --domain "bob.${ZONE}"
"${DNSID_CLI}" testnet agent ensure alice --upstream "http://localhost:${ALICE_PORT}" --cu "${ALICE_CU}" -- \
    "${DNSID_CLI}" log issue --domain "alice.${ZONE}"

# ---------------------------------------------------------------------------
# 2. Start Bob in the background
# ---------------------------------------------------------------------------
echo "==> starting Bob on :${BOB_PORT}"
"${DNSID_CLI}" testnet run bob --upstream "http://localhost:${BOB_PORT}" --cu "${BOB_CU}" -- \
    python -u examples/a2a/main.py \
    >"${BOB_LOG}" 2>&1 &
BOB_PID=$!

# Wait until Bob prints its identity URL or the process dies.
echo -n "    waiting for Bob"
for i in $(seq 1 60); do
    if ! kill -0 "${BOB_PID}" 2>/dev/null; then
        echo ""
        echo "ERROR: Bob exited early. Log:" >&2
        cat "${BOB_LOG}" >&2
        exit 1
    fi
    if grep -q "-> https://" "${BOB_LOG}" 2>/dev/null; then
        break
    fi
    echo -n "."
    sleep 1
done
echo " ready"

# Wait until Bob has published its identity (logged "published" or "already published").
echo -n "    waiting for Bob to publish identity"
for i in $(seq 1 90); do
    if ! kill -0 "${BOB_PID}" 2>/dev/null; then
        echo ""
        echo "ERROR: Bob exited early. Log:" >&2
        cat "${BOB_LOG}" >&2
        exit 1
    fi
    if grep -qE "published|already published" "${BOB_LOG}" 2>/dev/null; then
        break
    fi
    echo -n "."
    sleep 1
done
echo " done"

# ---------------------------------------------------------------------------
# 3. Run Alice — sends one message to Bob then exits
# ---------------------------------------------------------------------------
echo "==> starting Alice on :${ALICE_PORT} — sending hello to Bob"
"${DNSID_CLI}" testnet run alice --upstream "http://localhost:${ALICE_PORT}" --cu "${ALICE_CU}" -- \
    python -u examples/a2a/main.py "bob.${ZONE}"

echo ""
echo "==> done"
