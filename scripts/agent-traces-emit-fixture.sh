#!/bin/bash
# agent-traces-emit-fixture.sh — dev harness that spawns a benign process
# carrying a W3C TRACEPARENT in its environment, so a LIVE dev daemon's
# ESCollector env-scan can lift it, bind it in the TraceRegistry, and stamp
# `agent_trace_id` on the correlated kernel events.
#
# This is a FIXTURE, not a production path. It proves the *producer*
# env-readback end of the agent-traces stack, which cannot be unit-tested
# (it needs a live, ES-entitled client observing NOTIFY_EXEC).
#
# PREREQUISITES (the readback only fires when ALL hold):
#   1. A running MacCrab daemon with the ES entitlement (root sysext, or a
#      dev `sudo swift run maccrabd`). Non-root eslogger/kdebug fallbacks do
#      NOT deliver the exec env, so the scan is a no-op there.
#   2. The agent-traces master ON — either:
#        * dev:     export MACCRAB_AGENT_TRACES=1 before starting the daemon
#        * release: set  {"agent_traces_enabled": true}  in
#                   agent_traces_config.json and (re)start the sysext.
#      The master is boot-gated: enabling it on an already-running daemon
#      needs a restart to start the producer.
#
# USAGE (run AFTER the daemon is up):
#   scripts/agent-traces-emit-fixture.sh
#
# Then verify the binding produced correlated events, e.g.:
#   maccrabctl status                 # "Agent Traces:" line
#   maccrabctl events --search sleep  # look for agent_trace_id on the child
#
# Safe: spawns only /bin/sleep locally, no network, cleans up on exit.
set -euo pipefail

# Canonical W3C traceparent (matches the value used across the unit suite).
# version(00)-traceid(32 hex)-spanid(16 hex)-flags(01 = sampled)
TRACEPARENT_VALUE="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TRACESTATE_VALUE="maccrab=fixture"

echo "agent-traces fixture"
echo "  TRACEPARENT=${TRACEPARENT_VALUE}"
echo "  TRACESTATE=${TRACESTATE_VALUE}"
echo

if [[ "$(id -u)" -ne 0 ]]; then
  echo "  note: this script does not need root, but the *daemon* observing the"
  echo "        exec must be ES-entitled (root sysext or 'sudo swift run maccrabd')."
  echo
fi

# Spawn a short-lived child with TRACEPARENT/TRACESTATE exported into its
# environment. The execve is the NOTIFY_EXEC the env-scan inspects; the
# child then lives briefly so any follow-on events under it correlate.
echo "  spawning: TRACEPARENT=… /bin/sleep 3   (pid follows)"
TRACEPARENT="${TRACEPARENT_VALUE}" TRACESTATE="${TRACESTATE_VALUE}" /bin/sleep 3 &
CHILD_PID=$!
echo "  child pid: ${CHILD_PID}"

cleanup() { kill "${CHILD_PID}" 2>/dev/null || true; }
trap cleanup EXIT

wait "${CHILD_PID}" 2>/dev/null || true
echo
echo "  done — if the daemon is entitled + the master is on, its TraceRegistry"
echo "  now holds a binding for trace_id 4bf92f3577b34da6a3ce929d0e0e4736."
