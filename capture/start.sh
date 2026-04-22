#!/bin/bash

# start.sh - build the capture engine, then start it on the selected interface.

# Interface selection - four modes will be evaluated in priority order:

#   0. Dashboard -   /app/capture.json written by the inference engine when an
#                    analyst picks an interface in the dashboard settings.
#                    Highest priority, overrides all env vars
#   1. Explicit -    CAPTURE_INTERFACE=eth0 in .env or compose environment.
#                    Use for SPAN/TAP port deployments or any fixed interface
#   2. Promiscuous - Any interface that is UP and in PROMISCUOUS mode is used
#                    automatically. Set the interface before starting:
#                    ip link set <iface> promisc on
#                    Matches both physical NICs and Docker bridges, so this
#                    also covers the testbed case when Docker sets PROMISC
#                    on the bridge automatically
#   TODO
#   3. Testbel -     Auto-detect the Docker bridge for future testbed via
#                    the routing table. Fallback for demo with no config

# After each selection, the effective interface and filter are written back to
# capture.json as _status so the dashboard can display what is actively running

# On restart the interface is re-selected and only capture engine restarts

BUILD_DIR="/app/capture/build"
BINARY="$BUILD_DIR/capture_engine"

# Build

echo "[monitor] Building capture engine..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-march=native" -Wno-dev 2>&1 | tail -2
make -j"$(nproc)" 2>&1 | tail -2
echo "[monitor] Build complete."

# Interface selection

select_interface() {
    # Mode 0 - capture.json
    if [ -f /app/capture.json ]; then
        CFG_IFACE=$(grep '"interface"' /app/capture.json \
            | sed 's/.*"interface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
            | head -1)
        if [ -n "$CFG_IFACE" ]; then
            if ip link show "$CFG_IFACE" &>/dev/null; then
                echo "[monitor] Mode 0 - dashboard-configured: $CFG_IFACE" >&2
                echo "$CFG_IFACE"
                return 0
            else
                echo "[monitor] WARNING: dashboard-configured '$CFG_IFACE' not found, falling through" >&2
            fi
        fi
    fi

    # Mode 1 - explicit env var
    if [ -n "${CAPTURE_INTERFACE:-}" ]; then
        if ! ip link show "$CAPTURE_INTERFACE" &>/dev/null; then
            echo "[monitor] ERROR: interface '$CAPTURE_ENGINE' not found" >&2
            echo "[monitor] Available interfaces:" >&2
            ip -o link show | awk -F': ' '{printf " %-16s %s\n", $2, $3}' >&2
            return 1
        fi
        echo "[monitor] Mode 1 - explicit interface: $CAPTURE_INTERFACE" >&2
        echo "$CAPTURE_INTERFACE"
        return 0
    fi

    # Mode 2 - first UP+PROMISC interface (not loopback or veth pairs)
    PROMISC=$(ip -o link show | \
        awk '/PROMISC/ && /[,<]UP[,>]/ { gsub(/:/, "", $2); print $2 }' | \
        grep -v -E '^(lo|veth)' | \
        head -1)

    if [ -n "$PROMISC" ]; then
        echo "[monitor] Mode 2 - promiscuous interface: $PROMISC" >&2
        echo "$PROMISC"
        return 0
    fi

    # TODO
    # Mode 3 - Docker bridge for the testbed subnet
}

# BPF filter
# Returns just the filter expression (no -f prefix)

get_active_filter() {
    if [ -f /app/capture.json ]; then
        CFG_FILTER=$(grep '"filter"' /app/capture.json \
            | grep -v '"_status"' \
            | sed 's/.*"filter"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
            | head -1)
        if [ -n "$CFG_FILTER" ]; then
            echo "$CFG_FILTER"
            return
        fi
    fi
    if [ -n "${CAPTURE_FILTER:-}" ]; then
        echo "${CAPTURE_FILTER}"
    fi
}

# Write effective running config back to capture.json
# Stored under _status so the dashboard can show what is actually active
# Does not touch the 'interface' or 'filter' keys written by the dashboard

write_status() {
    local iface="$1"
    local filter="$2"
    # Re-read config keys (interface, filter) so they are preserved while
    # updating _status. Reconstruct the whole file - avoids JSON surgery
    local cfg_iface cfg_filter
    cfg_iface=$(grep '"interface"' /app/capture.json 2>/dev/null \
        | grep -v '"_status"' \
        | sed 's/.*"interface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
        | head -1)
    cfg_filter=$(grep '"filter"' /app/capture.json 2>/dev/null \
        | grep -v '"_status"' \
        | sed 's/.*"filter"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
        | head -1)
    {
        echo '{'
        [ -n "$cfg_iface"  ] && printf '  "interface": "%s",\n' "$cfg_iface"
        [ -n "$cfg_filter" ] && printf '  "filter": "%s",\n'    "$cfg_filter"
        printf '  "_status": {"interface": "%s", "filter": "%s"}\n' "$iface" "$filter"
        echo '}'
    } > /app/capture.json.tmp \
        && mv /app/capture.json.tmp /app/capture.json 2>/dev/null || true
}

# Restart loop
# Keeps the container alive after any exit. Interface and filter are
# re-selected on each restart so changes written by the dashboard take
# effect without a full container restart. The inference engine sends a kill
# signal via /tmp/capture_engine.pid rather than pkill (more reliable, no
# procps dependencies)

PID_FILE=/tmp/capture_engine.pid

while true; do
    IFACE=$(select_interface) || { sleep 5; continue; }

    ACTIVE_FILTER=$(get_active_filter)

    FILTER_ARGS=()
    if [ -n "$ACTIVE_FILTER" ]; then
        echo "[monitor] BPF filter: $ACTIVE_FILTER"
        FILTER_ARGS=(-f "$ACTIVE_FILTER")
    fi

    # Publish effective config so the dashboard can display it
    write_status "$IFACE" "$ACTIVE_FILTER"

    echo "[monitor] Starting capture on $IFACE..."
    "$BINARY" -i "$IFACE" "${FILTER_ARGS[@]}" &
    CAPTURE_PID=$!
    echo "$CAPTURE_PID" > "$PID_FILE"

    wait "$CAPTURE_PID"
    EXIT_CODE=$?
    rm -f "$PID_FILE"
    echo "[monitor] capture_engine exited (code $EXIT_CODE), restarting in 3s..."
    sleep 3
done