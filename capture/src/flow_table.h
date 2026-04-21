/*
    flow_table.h - fixed-size flow table using FNV-1a hash with linear probing

    Flows are keyed on normalised 5-tuple (lower IP -> src). Table size is
    a power of 2 so slot index is computed with bitmask, not modulo. Backward
    shift deletion keeps probe sequences short under high load

    Not thread-safe; all access from the packet callback thread-only
*/
#pragma once
#include "flow_types.h"
#include "packet_parser.h"

/*
    Power of 2; enables fast bitmask slot lookup instead of modulo
    65536 slots * sizeof(flow_record_t) = 65536 * 6352 bytes = 397MB. Acceptable
    for a server
    97% of that is the four accumulation buffers in flow_record_t (pkt_len_buf,
    bwd_pkt_len_buf, fwd_iat_buf, all_iat_buf). All scalar feature fields fit in ~208 bytes
*/
#define FLOW_TABLE_SIZE 65536

/*
    Flows with no packets for this many nanoseconds are expired
    120s matches CICFlowMeter's default idle timeout
    Unsigned long long for nanoseconds
*/
#define FLOW_IDLE_TIMEOUT_NS 120000000000ULL

/*
    UDP flows have no FIN/RST; without an active timeout a sustained
    flood would accumulate silently for 120s after the last packet.
    10s catches floods that are still in progress and emits partial
    flows for detection
*/
#define FLOW_ACTIVE_TIMEOUT_NS 10000000000ULL

// opaque table - allocate statically in main.c, pass pointer everywhere
typedef struct flow_table flow_table_t;

struct flow_table
{
    flow_record_t slots[FLOW_TABLE_SIZE];
    uint8_t occupied[FLOW_TABLE_SIZE]; // 1 is occupied, 0 is empty
    uint64_t flows_dropped;            // incremented when table is full
};

// initialize all slots to zero. Must be called once before any other function
void flow_table_init(flow_table_t *t);

/*
    Look up or insert a flow for the given parsed packet

    Returns a pointer to the flow_record_t for this 5-tuple, creating a new
    entry if none exists. Returns NULL if the table is full

    out_is_new is set to 1 if a new flow was created, 0 if an existing one was
    found. Caller uses this to initialize flow state on first packet
*/
flow_record_t *flow_table_get_or_create(flow_table_t *t,
                                        const parsed_pkt_t *pkt,
                                        int *out_is_new);

/*
    Mark a flow slot as free so it can be reused
    Called after the flow has been finalized and emitted
    to the IPC socket
*/
void flow_table_remove(flow_table_t *t, flow_record_t *flow);

/*
    Scan the table and call cb for every flow whose last packet was more
    than FLOW_IDLE_TIMEOUT_NS ago. The callback should finalise the flow
    and emit it; the flow is not automatically removed - the callback must
    call flow_table_remove() if it wants to reclaim the slot

    now_ns: current time in nanoseconds (passed in to avoid repeated syscalls)
*/
void flow_table_expire(flow_table_t *t, uint64_t now_ns,
                       void (*cb)(flow_record_t *flow, void *ctx),
                       void *ctx);