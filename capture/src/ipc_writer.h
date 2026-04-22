/*
    ipc_writer.h - Unix domain socket client for sending flow records to Python

    Wire format: [uint32_t payload_len = sizeof(flow_record_t)][flow_record_t bytes]

    The C engine is the socket client; Python inference is the server. This is the reverse
    of the usual convention, but it simplifies lifecycle management:
    the Python process owns the socket file and can be restarted independently.

    Flows that cannot be sent immediately are buffered in a ring buffer of 1024
    entries. If the ring is full, the oldest flow is silently dropped. This prevents
    the packet callback from blocking on I/O

    The writer runs its own reconnect loop; if the socket is unavailable (Python not
    started yet), it retries every 100ms in a background thread. The packet callback
    itself never blocks
*/
#pragma once
#include "flow_types.h"

#define IPC_SOCKET_PATH "/tmp/ids_ipc/flows.sock"
/*
    8192 slots * 6352 bytes = ~50 MB; a compromise for flood bursts
    so as to not drop too many flows before the inference engine drains
    it. Must be a power of 2 (used as bitmask index)
*/
#define IPC_RING_CAPACITY 8192

/*
    Initialise the IPC writer and start the background sender thread.
    Must be called once before ipc_writer_enqueue()
*/
void ipc_writer_init(void);

/*
    Enqueue a completed flow record for sending

    Called from the packet callback thread - must be non-blocking
    Copies the flow into the ring buffer. If the ring is full, the oldest
    entry is overwritten
*/
void ipc_writer_enqueue(const flow_record_t *flow);

/*
    Signal the sender thread to flush remaining flows and exit cleanly.
    Called from the signal handler on SIGINT/SIGTERM
*/
void ipc_writer_shutdown(void);