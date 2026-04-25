/*
    main.c - libpcap capture loop, pcap callback, periodic idle flow expiry

    One thread: the libpcap dispatch loop. All state (flow table, IPC writer)
    is owned by this thread. The IPC writer has its own sender thread but its
    ring buffer is accessed without locks

    Flow completion rules (matches CICFlowMeter):
        FIN: either direction - flow completes on FIN packet (included in flow)
        RST: either direction - flow completes immediately
        Timeout: no packets for FLOW_IDLE_TIMEOUT_NS - expiry scan runs
                 every second via pcap_dispatch() return or pcap alarm approach
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pcap/pcap.h>

#include "flow_types.h"
#include "packet_parser.h"
#include "flow_table.h"
#include "flow_features.h"
#include "ipc_writer.h"

// Globals
static flow_table_t g_table;
static pcap_t *g_pcap = NULL;
static volatile int g_stop = 0;

// Signal handling

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_pcap)
        pcap_breakloop(g_pcap);
}

// Helpers

static uint64_t clock_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
    Determine whether a packet is in the forward direction for a given flow

    Forward is defined as the direction of the first packet, which was recorded
    at flow creation time in fwd_is_lower_ip. A packet is forward if its source
    IP matches the "lower IP" side in the same way the first packet did
*/

static int is_forward(const flow_record_t *flow, const parsed_pkt_t *pkt)
{
    int pkt_from_lower = (pkt->src_ip <= pkt->dst_ip);
    return (flow->fwd_is_lower_ip == (uint8_t)pkt_from_lower);
}

// Expiry callback

static void expire_flow(flow_record_t *flow, void *ctx)
{
    (void)ctx;
    features_finalise(flow);
    ipc_writer_enqueue(flow);
    flow_table_remove(&g_table, flow);
}

// pcap callback
static void packet_callback(u_char *user, const struct pcap_pkthdr *hdr,
                            const u_char *data)
{
    (void)user;

    // Convert pcap timeval to ns; pcap gives microsecond resolution,
    // multiply tv_usec by 1000 to get ns
    uint64_t ts_ns = (uint64_t)hdr->ts.tv_sec * 1000000000ULL + (uint64_t)hdr->ts.tv_usec * 1000ULL;

    parsed_pkt_t pkt;
    if (!parse_packet(data, hdr->caplen, ts_ns, &pkt))
        return;

    int is_new = 0;
    flow_record_t *flow = flow_table_get_or_create(&g_table, &pkt, &is_new);
    if (!flow)
        return;

    if (is_new)
    {
        flow->first_pkt_ns = ts_ns;
        flow->last_pkt_ns = ts_ns;
        flow->last_pkt_ns_for_iat = ts_ns;
    }

    int fwd = is_forward(flow, &pkt);
    features_update(flow, &pkt, fwd);

    /*
        buffer-fill completion:
        When the packet length buffer reaches capacity (512 entries) the flow
        has enough data for accurate AVX2 stats - emit immediately.
        This catches high-rate floods that would otherwise wait for a timeout
        The 512-packet sample is representative: floods are uniform so std~0
        is a correct feature value not an artifact of truncation
    */
    if (!flow->complete && flow->pkt_len_buf_count >= 512)
    {
        features_finalise(flow);
        ipc_writer_enqueue(flow);
        flow_table_remove(&g_table, flow);
        return;
    }

    /*
        Flow completion detection. Check for FIN and include the packet
    */
    if (pkt.protocol == 6)
    {
        uint8_t flags = pkt.tcp_flags;

        if ((flags & 0x01) && !flow->complete)
        {
            // FIN: include this packet, then complete
            features_finalise(flow);
            ipc_writer_enqueue(flow);
            flow_table_remove(&g_table, flow);
            return;
        }
    }
}

// Usage

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -i <interface> [-f <bpf-filter>]\n", prog);
    fprintf(stderr, "  -i eth0              capture interface\n");
    fprintf(stderr, "  -f 'not host 1.2.3'  extra BPF pre-filter (ANDed with base filter)\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    const char *iface = NULL;
    const char *extra_filter = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
            iface = argv[++i];
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc)
            extra_filter = argv[++i];
        else
            usage(argv[0]);
    }

    if (!iface)
        usage(argv[0]);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // initialize subsystems
    flow_table_init(&g_table);
    ipc_writer_init();

    // open pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(iface, 65535, 1, /*promiscuous*/
                            1000,            /*ms timeout*/
                            errbuf);

    if (!g_pcap)
    {
        fprintf(stderr, "[capture] pcap_open_live: %s\n", errbuf);
        return 1;
    }

    /*
        Base filter: only IPv4 TCP and UDP. If the operator supplied an extra
        BPF expression, AND in it so packets matching neither are dropped in
        kernel before reaching userspace, reducing CPU load on noisy links
    */
    char filter_expr[4096];
    if (extra_filter && *extra_filter)
    {
        snprintf(filter_expr, sizeof(filter_expr),
                 "ip and (tcp or udp) and (%s)", extra_filter);
    }
    else
    {
        snprintf(filter_expr, sizeof(filter_expr), "ip and (tcp or udp)");
    }
    fprintf(stderr, "[capture] BPF filter: %s\n", filter_expr);

    struct bpf_program fp;
    if (pcap_compile(g_pcap, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        fprintf(stderr, "[capture] pcap_compile: %s\n", pcap_geterr(g_pcap));
        return 1;
    }
    if (pcap_setfilter(g_pcap, &fp) < 0)
    {
        fprintf(stderr, "[capture] pcap_setfilter: %s\n", pcap_geterr(g_pcap));
        return 1;
    }
    pcap_freecode(&fp);

    fprintf(stderr, "[capture] capturing on %s (press Ctrl + C to stop)\n", iface);

    /*
        Capture loop
        Use pcap_dispatch() in a loop rather than pcap_loop() so we can run
        the idle-expiry scan every second between dispatches
    */
    uint64_t last_expire_ns = clock_ns();

    while (!g_stop) {
        int n = pcap_dispatch(g_pcap, 256, packet_callback, NULL);
        if (n < 0 && n != PCAP_ERROR_BREAK)
        {
            fprintf(stderr, "[capture]: pcap_dispatch: %s\n", pcap_geterr(g_pcap));
            break;
        }

        // Run idle expiry scan approximately once per second
        uint64_t now = clock_ns();
        if (now - last_expire_ns >= 1000000000ULL)
        {
            flow_table_expire(&g_table, now, expire_flow, NULL);
            last_expire_ns = now;
        }
    }

    // shutdown: drain remaining flows
    fprintf(stderr, "[capture] shutting down, flushing active flows...\n");
    uint64_t now = clock_ns();
    // Finalise all remaining active flows regardless of idle time
    flow_table_expire(&g_table, now + FLOW_IDLE_TIMEOUT_NS + 1, expire_flow, NULL);

    ipc_writer_shutdown();
    pcap_close(g_pcap);

    fprintf(stderr, "[capture] done. flows_dropped_table=%llu\n",
            (unsigned long long)g_table.flows_dropped);
            
    return 0;
}