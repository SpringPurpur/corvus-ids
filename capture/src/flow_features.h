/*
    flow_features.h - per packet feature accumulation and flow finalisation

    features_update() is called on every packet and must be fast - it runs
    inside the libpcap callback on the capture thread

    features_finalise() is called once when a flow completes (FIN, RST, or
    timeout). It runs the AVX2 routines over the accumulated buffers and sets
    flow->complete = 1
*/
#pragma once
#include "flow_types.h"
#include "packet_parser.h"

/*
    Accumulate per packet features into the flow record

    is_fwd: 1 if this packet is in the forward direction, 0 for backward
    Determined by the caller (main.c) based on fwd_is_lower_ip and packet IPs
*/
void features_update(flow_record_t *flow, const parsed_pkt_t *pkt, int is_fwd);

/*
    Finalise the flow: run AVX2 stats over accumulated buffers, compute IAT
    statistics, set complete to 1

    Must only be called once per flow. After this the flow is ready to
    be emitted to the IPC socket
*/
void features_finalise(flow_record_t *flow);

// AVX2 declarations - implemented in asm/features_avx2.asm
void compute_pkt_len_stats_avx2(uint16_t *buf, uint32_t count,
                                float *out_mean, float *out_std);

void count_tcp_flags_avx2(uint8_t *flags, uint32_t count,
                          uint32_t *fin, uint32_t *syn, uint32_t *rst,
                          uint32_t *psh, uint32_t *ack, uint32_t *urg);