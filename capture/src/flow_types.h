/*
flow_types.h - flow_key_t

*/
#pragma once
#include <stdint.h>

typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // 6=TCP, 17=UDP
    uint8_t _pad[3];
} flow_key_t;

typedef struct
{
    // identity
    flow_key_t key;
    uint64_t first_pkt_ns;
    uint64_t last_pkt_ns;
    float flow_duration_s;

    // TCP feature set
    uint16_t init_fwd_win_bytes; // TCP window from first fwd SYN, raw value
                                 // (not scaled; CICFlowMeter records pre-scale)
    uint32_t rst_flag_cnt;
    float bwd_pkts_per_sec;
    uint16_t bwd_pkt_len_max;
    uint32_t tot_fwd_pkts;
    float pkt_len_mean; // computed by AVX2 at finalisation
    uint32_t ack_flag_cnt;
    uint32_t psh_flag_cnt;
    float pkt_len_std;  // population std, computed by AVX2
    float bwd_pkt_len_std; // population std of bwd lengths
    uint32_t fwd_seg_size_min; // min fwd payload length (TCP MSS proxy)
    uint32_t fwd_act_data_pkts; // fwd packets with payload_len > 0

    // UDP feature set
    uint64_t tot_fwd_bytes;
    uint64_t tot_bwd_bytes;
    uint16_t fwd_pkt_len_max;
    float flow_iat_mean; // mean inter-arrival time across all packets
    float fwd_iat_std; // std of fwd inter-arrival times

    // shared counters
    uint32_t tot_bwd_pkts;
    uint32_t tot_pkts;
    uint32_t syn_flag_cnt;
    uint32_t fin_flag_cnt;
    uint32_t urg_flag_cnt;
    float bwd_pkt_len_mean;

    // derived features (computed at finalisation, used by both IF models)
    // selected from the network measurement literature
    // fwd_pkts_per_sec - primary flood rate indicatior
    // syn_flag_ratio - SYN flood signature; normalised to be duration-independent
    // psh_flag_ratio - data transfer pattern; floods have near-zero PSH ratio
    float fwd_pkts_per_sec;
    float syn_flag_ratio; // syn_flag_cnt / tot_pkts
    float psh_flag_ratio; // psh_flag_cnt / tot_pkts

    // accumulation buffers (internal, not sent to Python)
    // capped at buffer size; values beyond the cap are silently dropped
    // under flood conditions this is expected, not an error
    uint16_t pkt_len_buf[512]; // all packet lengths for AVX2 mean/std
    uint32_t pkt_len_buf_count;
    uint16_t bwd_pkt_len_buf[512]; // bwd packet lengths for AVX2 mean/std
    uint32_t bwd_pkt_len_buf_count;
    uint64_t fwd_iat_buf[256]; // fwd inter-arrival ns deltas (differences)
    uint32_t fwd_iat_buf_count;
    uint64_t all_iat_buf[256]; // all inter-arrival ns deltas
    uint32_t all_iat_buf_count;
    uint64_t last_pkt_ns_for_iat; // timestamp of previous packet (any direction)
    uint64_t last_fwd_pkt_ns; // timestamp of previous fwd packet

    // pipeline timing
    // t_enque_ns - wall-clock ns when the flow was copied into the IPC ring buffer
    // by ipc_writer_enqueue(). Subtract from Python t_socket_ns to get IPC transfer
    // time (~microseconds). Subtracting first_pkt_ns would give flow lifetime, not
    // IPC latency
    uint64_t t_enqueue_ns;

    // state flags
    uint8_t complete;
    // forward direction is defined by the first packet seen, not key normalisation
    // fwd_is_lower_ip=1 means the lower IP side sent the first packet
    uint8_t fwd_is_lower_ip;
    uint8_t init_win_captured; // set to 1 after first fwd SYN window recorded
    uint8_t _pad[1];
} flow_record_t; // sizeof(flow_record_t)=6352