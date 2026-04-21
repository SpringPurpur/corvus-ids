/*
    flow_features.c - per packet feature accumulation and AVX2 finalisation

    The update path is called inside the libpcap callback; every nanosecond
    counts. Avoid function call overhead; keep hot paths branch-free where
    possible

    All features are defined to match CICFlowMeter conventions. WHere
    CICFlowMeter behaviour is not obvious, the relevant comment explains the
    specific rule being matched
*/

#include "flow_features.h"
#include <string.h>
#include <math.h>
#include <stdint.h>

// helpers

static inline uint64_t iat_delta(uint64_t now, uint64_t prev)
{
    return (now > prev) ? (now - prev) : 0;
}

// per packet accumulation
void features_update(flow_record_t *flow, const parsed_pkt_t *pkt, int is_fwd)
{
    /*
        Never update a completed flow; libpcap can deliver retransmissions
        after FIN/RST and we must not corrupt finalised stats
    */
    if (flow->complete)
        return;

    uint64_t ts = pkt->ts_ns;
    uint16_t ip_len = pkt->ip_total_len; // wire level packet length
    uint16_t payload = pkt->payload_len;

    // timestamps
    if (flow->first_pkt_ns == 0)
        flow->first_pkt_ns = ts;
    flow->last_pkt_ns = ts;

    // all packet IAT
    if (flow->last_pkt_ns_for_iat != 0)
    {
        uint64_t delta = iat_delta(ts, flow->last_pkt_ns_for_iat);
        if (flow->all_iat_buf_count < 256)
            flow->all_iat_buf[flow->all_iat_buf_count++] = delta;
    }
    flow->last_pkt_ns_for_iat = ts;

    // all packet length buffer (for global mean/std)
    // clamp to buffer size; under flood conditions this is expected
    if (flow->pkt_len_buf_count < 512)
        flow->pkt_len_buf[flow->pkt_len_buf_count++] = ip_len;

    flow->tot_pkts++;

    // forward direction
    if (is_fwd)
    {
        flow->tot_fwd_pkts++;
        flow->tot_fwd_bytes += ip_len;

        // fwd packet length max
        if (ip_len > flow->fwd_pkt_len_max)
            flow->fwd_pkt_len_max = ip_len;

        /*
            Fwd segment size min: min of payload lengths, not IP lengths
            Only meaningful for TCP; UDP "segments" have the same concept
            Initialized to UINT32_MAX at flow creation so first packet sets in
        */
        if (payload < flow->fwd_seg_size_min)
            flow->fwd_seg_size_min = payload;

        // count packets with actual data payload
        if (payload > 0)
            flow->fwd_act_data_pkts++;

        // fwd IAT
        if (flow->last_fwd_pkt_ns != 0)
        {
            uint64_t delta = iat_delta(ts, flow->last_fwd_pkt_ns);
            if (flow->fwd_iat_buf_count < 256)
                flow->fwd_iat_buf[flow->fwd_iat_buf_count++] = delta;
        }
        flow->last_pkt_ns = ts;

        // TCP specific
        if (pkt->protocol == 6)
        {
            /*
                Capture initial window size from the first forward SYN only
                Post-SYN packets may have window scaling applied; the raw SYN
                value is what CICFlowMeter records and what the model trains on
            */
            if (!flow->init_win_captured && (pkt->tcp_flags & 0x02))
            {
                flow->init_fwd_win_bytes = pkt->tcp_window;
                flow->init_win_captured = 1;
            }
        }
    }

    // backward direction
    else
    {
        flow->tot_bwd_pkts++;
        flow->tot_bwd_bytes += ip_len;

        if (ip_len > flow->bwd_pkt_len_max)
            flow->bwd_pkt_len_max = ip_len;

        // backward packet length buffer for AVX2 mean/std
        if (flow->bwd_pkt_len_buf_count < 512)
            flow->bwd_pkt_len_buf[flow->bwd_pkt_len_buf_count++] = ip_len;
    }

    /*
        TCP flags: accumulate individually here; AVX2 batch at finalisation
        Raw flag bytes go into a per packet buffer for the AVX2 path, but we
        also track them incrementally for correctness under small counts
    */

    if (pkt->protocol == 6)
    {
        uint8_t f = pkt->tcp_flags;
        if (f & 0x01)
            flow->fin_flag_cnt++;
        if (f & 0x02)
            flow->syn_flag_cnt++;
        if (f & 0x04)
            flow->rst_flag_cnt++;
        if (f & 0x08)
            flow->psh_flag_cnt++;
        if (f & 0x10)
            flow->ack_flag_cnt++;
        if (f & 0x20)
            flow->urg_flag_cnt++;
    }
}

// flow finalisation

void features_finalise(flow_record_t *flow)
{
    if (flow->complete)
        return;

    // flow duration
    if (flow->last_pkt_ns > flow->first_pkt_ns)
    {
        double dur_ns = (double)(flow->last_pkt_ns - flow->first_pkt_ns);
        flow->flow_duration_s = (float)(dur_ns / 1e9); // conversion to seconds
    }
    else
        flow->flow_duration_s = 0.0f;

    // bacward packets per second
    if (flow->flow_duration_s > 0.0f)
        flow->bwd_pkts_per_sec = (float)flow->tot_bwd_pkts / flow->flow_duration_s;
    else
        flow->bwd_pkts_per_sec = 0.0f;

    // global packet length mean and std (AVX2)
    if (flow->pkt_len_buf_count > 0)
    {
        compute_pkt_len_stats_avx2(
            flow->pkt_len_buf,
            flow->pkt_len_buf_count,
            &flow->pkt_len_mean,
            &flow->pkt_len_std);
    }

    // backward packet length mean and std (AVX2)
    if (flow->bwd_pkt_len_buf_count > 0)
    {
        compute_pkt_len_stats_avx2(
            flow->bwd_pkt_len_buf,
            flow->bwd_pkt_len_buf_count,
            &flow->bwd_pkt_len_mean,
            &flow->bwd_pkt_len_std);
    }

    // flow IAT mean (all packets)
    if (flow->all_iat_buf_count > 0)
    {
        /*
            Scalar mean over IAT buffer; AVX2 path not used here due
            to uint64 width of IAT deltas (truncation risk uint16 downscale)
        */
        double sum = 0.0;
        for (uint32_t i = 0; i < flow->all_iat_buf_count; i++)
            sum += (double)flow->all_iat_buf[i];
        flow->flow_iat_mean = (float)(sum / flow->all_iat_buf_count);
    }

    // forward IAT std (scalar double for precision)
    if (flow->fwd_iat_buf_count > 0)
    {
        double sum = 0.0;
        for (uint32_t i = 0; i < flow->fwd_iat_buf_count; i++)
            sum += (double)flow->fwd_iat_buf[i];
        double mean = sum / flow->fwd_iat_buf_count;

        double sq_sum = 0.0;
        for (uint32_t i = 0; i < flow->fwd_iat_buf_count; i++)
        {
            double d = (double)flow->fwd_iat_buf[i] - mean;
            sq_sum = d * d;
        }
        flow->fwd_iat_std = (float)sqrt(sq_sum / flow->fwd_iat_buf_count);
    }

    // fwd_seg_size_min: if no fwd packets were seen, reset to 0
    if (flow->fwd_seg_size_min == UINT32_MAX)
        flow->fwd_seg_size_min = 0;

    /*
        Derived features for OnlineIsolationForest models
        Normalised ratios are duration/count independent, per RFC 7011
        A 10-packet SYN flood has the same syn_flag_ratio as a 10000-packet one
    */
    flow->fwd_pkts_per_sec = (flow->flow_duration_s > 0.0f)
        ? (float)flow->tot_fwd_pkts / flow->flow_duration_s : 0.0f;

    flow->syn_flag_ratio = (flow->tot_pkts > 0)
        ? (float)flow->syn_flag_cnt / (float)flow->tot_pkts : 0.0f;

    flow->psh_flag_ratio = (flow->tot_pkts > 0)
        ? (float)flow->psh_flag_cnt / (float)flow->tot_pkts : 0.0f;

    flow->complete = 1;
}