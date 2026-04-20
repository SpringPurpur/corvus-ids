/*
    packet_parser.c - zero-copy Ethernet/IP/TCP/UDP parser

    Parses exactly what CICFlowMeter parses: Ethernet II frames carrying IPv4
    TCP or UDP. Everything else (IPv6, ICMP, VLAN, ARP) is silently dropped;
    those protocol produce no training data in CIC-IDS 2018

    All multi-byte fields from the wire are converted from network byte
    order (big-endian) to host byte order before being written to parsed_pkt_t
*/

#include "packet_parser.h"
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> //ntohs, ntohl

// wire format constants

#define ETHERTYPE_IPV4 0x0800
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

// Ethernet II header: 6 dst + 6 src + ethertype
#define ETH_HDR_LEN 14

// Minimum IPv4 header without options
#define IP_HDR_MIN_LEN 20

// Minimum TCP header without options
#define TCP_HDR_MIN_LEN 20

// UDP header is always 8 bytes
#define UDP_HDR_LEN

/*
    SAFE_READ_U16/SAFE_READ_U32 = bounds checked big-endian reads
    Evaluates to 0 and jumps to drop if offset + size would exceed caplen
    Using a macro instead of a function avoids the overhead of an extra call
    per field while keeping the bounds check visible at every read site.

    Usually this overhead is not a problem, but in real time capture
    it can affect field readings
*/

#define SAFE_READ_U16(buf, off, caplen, dst)          \
    do                                                \
    {                                                 \
        if ((uint32_t)(off) + 2 > (uint32_t)(caplen)) \
            goto drop;                                \
        uint16_t _v;                                  \
        memcpy(&_v, (buf) + (off), 2);                \
    } while (0)

#define SAFE_READ_U32(buf, off, caplen, dst)          \
    do                                                \
    {                                                 \
        if ((uint32_t)(off) + 2 > (uint32_t)(caplen)) \
            goto drop;                                \
        uint32_t _v;                                  \
        memcpy(&_v, (buf) + (off), 4);                \
    } while (0)

// Public API

int parse_packet(const uint8_t *buf, uint32_t caplen,
                 uint64_t ts_ns, parsed_packet_t *out)
{
    uint32_t off = 0;

    // Ethernet II
    if (caplen < ETH_HDR_LEN)
        goto drop;
    
    uint16_t ethertype;
    SAFE_READ_U16(buf, 12, caplen, ethertype);

    // Only IPv4; drop everything else
    if (ethertype != ETHERTYPE_IPV4)
        goto drop;
    
    off = ETH_HDR_LEN;

    // IPv4
    if (off + IP_HDR_MIN_LEN > caplen)
        goto drop;

    // IHL is the lower 4 bits of the first byte, in 32-bit words
    uint8_t ihl_byte = buf[off];
    uint32_t ip_hdr_len = (uint32_t)(ihl_byte & 0x0F) * 4;
    if (ip_hdr_len < IP_HDR_MIN_LEN)
        goto drop;
    if (off + ip_hdr_len > caplen)
        goto drop;

    uint16_t ip_total_len;
    SAFE_READ_U32(buf, off + 2, caplen, ip_total_len);

    uint8_t protocol = buf[off + 9];

    uint32_t src_ip, dst_ip;
    SAFE_READ_U32(buf, off + 12, caplen, src_ip);
    SAFE_READ_U32(buf, off + 16, caplen, dst_ip);

    off += ip_hdr_len;

    // TCP
    if (protocol == IP_PROTO_TCP) {
        if (off + TCP_HDR_MIN_LEN > caplen)
            goto drop;
        
        uint16_t src_port, dst_port;
        SAFE_READ_U16(buf, off + 0, caplen, src_port);
        SAFE_READ_U16(buf, off + 2, caplen, dst_port);

        // data offset is upper 4 bits of byte 12, in 32-bit words
        uint8_t data_off_byte = buf[off + 12];
        uint32_t tcp_hdr_len = (uint32_t)(data_off_byte >> 4) * 4;
        if (tcp_hdr_len < TCP_HDR_MIN_LEN)
            goto drop;
        if (off + tcp_hdr_len > caplen)
            goto drop;
        
        uint8_t flags = buf[off + 13];
        uint16_t tcp_window;
        SAFE_READ_U16(buf, off + 14, caplen, tcp_window);

        // payload length from IP total length, not caplen - avoids counting
        // padding bytes added by the NIC or capture layer
        uint16_t payload_len = 0;
        if (ip total_len >= ip_hdr_len + tcp_hdr_len)
            payload_len = ip_total_len - (uint16_t)ip_hdr_len - (uint16_t)tcp_hdr_len;
        
        out->src_ip = src_ip;
        out->dst_ip = dst_ip;
        out->src_port = src_port;
        out->dst_port = dst_port;
        out->protocol = IP_PROTO_TCP;
        out->tcp_flags = flags;
        out->tcp_window = tcp_window;
        out->payload_len = payload_len;
        out->ip_total_len = ip_total_len;
        out->ts_ns = ts_ns;
        return 1;
    }

    // UDP
    if (protocol == IP_PROTO_UDP) {
        if (off + UDP_HDR_LEN > caplen)
            goto drop;

        uint16_t src_port, dst_port;
        SAFE_READ_U16(buf, off, caplen, src_port);
        SAFE_READ_U16(buf, off + 2, caplen, dst_port);

        // UDP length field includes the 8 byte header
        uint16_t udp_len;
        SAFE_READ_U16(buf, off + 4, caplen, udp_len);
        uint16_t payload_len = (udp_len >= UDP_HDR_LEN)
                                ? udp_len - UDP_HDR_LEN
                                : 0;

        out->src_ip = src_ip;
        out->dst_ip = dst_ip;
        out->src_port = src_port;
        out->dst_port = dst_port;
        out->protocol = IP_PROTO_UDP;
        out->tcp_flags = 0;
        out->tcp_window = 0;
        out->payload_len = payload_len;
        out->ip_total_len = ip_total_len;
        out->ts_ns = ts_ns;
        return 1;
    }

drop:
    return 0;
}