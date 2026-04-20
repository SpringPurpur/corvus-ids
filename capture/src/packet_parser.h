/*
    packet_parser.h - zero copy Ethernet/IP/TCP/UDP parser

    All fields are returned in host byte order. The parser
    never writes to the pcap buffer; it only reads through
    const pointers with explicit bounds checks before every dereference
*/
#pragma once
#include <stdint.h>
#include <stddef.h>

// result of parsing a single packet
typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // 6=TCP, 17=UDP

    // TCP flags byte (0 if protocol != 6)
    uint8_t tcp_flags;

    // TCP window size in host byte order (0 if protocol != 6)
    uint16_t tcp_window;

    // Layer 4 payload length (bytes after TCP/UDP header)
    uint16_t payload_len;

    // total IP packet length
    uint16_t ip_total_len;

    // packet timestamp in nanoseconds since epoch
    uint64_t ts_ns;
} parsed_pkt_t;

// TCP flag bit positions
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/*
    Parse a raw packet from pcap

    buf: pointer to start of Ethernet frame (pcap gives this)
    caplen: captured byte count (may be less than wire length)
    ts_ns: packet timestamp in nanoseconds
    out: filled on success

    Returns 1 on success, 0 if the packet should be dropped
    (truncated, unsupported protocol, or malformed headers)
*/
int parse_packet(const uint8_t *buf, uint32_t caplen,
                 uint64_t ts_ns, parsed_pkt_t *out);