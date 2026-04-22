/*
    flow_table.c - FNV-1a hash map with linear probing and backward
    shift deletion

    Key normalisation: lower IP is always stored as src_ip. This ensures
    packets from both sides of a flow map to the same slot regardless of
    direction. The actual forward direction is recorded separately in
    flow_record_t.fwd_is_lower_ip at flow creation time

    Backward shift deletion: when a slot is freed, any entries in the
    probe chain that are displaced are shifted back. This keeps average
    probing length O(1) even under high load rather than degrading to O(n)
*/

#include "flow_table.h"
#include <string.h>
#include <stdio.h>

// FNV-1a hash over the 5 tuple
/*
    seeding for hash irregular pattern, chosen
    by Glenn Fowler, Landon Curt Noll, Phong Vo
*/
#define FNV_OFFSET_BASIS_32 0x811C9DC5U

// multiplier prime value (sparse bit pattern)
#define FNV_PRIME_32 0x01000193U

static inline uint32_t fnv1a_u32(uint32_t hash, uint32_t val)
{
    // FNV-1a: XOR then multiply, byte at a time for avalanche
    hash ^= (val & 0xFF);
    hash *= FNV_PRIME_32;
    hash ^= ((val >> 8) & 0xFF);
    hash *= FNV_PRIME_32;
    hash ^= ((val >> 16) & 0xFF);
    hash *= FNV_PRIME_32;
    hash ^= ((val >> 24) & 0xFF);
    hash *= FNV_PRIME_32;
    return hash;
}

static inline uint32_t fnv1a_u16(uint32_t hash, uint16_t val)
{
    hash ^= (val & 0xFF);
    hash *= FNV_PRIME_32;
    hash ^= ((val >> 8) & 0xFF);
    hash *= FNV_PRIME_32;
    return hash;
}

static uint32_t hash_key(const flow_key_t *k)
{
    uint32_t h = FNV_OFFSET_BASIS_32;
    h = fnv1a_u32(h, k->src_ip);
    h = fnv1a_u32(h, k->dst_ip);
    h = fnv1a_u16(h, k->src_port);
    h = fnv1a_u16(h, k->dst_port);
    h ^= k->protocol;
    h *= FNV_PRIME_32;
    return h;
}

/*
    Key normalisation

    Normalise so lower IP is always src. Returns 1 if the original src_ip
    was the lower IP, 0 if swapped
*/
static int normalise_key(flow_key_t *k)
{
    if (k->src_ip <= k->dst_ip)
        return 1;

    // swap IP and ports to put lower IP in src position
    uint32_t tmp_ip = k->src_ip;
    k->src_ip = k->dst_ip;
    k->dst_ip = tmp_ip;
    uint16_t tmp_port = k->src_port;
    k->src_port = k->dst_port;
    k->dst_port = tmp_port;
    return 0;
}

static int keys_equal(const flow_key_t *a, const flow_key_t *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip && a->src_port == b->src_port && a->dst_port == b->dst_port && a->protocol == b->protocol;
}

// Public API

void flow_table_init(flow_table_t *t)
{
    memset(t, 0, sizeof(*t));
}

flow_record_t *flow_table_get_or_create(flow_table_t *t,
                                        const parsed_pkt_t *pkt,
                                        int *out_is_new)
{
    flow_key_t key = {
        .src_ip = pkt->src_ip,
        .dst_ip = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .protocol = pkt->protocol,
    };
    int fwd_is_lower_ip = normalise_key(&key);

    uint32_t natural_slot = hash_key(&key) & (FLOW_TABLE_SIZE - 1);
    uint32_t slot = natural_slot;

    for (uint32_t i = 0; i < FLOW_TABLE_SIZE; i++)
    {
        if (!t->occupied[slot])
        {
            // empty slot, insert here
            flow_record_t *r = &t->slots[slot];
            memset(r, 0, sizeof(*r));
            r->key = key;
            r->fwd_is_lower_ip = (uint8_t)fwd_is_lower_ip;
            r->fwd_seg_size_min = UINT32_MAX; // initialize to max so first
            // update set correct min
            t->occupied[slot] = 1;
            *out_is_new = 1;
            return r;
        }

        if (t->occupied[slot] && keys_equal(&t->slots[slot].key, &key))
        {
            *out_is_new = 0;
            return &t->slots[slot];
        }

        slot = (slot + 1) & (FLOW_TABLE_SIZE - 1);
    }

    // table full, drop the packet
    t->flows_dropped++;
    if (t->flows_dropped % 1000 == 0)
    {
        fprintf(stderr, "[flow_table] WARNING: table full, %llu flows dropped total\n",
                (unsigned long long)t->flows_dropped);
    }
    return NULL;
}

void flow_table_remove(flow_table_t *t, flow_record_t *flow)
{
    // find the slot, index from the pointer
    uint32_t slot = (uint32_t)(flow - t->slots);

    t->occupied[slot] = 0;

    /*
        Robin Hood repair: shift back any entries whose natural slot is at or
        before the freed slot. Without this, their probe chains would be broken
        and the entries would become unreachable
    */
    uint32_t free_slot = slot;
    uint32_t next_slot = (slot + 1) & (FLOW_TABLE_SIZE - 1);

    while (t->occupied[next_slot])
    {
        uint32_t natural = hash_key(&t->slots[next_slot].key) & (FLOW_TABLE_SIZE - 1);

        /*
            check if next_slot's entry would benefit from moving to free_slot
            this is true when natural <= free_slot in the circular sense, meaning
            the entry is displaced and moving it closer reduces probe length
        */
        int displaced;
        if (free_slot >= natural)
            displaced = (free_slot - natural) < (next_slot - natural + FLOW_TABLE_SIZE);
        else
            displaced = (free_slot + FLOW_TABLE_SIZE - natural) < (next_slot - natural + FLOW_TABLE_SIZE);

        if (!displaced)
            break;

        // move the entry back towards its natural slot
        t->slots[free_slot] = t->slots[next_slot];
        t->occupied[free_slot] = 1;
        t->occupied[next_slot] = 0;

        free_slot = next_slot;
        next_slot = (next_slot + 1) & (FLOW_TABLE_SIZE - 1);
    }
}

void flow_table_expire(flow_table_t *t, uint64_t now_ns,
                       void (*cb)(flow_record_t *flow, void *ctx),
                       void *ctx)
{
    for (uint32_t i = 0; i < FLOW_TABLE_SIZE; i++)
    {
        if (!t->occupied[i])
            continue;
        if (t->slots[i].complete)
            continue;

        uint64_t idle = now_ns - t->slots[i].last_pkt_ns;
        uint64_t active = now_ns - t->slots[i].first_pkt_ns;

        if (idle >= FLOW_IDLE_TIMEOUT_NS)
            cb(&t->slots[i], ctx);
        else if (active >= FLOW_ACTIVE_TIMEOUT_NS)
            // active timeout: bounds detection latency to 10s regardless of FIN/RST
            cb(&t->slots[i], ctx);
    }
}