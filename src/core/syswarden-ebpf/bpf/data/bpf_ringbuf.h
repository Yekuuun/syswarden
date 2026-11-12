#ifndef BPF_RINGBUF_H
#define BPF_RINGBUF_H

#include "../includes/bpf_config.h"

/**
 * Size of the event ringbuffer, in bytes (not in events). Must be a power of 2 and a
 * multiple of the page size. Each record also carries a small header.
 */
#ifndef RINGBUF_SIZE_BYTES
#define RINGBUF_SIZE_BYTES (256 * 1024)
#endif

/**
 * Global ringbuffer for sending events to the daemon.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_BYTES);
} ebpf_output SEC(".maps");

/**
 * drop_stats index.
 */
#define DROP_RINGBUF_FULL   0
#define DROP_FILTERED       1   // dropped on purpose by ebpf_config
#define DROP_STATS_MAX      2

/**
 * Lost events counters, read by userspace (bpf_ringbuf_reserve fails silently).
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

/**
 * ebpf_config_val.flags.
 */
#define CFG_IGNORE_LOOPBACK (1 << 0)

/**
 * Runtime filters, written by userspace before attach. Zeroed = no filtering.
 */
typedef struct ebpf_config_val {
    __u32 flags;            // CFG_*
    __u32 self_tgid;        // syswarden-ebpf own tgid, 0 = disabled
} ebpf_config_val;

_Static_assert(sizeof(ebpf_config_val) == 8, "ebpf_config_val layout");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, ebpf_config_val);
} ebpf_config SEC(".maps");

#endif