#ifndef BPF_RINGBUF_H
#define BPF_RINGBUF_H

#include "../includes/bpf_config.h"

/**
 * Size of the event ringbuffer, in bytes (not in events). Must be a power of 2 and a
 * multiple of the page size. Each record also carries a small header.
 */
#ifndef RINGBUF_SIZE_BYTES
#define RINGBUF_SIZE_BYTES 16384
#endif

/**
 * Global ringbuffer for sending events to the daemon.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_BYTES);
} ebpf_output SEC(".maps");

#endif