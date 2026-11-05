#ifndef BPF_EVENTS_H
#define BPF_EVENTS_H

#include "../includes/bpf_config.h"
#include "../includes/bpf_common.h"

/**
 * Global event types.
 */
#define EVENT_CONNECTION_OPEN  1
#define EVENT_CONNECTION_CLOSE 2

//-------------------------------

/**
 * Global event packet hdr. Contains usefull infos about event sendt.
 */
typedef struct event_hdr {
    __u16 type;
    __u16 size;
    __u64 timestamp;
} __attribute__((packed)) event_hdr;

/**
 * Simple macro for fast event hdr creation.
 */
#define SET_EVENT_HDR(_type, _size, _timestamp) \
((event_hdr) {                             \
    .type       = (_type),                      \
    .size       = (_size),                      \
    .timestamp  = (_timestamp)                  \
})

//--------------------------------

typedef struct event_payload_conn_open {
    __u16 port;
    __u32 ipv4_addr;
    char protocol[DNAME_PROTOCOL_SIZE];

    //ipv6 ?
} __attribute__((packed)) event_payload_conn_open;

typedef struct event_payload_conn_close {
    __u16 port;
    __u32 ipv4_addr;

    //ipv6 ?
} __attribute__((packed)) event_payload_conn_close;

/**
 * Main payload send on the ringbuffer.
 */
typedef struct ebpf_event {
    struct event_hdr hdr;

    union {
        event_payload_conn_close conn_close;
        event_payload_conn_open  conn_open;
    } payload;

} __attribute__((packed)) ebpf_event;

#endif