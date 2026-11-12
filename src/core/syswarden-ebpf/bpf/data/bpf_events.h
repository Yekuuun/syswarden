#ifndef BPF_EVENTS_H
#define BPF_EVENTS_H

#include "../includes/bpf_config.h"
#include "../includes/bpf_common.h"

/**
 * Global event types.
 */
#define EVENT_CONN_OPEN     1
#define EVENT_CONN_CLOSE    2
#define EVENT_LSM_CONNECT   3
#define EVENT_LSM_BIND      4

//-------------------------------

/**
 * Global event packet hdr. Contains usefull infos about event sendt.
 */
typedef struct event_hdr {
    __u16 schema_version;   // 1
    __u16 type;             // CONN_OPEN, CONN_CLOSE, LSM_CONNECT, ...
    __u16 size;             
    __u64 ts_ns;            // bpf_ktime_get_ns
    
    __u32 pid, tgid, uid;
    __u8  comm[16];
    __u8  _pad[3];
} event_hdr;

//--------------------------------

typedef struct conn_event {
    __u64 sock_key;
    __u16 family, proto, sport, dport;
    __u8  saddr[16], daddr[16];
    __u8  old_state, new_state, direction; // ACTIVE | PASSIVE
    __u8  _pad[1];
} conn_event;

typedef struct sock_event {
    __u64 sock_key;
    __u16 family, proto, type;
    __u16 sport, dport;
    __u8  saddr[16], daddr[16];
    __u8  _pad[6];
} sock_event;

/**
 * Main payload send on the ringbuffer.
 */
typedef struct ebpf_event {
    struct event_hdr hdr;

    union {
        conn_event conn_event;
        sock_event sock_event;
    } payload;

} ebpf_event;

#endif