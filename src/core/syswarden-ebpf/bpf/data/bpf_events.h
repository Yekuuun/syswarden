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

#define EVENT_SCHEMA_VERSION 1

/**
 * hdr.attribution: is pid / comm really the task behind the event ?
 */
#define ATTR_RELIABLE       1
#define ATTR_UNRELIABLE     2   // softirq / timer context, current is random

//-------------------------------

/**
 * Global event packet hdr. Contains usefull infos about event sendt.
 */
typedef struct event_hdr {
    __u16 schema_version;   // EVENT_SCHEMA_VERSION
    __u16 type;             // EVENT_*
    __u32 size;
    __u64 ts_ns;            // bpf_ktime_get_ns (monotonic)

    __u32 pid, tgid, uid;
    __u8  comm[16];
    __u8  attribution;      // ATTR_*
    __u8  _pad[3];
} event_hdr;

//--------------------------------

typedef struct conn_event {
    __u64 sock_key;
    __u16 family, proto, sport, dport;
    __u8  saddr[16], daddr[16];
    __u8  old_state, new_state, direction; // ACTIVE | PASSIVE
    __u8  _pad[5];
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

//layout shared with userspace, no implicit padding allowed.
_Static_assert(sizeof(event_hdr) == 48, "event_hdr layout");
_Static_assert(sizeof(conn_event) == 56, "conn_event layout");
_Static_assert(sizeof(sock_event) == 56, "sock_event layout");
_Static_assert(sizeof(ebpf_event) == 104, "ebpf_event layout");
_Static_assert(__builtin_offsetof(ebpf_event, payload) == 48, "payload offset");

#endif