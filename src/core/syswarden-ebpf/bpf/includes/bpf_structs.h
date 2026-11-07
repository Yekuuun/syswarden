#ifndef BPF_STRUCTS
#define BPF_STRUCTS

#include "bpf_common.h"
#include "bpf_config.h"

//----------------------------------------------------
// ┌────────────────────────────────────┐
//  SOCKETS
// └────────────────────────────────────┘
//----------------------------------------------------

/**
 * >> cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
 */
typedef struct inet_sock_set_state {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    int   common_pid;

    void* skaddr;
    int   oldstate;
    int   newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
} inet_sock_set_state;


#endif