/**
 * Commont declaration & defs
 *
 * @author 0xYkn
 */

#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN   16
#endif

//UAPI macros, not in vmlinux.h.
#ifndef AF_INET_
#define AF_INET_        2
#endif

#ifndef AF_INET6_
#define AF_INET6_       10
#endif

//min sockaddr_in6 len accepted by inet6 (sin6_scope_id optional).
#ifndef SIN6_LEN_RFC2133
#define SIN6_LEN_RFC2133 24
#endif

#ifndef bpf_map_def

/**
 * Base struct of a simple bpf map.
 */
typedef struct bpf_map_def {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
    __u32 map_flags;
} bpf_map_def;

#endif

/**
 * Get basic current caller ctx informations.
 */
typedef struct current_ctx_infos {
    __u32 pid, tgid, uid;
    char comm[TASK_COMM_LEN];
} current_ctx_infos;

#endif
