#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include "bpf_config.h"
#include "bpf_common.h"
#include "../data/bpf_events.h"
#include "../data/bpf_ringbuf.h"

/**
 * Utility function for cleaning memory structs
 *
 * @note => sequels from Windows ;)
 */
static __always_inline void __rtl_secure_zero_memory(void *dst, __u32 size)
{
    __builtin_memset(dst, 0, size);
}

/**
 * Get current context informations.
 */
static __always_inline current_ctx_infos get_current_ctx_infos()
{
    current_ctx_infos ctx = {0};
    __rtl_secure_zero_memory(&ctx, sizeof(current_ctx_infos));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_tgid = bpf_get_current_uid_gid();

    ctx.pid  = (__u32)pid_tgid;
    ctx.uid  = (__u32)uid_tgid;
    ctx.tgid = pid_tgid >> 32;

    bpf_get_current_comm(&ctx.comm, TASK_COMM_LEN);

    return ctx;
}

/**
 * Increment a drop_stats counter.
 *
 * @idx => DROP_*.
 */
static __always_inline void inc_drop_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&drop_stats, &idx);
    if (!count)
        return;

    //per-cpu value, no atomic needed.
    *count += 1;
}

/**
 * Reserve a zeroed event on the ringbuf, counts the drop on failure.
 *
 * @note => zeroed so padding never leaks kernel bytes to userspace.
 */
static __always_inline ebpf_event *reserve_event(void)
{
    ebpf_event *event = bpf_ringbuf_reserve(&ebpf_output, sizeof(ebpf_event), 0);
    if (!event) {
        inc_drop_stat(DROP_RINGBUF_FULL);
        return NULL;
    }

    __rtl_secure_zero_memory(event, sizeof(ebpf_event));
    return event;
}

/**
 * Check if an address is loopback (127.0.0.0/8, ::1, ::ffff:127.0.0.0/104).
 *
 * @ip => 4 bytes for AF_INET_, 16 for AF_INET6_, network byte order.
 */
static __always_inline int is_loopback(__u16 family, const __u8 *ip)
{
    if (family == AF_INET_)
        return ip[0] == 127;

    if (family != AF_INET6_)
        return 0;

    __u64 hi  = 0;
    __u32 mid = 0;
    __u32 lo  = 0;

    __builtin_memcpy(&hi, ip, 8);
    __builtin_memcpy(&mid, ip + 8, 4);
    __builtin_memcpy(&lo, ip + 12, 4);

    if (hi != 0)
        return 0;

    if (mid == 0 && lo == bpf_htonl(1))
        return 1;

    //v4-mapped.
    return mid == bpf_htonl(0x0000ffff) && ip[12] == 127;
}

/**
 * Apply ebpf_config filters, counts the event in DROP_FILTERED when filtered.
 *
 * @ip         => remote addr, same layout as is_loopback.
 * @check_self => only in syscall context, current is random in softirq.
 */
static __always_inline int is_filtered(__u16 family, const __u8 *ip, int check_self)
{
    __u32 key = 0;

    ebpf_config_val *cfg = bpf_map_lookup_elem(&ebpf_config, &key);
    if (!cfg)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (check_self == 1 && cfg->self_tgid != 0 && tgid == cfg->self_tgid) {
        inc_drop_stat(DROP_FILTERED);
        return 1;
    }

    if ((cfg->flags & CFG_IGNORE_LOOPBACK) != 0 && is_loopback(family, ip) == 1) {
        inc_drop_stat(DROP_FILTERED);
        return 1;
    }

    return 0;
}

/**
 * Fill the event header with the current task infos.
 *
 * @event       => zeroed record from reserve_event.
 * @type        => EVENT_*.
 * @attribution => ATTR_*.
 */
static __always_inline void fill_event_hdr(ebpf_event *event, __u16 type, __u8 attribution)
{
    current_ctx_infos caller = get_current_ctx_infos();

    event->hdr.schema_version = EVENT_SCHEMA_VERSION;
    event->hdr.type           = type;
    event->hdr.size           = sizeof(ebpf_event);
    event->hdr.ts_ns          = bpf_ktime_get_ns();
    event->hdr.pid            = caller.pid;
    event->hdr.tgid           = caller.tgid;
    event->hdr.uid            = caller.uid;
    event->hdr.attribution    = attribution;

    __builtin_memcpy(event->hdr.comm, caller.comm, sizeof(event->hdr.comm));
}

/**
 * Check if a sock is AF_INET / AF_INET6.
 *
 * @sk => may be NULL.
 */
static __always_inline int is_inet_sock(struct sock *sk)
{
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    return family == AF_INET_ || family == AF_INET6_;
}

/**
 * Decode an inet sockaddr given to a LSM hook.
 *
 * @addrlen => not validated by the kernel yet at LSM time.
 * @port    => out, host byte order.
 * @ip      => out, 16 bytes, network byte order.
 */
static __always_inline int read_sockaddr(struct sockaddr *addr, int addrlen, __u16 *family, __u16 *port, __u8 *ip)
{
    if (!addr)
        return -1;

    __u16 sa_family = BPF_CORE_READ(addr, sa_family);

    //AF_UNSPEC (udp disconnect), AF_UNIX, ...
    if (sa_family != AF_INET_ && sa_family != AF_INET6_)
        return -1;

    //bytes past addrlen are stale sockaddr_storage content.
    if (sa_family == AF_INET_ && addrlen < (int)sizeof(struct sockaddr_in))
        return -1;

    if (sa_family == AF_INET6_ && addrlen < SIN6_LEN_RFC2133)
        return -1;

    *family = sa_family;

    if (sa_family == AF_INET_) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;

        *port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
        return bpf_core_read(ip, 4, &sin->sin_addr.s_addr);
    }

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

    *port = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
    return bpf_core_read(ip, 16, &sin6->sin6_addr);
}

/**
 * Read the local endpoint of a sock (zero when not bound yet).
 *
 * @sk   => must not be NULL.
 * @port => out, host byte order (skc_num is not __be16).
 * @ip   => out, 16 bytes, network byte order.
 */
static __always_inline void read_sock_local(struct sock *sk, __u16 *port, __u8 *ip)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    *port = BPF_CORE_READ(sk, __sk_common.skc_num);

    if (family == AF_INET_){
        bpf_core_read(ip, 4, &sk->__sk_common.skc_rcv_saddr);
    }
    else {
        bpf_core_read(ip, 16, &sk->__sk_common.skc_v6_rcv_saddr);
    }
}

#endif
