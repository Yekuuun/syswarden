/**
 * Main file for handling LSM socket_connect endpoint.
 * 
 * @note => kernel must have LSM configured to run LSM based endpoints.
 * 
 * @author Yekuuun
 */

#include "../includes/bpf_common.h"
#include "../includes/bpf_config.h"
#include "../includes/bpf_structs.h"
#include "../includes/bpf_utils.h"
#include "../data/bpf_events.h"
#include "../data/bpf_ringbuf.h"

/**
 * Report inet connect() attempts. Observe only, the verdict belongs to ip / nftables.
 *
 * @ret  => verdict of the previous BPF LSM prog.
 * @note => kernel >= 5.7 (BPF LSM).
 *
 * @ref => https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h
 */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    if (!sock)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (is_inet_sock(sk) == 0)
        return 0;

    __u16 family    = 0;
    __u16 dport     = 0;
    __u8  daddr[16] = {0};

    if (read_sockaddr(addr, addrlen, &family, &dport, daddr) < 0)
        return 0;

    if (is_filtered(family, daddr, 1) == 1)
        return 0;

    ebpf_event *event = reserve_event();
    if (!event)
        return 0;

    //syscall context, current is the caller.
    fill_event_hdr(event, EVENT_LSM_CONNECT, ATTR_RELIABLE);

    sock_event *sev = &event->payload.sock_event;

    sev->sock_key = (__u64)sk;
    sev->family   = family;
    sev->proto    = BPF_CORE_READ(sk, sk_protocol);
    sev->type     = (__u16)BPF_CORE_READ(sock, type);
    sev->dport    = dport;

    __builtin_memcpy(sev->daddr, daddr, sizeof(sev->daddr));

    //usually zero, unless bind() was called before connect().
    read_sock_local(sk, &sev->sport, sev->saddr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
