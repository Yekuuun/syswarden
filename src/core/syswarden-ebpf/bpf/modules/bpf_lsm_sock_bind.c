/**
 * Main file for handling LSM socket_bind endpoint.
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
 * Report inet bind() attempts. Observe only, the verdict belongs to ip / nftables.
 *
 * @ret  => verdict of the previous BPF LSM prog.
 * @note => kernel >= 5.7 (BPF LSM). sport can be 0 (ephemeral port).
 *
 * @ref => https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h
 */
SEC("lsm/socket_bind")
int BPF_PROG(lsm_socket_bind, struct socket *sock, struct sockaddr *addr, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    if (!sock)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (is_inet_sock(sk) == 0)
        return 0;

    __u16 family    = 0;
    __u16 sport     = 0;
    __u8  saddr[16] = {0};

    if (read_sockaddr(addr, addrlen, &family, &sport, saddr) < 0)
        return 0;

    ebpf_event *event = bpf_ringbuf_reserve(&ebpf_output, sizeof(ebpf_event), 0);
    if (!event)
        return 0;

    fill_event_hdr(event, EVENT_LSM_BIND);

    sock_event *sev = &event->payload.sock_event;
    __rtl_secure_zero_memory(sev, sizeof(sock_event));

    sev->sock_key = (__u64)sk;
    sev->family   = family;
    sev->proto    = BPF_CORE_READ(sk, sk_protocol);
    sev->type     = (__u16)BPF_CORE_READ(sock, type);
    sev->sport    = sport;

    __builtin_memcpy(sev->saddr, saddr, sizeof(sev->saddr));

    bpf_ringbuf_submit(event, 0);
    return 0;
}
