/**
 * Main file for handling handle_sock_state events
 *
 * @author 0xYkn
 */

#include "../includes/bpf_common.h"
#include "../includes/bpf_config.h"
#include "../includes/bpf_structs.h"
#include "../includes/bpf_utils.h"
#include "../data/bpf_events.h"
#include "../data/bpf_ringbuf.h"

#define IPPROTO_TCP_ 6

/**
 * AF_INET/AF_INET6 are plain UAPI macros
 */
#define AF_INET_  2
#define AF_INET6_ 10

/**
 * handle inet_sock_set_state function
 *
 * @param ctx => inet_sock_set_state struct (view bpf_structs)
 *
 * @note => linux kernel version >= 4.16
 */
SEC("tp/sock/inet_sock_set_state")
int sock_handle_set_state(struct inet_sock_set_state *ctx)
{
    if(!ctx)
        return 0;

    /**
     * Handling only TCP connections for the moment.
     * https://elixir.bootlin.com/linux/v3.9/source/include/uapi/linux/in.h#L30
     */
    if(ctx->protocol != IPPROTO_TCP_)
        return 0;

    /**
     * Only the two transitions that bound a connection's lifecycle are
     * reported for now: it becomes active (ESTABLISHED) or it's torn down
     * (CLOSE). Every other intermediate state (SYN_SENT, FIN_WAIT, ...) is
     * ignored.
     */
    __u16 event_type;

    if(ctx->newstate == TCP_ESTABLISHED){
        event_type = EVENT_CONN_OPEN;
    }
    else if(ctx->newstate == TCP_CLOSE){
        event_type = EVENT_CONN_CLOSE;
    }
    else{
        return 0;
    }

    ebpf_event *event = bpf_ringbuf_reserve(&ebpf_output, sizeof(ebpf_event), 0);
    if(!event)
        return 0;

    current_ctx_infos caller = get_current_ctx_infos();

    event->hdr.schema_version = 1;
    event->hdr.type           = event_type;
    event->hdr.size           = sizeof(ebpf_event);
    event->hdr.ts_ns          = bpf_ktime_get_ns();
    event->hdr.pid            = caller.pid;
    event->hdr.tgid           = caller.tgid;
    event->hdr.uid            = caller.uid;

    __rtl_secure_zero_memory(event->hdr.comm, sizeof(event->hdr.comm));
    __builtin_memcpy(event->hdr.comm, caller.comm, sizeof(event->hdr.comm));

    conn_event *conn = &event->payload.conn_event;
    __rtl_secure_zero_memory(conn, sizeof(conn_event));

    conn->sock_key  = (__u64)ctx->skaddr;
    conn->family    = ctx->family;
    conn->proto     = ctx->protocol;
    conn->sport     = ctx->sport;
    conn->dport     = ctx->dport;
    conn->old_state = (__u8)ctx->oldstate;
    conn->new_state = (__u8)ctx->newstate;

    conn->direction = (ctx->oldstate == TCP_SYN_SENT) ? 0 /* ACTIVE */ : 1 /* PASSIVE */;

    if(ctx->family == AF_INET_) {
        __builtin_memcpy(conn->saddr, ctx->saddr, sizeof(ctx->saddr));
        __builtin_memcpy(conn->daddr, ctx->daddr, sizeof(ctx->daddr));
    }
    else if(ctx->family == AF_INET6_) {
        __builtin_memcpy(conn->saddr, ctx->saddr_v6, sizeof(ctx->saddr_v6));
        __builtin_memcpy(conn->daddr, ctx->daddr_v6, sizeof(ctx->daddr_v6));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
