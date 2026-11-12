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

    ebpf_event *event = reserve_event();
    if(!event)
        return 0;

    //transitions mostly run in softirq, pid / comm may belong to any task.
    fill_event_hdr(event, event_type, ATTR_UNRELIABLE);

    //main payload.
    conn_event *conn = &event->payload.conn_event;

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
    
    if(ctx->family == AF_INET6_) {
        __builtin_memcpy(conn->saddr, ctx->saddr_v6, sizeof(ctx->saddr_v6));
        __builtin_memcpy(conn->daddr, ctx->daddr_v6, sizeof(ctx->daddr_v6));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
