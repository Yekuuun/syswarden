/**
 * Main file for handling handle_sock_state events
 * 
 * @author 0xYkn
 */

#include "../includes/bpf_common.h"
#include "../includes/bpf_config.h"
#include "../includes/bpf_structs.h"


/**
 * handle inet_sock_set_state function
 * 
 * @param ctx => inet_sock_set_state struct (view bpf_structs)
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
    if(ctx->protocol != IPPROTO_TCP)
        return 0;

    
        
    return 0;
}