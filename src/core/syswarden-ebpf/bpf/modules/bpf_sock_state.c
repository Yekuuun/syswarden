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
    return 0;
}