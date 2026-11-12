/**
 * Main entry point for the syswarden-ebpf project bpf source
 * 
 * @author 0xYkn
 */

#include "./includes/bpf_config.h"

//modules
#include "./modules/bpf_tp_sock_state.c"
#include "./modules/bpf_lsm_sock_connect.c"
#include "./modules/bpf_lsm_sock_bind.c"

char LICENSE[] SEC("license") = "GPL";