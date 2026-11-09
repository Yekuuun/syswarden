/**
 * Commont declaration & defs
 * 
 * @author 0xYkn
 */

#ifndef BPF_COMMON_H
#define BPF_COMMON_H

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

#endif