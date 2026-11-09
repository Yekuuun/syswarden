#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include "bpf_config.h"
#include "bpf_common.h"

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
 *
 * @note => returned by value: the struct lives on the caller's stack,
 * returning a pointer to a local would dangle once this frame unwinds.
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

#endif
