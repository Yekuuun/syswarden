/**
 * Global utility libs for configuring the bpf project.
 * 
 * @author 0xYkn
 */

#ifndef BPF_CONFIG_H
#define BPF_CONFIG_H

/**
 * Global vmlinux config.
 */
#include "./vmlinux/vmlinux.h"

/**
 * Utils
 */
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#endif