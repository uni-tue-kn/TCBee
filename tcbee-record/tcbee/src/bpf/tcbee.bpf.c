// SPDX-License-Identifier: (MIT OR GPL-2.0)
// All tcbee-record eBPF programs, built into a single object with libbpf CO-RE.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "config.h"
#include "records.h"
#include "maps.h"
#include "counters.h"
#include "filter.h"
#include "flow.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
