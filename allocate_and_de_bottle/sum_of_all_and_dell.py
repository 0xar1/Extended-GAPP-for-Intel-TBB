#!/usr/bin/env python3

from bcc import BPF
from time import sleep
import ctypes as ct

bpf_source = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(alloc_count);
BPF_HASH(dealloc_count);

int trace_alloc(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *count = alloc_count.lookup(&key);
    if (!count) {
        u64 zero = 0;
        alloc_count.update(&key, &zero);
        count = alloc_count.lookup(&key);
    }
    if (count) {
        (*count)++;
    }
    return 0;
}

int trace_dealloc(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *count = dealloc_count.lookup(&key);
    if (!count) {
        u64 zero = 0;
        dealloc_count.update(&key, &zero);
        count = dealloc_count.lookup(&key);
    }
    if (count) {
        (*count)++;
    }
    return 0;
}
"""

alloc_symbol = "_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEm"
dealloc_symbol = "_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE"

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="tbb", sym=alloc_symbol, fn_name="trace_alloc")
bpf.attach_uprobe(name="tbb", sym=dealloc_symbol, fn_name="trace_dealloc")

print("Tracing Intel TBB task allocations and deallocations... Ctrl-C to end.")
try:
    while True:
        sleep(1)
        alloc_key = ct.c_ulonglong(0)
        dealloc_key = ct.c_ulonglong(0)
        alloc_count = bpf["alloc_count"][alloc_key].value if bpf["alloc_count"].__contains__(alloc_key) else 0
        dealloc_count = bpf["dealloc_count"][dealloc_key].value if bpf["dealloc_count"].__contains__(dealloc_key) else 0
        print(f"Allocated tasks: {alloc_count}, Deallocated tasks: {dealloc_count}")
except KeyboardInterrupt:
    print("Ending tracing.")
