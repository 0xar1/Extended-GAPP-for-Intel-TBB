#!/usr/bin/env python3

from bcc import BPF
from time import sleep

bpf_source = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(start, u32);
BPF_HISTOGRAM(task_duration);

int trace_task_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);
    return 0;
}

int trace_task_end(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 duration = ts - *tsp;
    task_duration.increment(bpf_log2l(duration));

    start.delete(&pid);
    return 0;
}
"""

bpf = BPF(text=bpf_source)

alloc_symbol = "_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEmRKNS2_14execution_dataE"
dealloc_symbol = "_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE"
your_tbb_application_name = "tbb"
bpf.attach_uprobe(name=your_tbb_application_name, sym=alloc_symbol, fn_name="trace_task_start")
bpf.attach_uprobe(name=your_tbb_application_name, sym=dealloc_symbol, fn_name="trace_task_end")

print("Tracing task execution time... Hit Ctrl-C to end.")

try:
    while True:
        sleep(1)
        bpf["task_duration"].print_log2_hist("Task duration (ns)")
        bpf["task_duration"].clear()

except KeyboardInterrupt:
    print("Detaching...")
    bpf.detach_uprobe(alloc_symbol)
    bpf.detach_uprobe(dealloc_symbol)
