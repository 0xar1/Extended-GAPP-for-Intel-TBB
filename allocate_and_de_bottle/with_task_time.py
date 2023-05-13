#!/usr/bin/env python3

from bcc import BPF
from time import sleep, time_ns
import ctypes as ct

bpf_source = r"""
#include <uapi/linux/ptrace.h>

struct task_info {
    u64 alloc_time;
    u64 dealloc_time;
};

BPF_HASH(task_info, u32, struct task_info);

int trace_alloc(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct task_info info = {};
    info.alloc_time = bpf_ktime_get_ns();
    task_info.update(&pid, &info);
    return 0;
}

int trace_dealloc(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct task_info *info = task_info.lookup(&pid);
    if (info) {
        info->dealloc_time = bpf_ktime_get_ns();
        u64 time_ns = info->dealloc_time - info->alloc_time;
        task_info.delete(&pid);
    }
    return 0;
}
"""

alloc_symbol = "_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEm"
dealloc_symbol = "_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE"

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="libtbb.so", sym=alloc_symbol, fn_name="trace_alloc")
bpf.attach_uprobe(name="libtbb.so", sym=dealloc_symbol, fn_name="trace_dealloc")

print("Tracing Intel TBB task allocations and deallocations... Ctrl-C to end.")
try:
    while True:
        sleep(1)
        for task, value in bpf.get_table("task_info").items():
            if value.dealloc_time > 0:
                time_ns = value.dealloc_time - value.alloc_time
                print(f"Task {task.value}: Time {time_ns} ns")
                bpf.get_table("task_info").delete(task)
except KeyboardInterrupt:
    print("Ending tracing.")
