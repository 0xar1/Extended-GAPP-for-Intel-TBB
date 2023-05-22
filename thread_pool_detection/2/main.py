#!/usr/bin/env python3

from bcc import BPF
import ctypes
import time

# BPF program to trace Intel TBB task stack and task pool
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct task_info_t {
    u64 task_address;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 timestamp;
};

BPF_HASH(task_stack_count, u64, u64);
BPF_HASH(task_pool_count, u64, u64);
BPF_PERF_OUTPUT(events);

int trace_task_allocate(struct pt_regs *ctx) {
    u64 task_address = PT_REGS_PARM1(ctx);
    u64 *count = task_pool_count.lookup(&task_address);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        task_pool_count.update(&task_address, &one);
    }

    return 0;
}

int trace_task_deallocate(struct pt_regs *ctx) {
    u64 task_address = PT_REGS_PARM1(ctx);
    u64 *count = task_pool_count.lookup(&task_address);
    if (count) {
        (*count)--;
    }

    return 0;
}
int trace_task_spawn(struct pt_regs *ctx) {
    u64 task_address = PT_REGS_PARM1(ctx);
    u64 *count = task_stack_count.lookup(&task_address);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        task_stack_count.update(&task_address, &one);
    }

    struct task_info_t ti = {};
    ti.task_address = task_address;
    ti.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ti.comm, sizeof(ti.comm));
    ti.timestamp = bpf_ktime_get_ns();

    events.perf_submit(ctx, &ti, sizeof(ti));

    return 0;
}
"""

bpf = BPF(text=bpf_program)
# bpf.attach_uprobe(name="tbb", sym="_ZN3tbb6detail2r15spawnERNS0_2d14taskERNS2_18task_group_contextE", fn_name="trace_task_spawn")
bpf.attach_uprobe(name="tbb", sym="_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEmRKNS2_14execution_dataE", fn_name="trace_task_allocate")
bpf.attach_uprobe(name="tbb", sym="_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE", fn_name="trace_task_deallocate")
# _ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEmRKNS2_14execution_dataE
# _ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE

# _ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEm
# _ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvm
class TaskInfo(ctypes.Structure):
    _fields_ = [("task_address", ctypes.c_ulonglong),
                ("pid", ctypes.c_uint),
                ("comm", ctypes.c_char * 16),
                ("timestamp", ctypes.c_ulonglong)]
# ...previous code...

def print_event(cpu, data, size):
    ti = ctypes.cast(data, ctypes.POINTER(TaskInfo)).contents
    print(f"[{ti.timestamp}] {ti.comm.decode('utf-8', 'replace')} ({ti.pid}) - Task spawned at 0x{ti.task_address:x}")

bpf["events"].open_perf_buffer(print_event)

print("Tracing Intel TBB task spawns... Ctrl+C to exit")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break


print("\nTask Stack Count:")
for task_address, count in bpf["task_stack_count"].items():
    print(f"0x{task_address.value:x}: {count.value}")

print("\nTask Pool Count:")
for task_address, count in bpf["task_pool_count"].items():
    print(f"0x{task_address.value:x}: {count.value}")


# ... previous code ...

# Get the length of task_stack_count hash
task_stack_count_length = len(bpf["task_stack_count"].items())

# Get the length of task_pool_count hash
task_pool_count_length = len(bpf["task_pool_count"].items())

print(f"task_stack_count length: {task_stack_count_length}")
print(f"task_pool_count length: {task_pool_count_length}")

print("###############################\n")

# ... previous code ...

# Calculate the total number of tasks allocated
total_tasks_allocated = 0
for count in bpf["task_pool_count"].values():
    total_tasks_allocated += count.value

# Calculate the total number of tasks deallocated
total_tasks_deallocated = 0
for count in bpf["task_pool_count"].values():
    total_tasks_deallocated += count.value

print(f"Total tasks allocated: {total_tasks_allocated}")
print(f"Total tasks deallocated: {total_tasks_deallocated}")
