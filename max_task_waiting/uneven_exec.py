#!/usr/bin/env python3
from bcc import BPF
from time import sleep
import ctypes as ct
from collections import defaultdict
from statistics import mean, stdev

MAX_STACK_DEPTH = 64

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_STACK_DEPTH 64

struct data_t {
    u32 pid;
    u64 ts;
    int cpu;
    int type;
    int stack_id;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);

int trace_alloc_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);
    return 0;
}

int trace_alloc_end(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);

    if (tsp != NULL) {
        struct data_t data = {};
        data.pid = pid;
        data.ts = bpf_ktime_get_ns() - *tsp;
        data.cpu = bpf_get_smp_processor_id();
        data.type = 0;
        data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));
        start.delete(&pid);
    }
    
    return 0;
}

int trace_dealloc_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);
    return 0;
}

int trace_dealloc_end(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);

    if (tsp != NULL) {
        struct data_t data = {};
        data.pid = pid;
        data.ts = bpf_ktime_get_ns() - *tsp;
        data.cpu = bpf_get_smp_processor_id();
        data.type = 1;
        data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));
        start.delete(&pid);
    }
    
    return 0;
}

"""

b = BPF(text=bpf_source)

alloc_symbol1 = "_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEm"
alloc_symbol2 = "_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEmRKNS2_14execution_dataE"
dealloc_symbol1 = "_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvm"
dealloc_symbol2 = "_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE"

b.attach_uprobe(name="tbb", sym=alloc_symbol1, fn_name="trace_alloc_start")
b.attach_uretprobe(name="tbb", sym=alloc_symbol1, fn_name="trace_alloc_end")

b.attach_uprobe(name="tbb", sym=alloc_symbol2, fn_name="trace_alloc_start")
b.attach_uretprobe(name="tbb", sym=alloc_symbol2, fn_name="trace_alloc_end")

b.attach_uprobe(name="tbb", sym=dealloc_symbol1, fn_name="trace_dealloc_start")
b.attach_uretprobe(name="tbb", sym=dealloc_symbol1, fn_name="trace_dealloc_end")

b.attach_uprobe(name="tbb", sym=dealloc_symbol2, fn_name="trace_dealloc_start")
b.attach_uretprobe(name="tbb", sym=dealloc_symbol2, fn_name="trace_dealloc_end")

# Dictionary to store execution times of each task for each PID
# A task is identified by a unique combination of PID and stack trace
execution_times_tasks = defaultdict(list)

# Define event handler
def print_event(cpu, data, size):
    event = b["events"].event(data)
    operation_type = 'Allocation' if event.type == 0 else 'Deallocation'
    
    # Get the stack trace for the event
    stack_trace = []
    if event.stack_id >= 0 and event.stack_id < MAX_STACK_DEPTH:
        stack_trace = list(b["stack_traces"].walk(event.stack_id))

    # Use the combination of PID and stack trace as the key for the task
    task_key = (event.pid, tuple(stack_trace))
    
    # Aggregate elapsed times
    execution_times_tasks[task_key].append(event.ts)

# Set up the event
b["events"].open_perf_buffer(print_event)

# Poll for the event
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Ending tracing.")
        break  # break the loop to allow printing of aggregated results

# Print aggregated results
print("Aggregated elapsed times for tasks:")
for task_key, elapsed_times in execution_times_tasks.items():
    print(f"PID: {task_key[0]}, Stack trace: {task_key[1]}, Elapsed times: {elapsed_times}")

# Analyze if there is potential uneven execution
print("\nTasks with potential uneven execution:")
for task_key, elapsed_times in execution_times_tasks.items():
    average_time = mean(elapsed_times)
    deviation = stdev(elapsed_times) if len(elapsed_times) > 1 else 0
    if deviation > 0.1 * average_time:  # assuming a task has uneven execution if standard deviation > 10% of average
        print(f"PID: {task_key[0]}, Stack trace: {task_key[1]}, Average time: {average_time}, Standard deviation: {deviation}")

