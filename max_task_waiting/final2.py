#!/usr/bin/env python3
from bcc import BPF

# Define the eBPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct alloc_data_t {
    u32 pid;
    u64 ts;
    int cpu;
    int type;  // 0 for allocation, 1 for deallocation
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, u32);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(tbb, tbb__allocate) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);
    return 0;
}

TRACEPOINT_PROBE(tbb, tbb__deallocate) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);

    if (tsp != NULL) {
        struct alloc_data_t data = {};
        data.pid = pid;
        data.ts = bpf_ktime_get_ns() - *tsp;
        data.cpu = bpf_get_smp_processor_id();
        data.type = 1;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(args, &data, sizeof(data));
        start.delete(&pid);
    }

    return 0;
}

BPF_HASH(task_exit, u32);
BPF_HASH(threads, u32, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_futex)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    threads.update(&pid, &ts);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_futex)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = threads.lookup(&pid);

    if (tsp != NULL) {
        u64 elapsed = bpf_ktime_get_ns() - *tsp;
        task_exit.update(&pid, &elapsed);
        threads.delete(&pid);
    }

    return 0;
}
"""

# Load the eBPF program
b = BPF(text=prog)

# Attach tracepoints for TBB allocations
b.attach_tracepoint(tp="tbb:tbb__allocate")
b.attach_tracepoint(tp="tbb:tbb__deallocate")

# Attach tracepoints for futex_wait
b.attach_tracepoint(tp="syscalls:sys_enter_futex")
b.attach_tracepoint(tp="syscalls:sys_exit_futex")

# Define the event handlers
def print_event_alloc(cpu, data, size):
    event = b["events"].event(data)
    operation_type = 'Allocation' if event.type == 0 else 'Deallocation'
    print(f"TBB: PID: {event.pid}, Program: {event.comm}, Operation: {operation_type}, Elapsed Time: {event.ts}, Thread No: {event.cpu}")

def print_event_exit(cpu, data, size):
    event = b["task_exit"].event(data)
    print(f"Futex: Thread {event.pid} exited after {event.elapsed} ns")

def print_event_enter(cpu, data, size):
    event = b["threads"].event(data)
    print(f"Futex: Thread {event.pid} entered futex_wait")

# Set up the event handlers
b["events"].open_perf_buffer(print_event_alloc)
b["task_exit"].open_perf_buffer(print_event_exit)
b["threads"].open_perf_buffer(print_event_enter)

# Poll for the events
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
