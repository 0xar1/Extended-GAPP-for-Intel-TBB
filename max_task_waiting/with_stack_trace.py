#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct

# Define the BPF program
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    int cpu;
    int type;  // 0 for allocation, 1 for deallocation
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

# Attach probes
b.attach_uprobe(name="tbb", sym=alloc_symbol1, fn_name="trace_alloc_start")
b.attach_uretprobe(name="tbb", sym=alloc_symbol1, fn_name="trace_alloc_end")

b.attach_uprobe(name="tbb", sym=alloc_symbol2, fn_name="trace_alloc_start")
b.attach_uretprobe(name="tbb", sym=alloc_symbol2, fn_name="trace_alloc_end")

b.attach_uprobe(name="tbb", sym=dealloc_symbol1, fn_name="trace_dealloc_start")
b.attach_uretprobe(name="tbb", sym=dealloc_symbol1, fn_name="trace_dealloc_end")

b.attach_uprobe(name="tbb", sym=dealloc_symbol2, fn_name="trace_dealloc_start")
b.attach_uretprobe(name="tbb", sym=dealloc_symbol2, fn_name="trace_dealloc_end")


# Define event handler
def print_event(cpu, data, size):
    event = b["events"].event(data)
    operation_type = 'Allocation' if event.type == 0 else 'Deallocation'
    print(f"PID: {event.pid}, Program: {event.comm.decode('utf-8', 'ignore')}, Operation: {operation_type}, Elapsed Time: {event.ts}, Thread No: {event.cpu}")

    stack_trace = list(b["stack_traces"].walk(event.stack_id))
    for addr in stack_trace:
        print("  %s" % b.ksym(addr))

# Set up the event
b["events"].open_perf_buffer(print_event)

# Poll for the event
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Ending tracing.")
        exit()
