#!/usr/bin/env python3

from bcc import BPF, PerfType, PerfHWConfig

bpf_text = """
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <uapi/linux/perf_event.h>

struct data_t {
    u32 pid;
    u32 tid;
    u64 core_id;
    char mystring[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_entry(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    data.core_id = bpf_get_smp_processor_id();
    bpf_get_current_comm(&data.mystring, sizeof(data.mystring));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_uprobe(name="./out", sym="_ZZ13parallel_taskvENKUlRKN3tbb6detail2d113blocked_rangeIiEEE_clES5_", fn_name="trace_entry")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("PID: %d, TID: %d, Core ID: %d, Process Name: %s" % (event.pid, event.tid, event.core_id,event.mystring.decode()))

b["events"].open_perf_buffer(print_event)

print("Tracing... Hit Ctrl-C to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

