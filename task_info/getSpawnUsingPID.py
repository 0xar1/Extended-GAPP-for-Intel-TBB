from bcc import BPF
import subprocess

prog = """
#include <uapi/linux/ptrace.h>

struct task_info_t {
    u64 pid;
    u64 task_ptr;
};

BPF_HASH(task_count, u64, u64);
BPF_PERF_OUTPUT(task_info_events);

int count_tasks(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 zero = 0, *val;

    val = task_count.lookup_or_init(&pid, &zero);
    (*val)++;

    struct task_info_t task_info = {};
    task_info.pid = pid;
    task_info.task_ptr = PT_REGS_PARM1(ctx);
    task_info_events.perf_submit(ctx, &task_info, sizeof(task_info));

    return 0;
}
"""

b = BPF(text=prog)

# Start your application and get its pid

# Attach uprobe to TBB task spawn function
# Note: replace /usr/local/lib/libtbb.so with the actual path to the library
b.attach_uprobe(name="tbb", sym="_ZN3tbb6detail2r15spawnERNS0_2d14taskERNS2_18task_group_contextE", fn_name="count_tasks")

with open('output.txt', 'w') as f:
    def print_event(cpu, data, size):
        event = b["task_info_events"].event(data)
        output = "PID: %d, Task Pointer: %d\n" % (event.pid, event.task_ptr)
        print(output)
        f.write(output)

    b["task_info_events"].open_perf_buffer(print_event)

    while 1:
        b.perf_buffer_poll()
