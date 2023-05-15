from bcc import BPF

# BPF program
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

# load BPF program
b = BPF(text=prog)

# attach kprobe to TBB task spawn function
spawn_mangled_name = "_ZGVZN3tbb6detail2r15spawnERNS0_2d14taskERNS2_18task_group_contextE"
b.attach_kprobe(event=spawn_mangled_name, fn_name="count_tasks")

# open output file
with open('output.txt', 'w') as f:
    # define print function
    def print_event(cpu, data, size):
        event = b["task_info_events"].event(data)
        output = "PID: %d, Task Pointer: %d\n" % (event.pid, event.task_ptr)
        print(output)
        f.write(output)

    # set up perf buffer to print task info events
    b["task_info_events"].open_perf_buffer(print_event)

    while 1:
        b.perf_buffer_poll()
