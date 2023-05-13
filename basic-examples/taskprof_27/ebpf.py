from bcc import BPF, PerfBuffer
import time

# Define the eBPF program
ebpf_program = """
#include <tbb/task.h>

BPF_PERF_OUTPUT(events);

int trace_tbb_task_execute(struct pt_regs *ctx, void *task) {
    u64 timestamp = bpf_ktime_get_ns();
    u32 thread_id = bpf_get_current_pid_tgid() >> 32;
    u64 task_runtime_ns = bpf_ktime_get_ns() - ((tbb::task*)task)->my_execution_time();
    u32 num_subtasks = ((tbb::task*)task)->num_subtasks();
    events.perf_submit(ctx, &timestamp, sizeof(timestamp));
    events.perf_submit(ctx, &thread_id, sizeof(thread_id));
    events.perf_submit(ctx, &task_runtime_ns, sizeof(task_runtime_ns));
    events.perf_submit(ctx, &num_subtasks, sizeof(num_subtasks));
    return 0;
}
"""

# Load and attach the eBPF program
b = BPF(text=ebpf_program)
b.attach_kprobe(event="tbb::task::execute", fn_name="trace_tbb_task_execute")

# Define the PerfBuffer for capturing events
perf_buffer = PerfBuffer(b.get_table("events"), page_cnt=64)

# Start capturing events
perf_buffer.open()
time.sleep(5)
perf_buffer.close()

# Parse and display the captured data
for event in b.get_table("events").__iter__():
    timestamp = event.value
    thread_id = event.value
    task_runtime_ns = event.value
    num_subtasks = event.value
    print(f"Timestamp: {timestamp}, Thread ID: {thread_id}, Task Runtime (ns): {task_runtime_ns}, # of Subtasks: {num_subtasks}")
