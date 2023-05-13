#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct

# Define the eBPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct tbb_thread_data_t {
    u64 count;
};

BPF_HASH(tbb_thread_data, u64, struct tbb_thread_data_t);

int tbb_thread_pool_enter(struct pt_regs *regs) {
    u64 pid = bpf_get_current_pid_tgid();
    struct tbb_thread_data_t *data = tbb_thread_data.lookup_or_init(&pid, NULL);
    data->count++;
    return 0;
}

int tbb_thread_pool_exit(struct pt_regs *regs) {
    u64 pid = bpf_get_current_pid_tgid();
    struct tbb_thread_data_t *data = tbb_thread_data.lookup_or_init(&pid, NULL);
    data->count--;
    return 0;
}

"""

# Load the eBPF program
b = BPF(text=prog)

# Attach the eBPF program to the TBB thread pool enter and exit functions
b.attach_uprobe(name="/usr/local/lib/libtbb.so", sym="_ZN3tbb6detail2r17observeERNS0_2d123task_scheduler_observerEb", fn_name="tbb_thread_pool_enter")
b.attach_uprobe(name="/usr/local/lib/libtbb.so", sym="_ZN3tbb6detail2r17observeERNS0_2d123task_scheduler_observerEb", fn_name="tbb_thread_pool_exit")
# Define the ctypes struct for the thread data
class TbbThreadData(ct.Structure):
    _fields_ = [("count", ct.c_ulonglong)]

# Get the thread data for each task
tbb_thread_data = b["tbb_thread_data"]
for key, value in tbb_thread_data.items():
    thread_data = ct.cast(value.value, ct.POINTER(TbbThreadData)).contents
    print(f"Task {key} has {thread_data.count} threads in the TBB thread pool.")


# Load the eBPF program
b = BPF(text=prog)

# Attach the eBPF program to the TBB thread pool enter and exit functions
b.attach_uretprobe(name="tbb", sym="_ZN3tbb6detail2r17observeERNS0_2d123task_scheduler_observerEb", fn_name="tbb_thread_pool_enter")
b.attach_uretprobe(name="tbb", sym="_ZN3tbb6detail2r17observeERNS0_2d123task_scheduler_observerEb", fn_name="tbb_thread_pool_exit")

# Define the ctypes struct for the thread data
class TbbThreadData(ct.Structure):
    _fields_ = [("count", ct.c_ulonglong)]

# Get the thread data for each task
tbb_thread_data = b["tbb_thread_data"]
for key, value in tbb_thread_data.items():
    thread_data = ct.cast(value.value, ct.POINTER(TbbThreadData)).contents
    print(f"Task {key.value.pid} has {thread_data.count} threads in the TBB thread pool.")
