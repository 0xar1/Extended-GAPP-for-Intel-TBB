#!/usr/bin/env python3
from bcc import BPF
import ctypes

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct task_info_t {
    u64 id;
    u64 start_ns;
    u64 end_ns;
};

BPF_HASH(task_map, u64, struct task_info_t);

int alloc_trace(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct task_info_t task = {};
    task.id = id;
    task.start_ns = bpf_ktime_get_ns();
    task_map.update(&id, &task);
    return 0;
}

int dealloc_trace(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct task_info_t *task = task_map.lookup(&id);
    if (task) {
        task->end_ns = bpf_ktime_get_ns();
    }
    return 0;
}
"""

bpf = BPF(text=BPF_PROGRAM)

# Replace these with the correct function names or symbols
alloc_symbol = "_ZN3tbb6detail2r18allocateERPNS0_2d117small_object_poolEm"
dealloc_symbol = "_ZN3tbb6detail2r110deallocateERNS0_2d117small_object_poolEPvmRKNS2_14execution_dataE"

bpf.attach_uprobe(name="tbb", sym=alloc_symbol, fn_name="alloc_trace")
bpf.attach_uprobe(name="tbb", sym=dealloc_symbol, fn_name="dealloc_trace")

# Define a C-compatible structure for task data
class TaskInfo(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_ulonglong),
        ("start_ns", ctypes.c_ulonglong),
        ("end_ns", ctypes.c_ulonglong),
    ]
    
filedata = open('task_out.txt','w')

print("Tracing Intel TBB tasks... Press Ctrl+C to exit.")

try:
    while True:
        for k, v in bpf["task_map"].items():
            task_info = ctypes.cast(ctypes.pointer(v), ctypes.POINTER(TaskInfo)).contents
            print(f"Task ID: {task_info.id}, Start: {task_info.start_ns}, End: {task_info.end_ns}")
            task_time = task_info.end_ns - task_info.start_ns
            # print("*****************************************")
            # print("\t Time for task completion: "+ str(task_time) +"ns \n")
            # print("*****************************************")
            printer = "Time for task" + str({task_info.id}) + ":" + str(task_time) + "\n"
            filedata.write(printer)
except KeyboardInterrupt:
    print("Tracing stopped.")
    print(filedata.read())
