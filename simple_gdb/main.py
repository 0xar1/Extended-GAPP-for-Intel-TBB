# Import the necessary modules
import gdb
import tbb

# Get the global TBB task scheduler object
task_scheduler = tbb.task_scheduler_init.__get_task_scheduler()

# Get the number of worker threads in the thread pool
num_threads = task_scheduler.__get_num_threads()

# Get a list of worker threads in the thread pool
worker_threads = task_scheduler.__get_worker_threads()

# Iterate over the worker threads and print their stack information
for i, thread in enumerate(worker_threads):
    print("Thread %d:" % i)
    print("  Stack base address: 0x%x" % thread.stack_base_address())
    print("  Stack size: %d bytes" % thread.stack_size())

# Exit the debugger
gdb.execute("quit")
