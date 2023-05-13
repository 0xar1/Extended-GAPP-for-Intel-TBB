#include <iostream>
#include <tbb/tbb.h>
#include <atomic>

const size_t num_tasks = 100;

std::atomic<size_t> allocated_tasks(0);
std::atomic<size_t> deallocated_tasks(0);

void task_function(size_t i) {
    std::cout << "Task " << i << " is running..." << std::endl;
    deallocated_tasks.fetch_add(1);
}

int main() {
    tbb::task_group task_group;
    size_t i = 0;

    while (deallocated_tasks < num_tasks) {
        if (allocated_tasks - deallocated_tasks.load() < 5) {
            if (i < num_tasks) {
                task_group.run([i]() { task_function(i); });
                allocated_tasks.fetch_add(1);
                i++;
            }
        } else {
            std::this_thread::yield();
        }
    }

    task_group.wait();
    std::cout << "All tasks completed." << std::endl;

    return 0;
}

