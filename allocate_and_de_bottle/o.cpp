#include <iostream>
#include <tbb/tbb.h>
#include <atomic>

std::atomic<size_t> allocated_tasks(0);
std::atomic<size_t> deallocated_tasks(0);

void task_function(size_t i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    std::cout << "Task " << i << " is running..." << std::endl;
    deallocated_tasks.fetch_add(1);
}

int main() {
    size_t num_tasks = 10;

    tbb::task_group task_group;

    for (size_t i = 0; i < num_tasks; ++i) {
        task_group.run([i]() { task_function(i); });
        allocated_tasks.fetch_add(1);
    }

    std::cout << "Allocated tasks: " << allocated_tasks.load() << std::endl;
    std::cout << "Deallocated tasks: " << deallocated_tasks.load() << std::endl;

    task_group.wait();

    std::cout << "All tasks completed." << std::endl;
    std::cout << "Allocated tasks: " << allocated_tasks.load() << std::endl;
    std::cout << "Deallocated tasks: " << deallocated_tasks.load() << std::endl;

    return 0;
}
