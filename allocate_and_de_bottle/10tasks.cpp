#include <tbb/tbb.h>
#include <iostream>
#include <chrono>

void do_work() {
    // simulate some work by having the task sleep
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

int main() {
    tbb::task_group group;

    for (int i = 0; i < 10; ++i) {
        group.run(do_work);
    }

    std::cout << "Waiting for tasks to complete...\n";

    // Wait for all tasks to complete
    group.wait();

    std::cout << "All tasks completed.\n";

    return 0;
}
