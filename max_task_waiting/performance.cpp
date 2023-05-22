#include <iostream>
#include <tbb/tbb.h>

void performAllocation() {
    // Allocate memory using standard malloc
    void* memory = std::malloc(1024);

    // Simulate some work
    tbb::parallel_for(0, 1000, [](int) {
        // Perform some computations
    });

    // Deallocate memory using standard free
    std::free(memory);
}

int main() {
    // Run the allocation task multiple times
    for (int i = 0; i < 10; i++) {
        performAllocation();
    }

    return 0;
}
