#include <iostream>
#include <vector>
#include "tbb/parallel_for.h"
#include "tbb/blocked_range.h"

double heavy_task(double x) {
    // Simulate a heavy computation
    double result = 0;
    for (int i = 0; i < 10000000; ++i) {
        result += x * i;
    }
    return result;
}

void parallel_task() {
    const int N = 1000;
    std::vector<double> input(N), output(N);
    for (int i = 0; i < N; ++i) {
        input[i] = i;
    }

    tbb::parallel_for(tbb::blocked_range<int>(0, N), [&](const tbb::blocked_range<int>& range) {
        for (int i = range.begin(); i < range.end(); ++i) {
            output[i] = heavy_task(input[i]);
        }
    });

    // Print the result
    for (int i = 0; i < N; ++i) {
        std::cout << output[i] << std::endl;
    }
}

int main() {
    parallel_task();
    parallel_task();
    return 0;
}

