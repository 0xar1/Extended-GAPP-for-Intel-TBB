#include <iostream>
#include <vector>
#include <tbb/tbb.h>

void square_elements(std::vector<int>& vec) {
    tbb::parallel_for(tbb::blocked_range<size_t>(0, vec.size()),
        [&](const tbb::blocked_range<size_t>& r) {
            for (size_t i = r.begin(); i != r.end(); ++i) {
                vec[i] = vec[i] * vec[i];
            }
        }
    );
}

int main() {
    std::vector<int> vec(100000);

    for (size_t i = 0; i < vec.size(); ++i) {
        vec[i] = i;
    }

    square_elements(vec);

    for (size_t i = 0; i < 10; ++i) {
        std::cout << "vec[" << i << "] = " << vec[i] << std::endl;
    }

    return 0;
}
