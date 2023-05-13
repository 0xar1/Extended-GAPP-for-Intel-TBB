#include <iostream>
#include <tbb/tbb.h>

using namespace tbb;

class HelloTask: public task {
public:
    task* execute() {
        std::cout << "Hello, world!\n";
        return NULL;
    }
};

int main() {
    task_scheduler_init init;
    task_group group;

    for (int i = 0; i < 10; i++) {
        group.run(new(allocate_child()) HelloTask());
    }

    group.wait();
    return 0;
}
