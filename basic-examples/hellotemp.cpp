#include <iostream>
#include <tbb/tbb.h>

void printHello() {
  tbb::task_scheduler_init init; // initialize TBB task scheduler

  // define task that prints "Hello, world!"
  class HelloTask : public tbb::task {
  public:
    tbb::task* execute() override {
      std::cout << "Hello, world!" << std::endl;
      return nullptr;
    }
  };

  // create and run task
  tbb::task::spawn_root_and_wait(*new (tbb::task::allocate_root()) HelloTask);
}

int main() {
  for (int i = 0; i < 3; i++) {
    printHello();
  }
  return 0;
}
