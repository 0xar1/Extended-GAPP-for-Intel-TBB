#include <iostream>
#include <tbb/tbb.h>

using namespace std;
using namespace tbb;

void printHello() {
    cout << "Hello World!" << endl;
}

class HelloWorld {
    const char* id;
public:
    HelloWorld(const char* s) : id(s) {}
    void operator()() const {
        printHello();
        cout << "Hello from task " << id << endl;
    }
};

int main() {
    task_group tg;
    tg.run(HelloWorld("1"));
    tg.run(HelloWorld("2"));
    tg.run(HelloWorld("1"));
    tg.run(HelloWorld("2"));
    tg.run(HelloWorld("1"));
    tg.run(HelloWorld("2"));
    tg.run(HelloWorld("1"));
    tg.run(HelloWorld("2"));
    tg.run(HelloWorld("1"));
    tg.run(HelloWorld("2"));
    tg.run(HelloWorld("1"));
    tg.run(HelloWorld("2"));
    
    tg.wait();
    return 0;
}

