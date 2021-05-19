#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include "include/server.h"

#define PORT 8080

using namespace std;

int main(int argc, char* const argv[]) {
    try {
        Server server;
        cout << "Login" << endl;
        server.handleLogin();
    } catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
    return 0;
}

