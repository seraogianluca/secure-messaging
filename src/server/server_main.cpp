#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include "include/server.h"
#include "include/socket.h"

#define PORT 8080

using namespace std;

int main(int argc, char* const argv[]) {
    try {
        SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
        while(true) {
            serverSocket.initSet();
            serverSocket.selectActivity();
            if(serverSocket.isMasterSet()) {
                serverSocket.acceptNewConnection();
            } else {
                serverSocket.readMessageOnOtherSockets();
            }
        }
    } catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
    return 0;
}

