#include <iostream>
#include <string>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

using namespace std;

class Exchange {
    private:

        struct sockaddr_in address;
        int master_fd;
        int client_socket[30];
        void createSocket();
        void serverBind();
        void listen();

    public:
        Exchange();
        ~Exchange();
        void sendMessage(string message);
        string receiveMessage(string message);
        void buildServerSocket();
        void buildClientSocket();
};

Exchange::Exchange() {
}

Exchange::~Exchange() {
}
