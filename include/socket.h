#include <iostream>
#include <string>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close
#include <string.h>
#include "include/symbols.h"
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>

using namespace std;

class SocketClient {
    private:

    protected:
        int socketType;
        struct sockaddr_in address;
        int master_fd;
        int port;
        void createSocket();

    public:
        SocketClient(int socketType);
        ~SocketClient();
        void sendMessage(string message);
        string receiveMessage();
        void makeConnection();
};




class SocketServer: private SocketClient {
    
    private:
        int client_socket[MAX_CLIENTS];
        fd_set readfds;
        int max_sd;
        int sd;
        int activity;
        int addrlen;
        int port;
        char buffer[1025];
        void serverBind();
        void listenForConnections();
        
    public:
        SocketServer(int socketType);
        ~SocketServer();
        void initSet();
        void selectActivity();
        bool isMasterSet();
        void acceptNewConnection();
        void readMessageOnOtherSockets();
};

