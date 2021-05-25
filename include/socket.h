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
        int getMasterFD();
        void sendMessage(string message, int sd);
        string receiveMessage(int sd);
        void makeConnection();
};




class SocketServer: public SocketClient {
    
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
        int getClient(unsigned int i);
        void initSet();
        void selectActivity();
        bool isFDSet(int fd);
        void acceptNewConnection();
        void readMessageOnOtherSockets();
        void disconnectHost(int sd, unsigned int i);
};

