#include <iostream>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>
#include "include/symbols.h"

using namespace std;

class SocketClient {
    private:

    protected:
        int socketType;
        struct sockaddr_in address;
        int master_fd;
        int port;

    public:
        SocketClient(int socketType);
        ~SocketClient();
        int getMasterFD();
        void makeConnection();
        bool wait(int socket);
        void setBlockingSocket(int socket, bool is_blocking);
        void sendMessage(int sd, unsigned char* message, unsigned int message_len);
        int receiveMessage(int sd, unsigned char *buffer);
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

