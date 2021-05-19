#include <vector>
#include <iostream>
#include <string>
#include <stdexcept>
#include "symbols.h"
#include "include/crypto.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include "include/symbols.h"

using namespace std;

struct user {
    string username;
    int port;
};

class Server {
    private:
        vector<user> onlineUsers;
        void sendMessage(string message);
        string readMessage();
        string extractClientNonce(string message, size_t serverNonceLen);
        string extractServerNonce(string message, size_t serverNonceLen);
    public:
        Server();
        ~Server();

        int forwardMessage(string dest, string message);
        int authenticate(string dest);
        int sendOnlineUsers(string dest);
};
