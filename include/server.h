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
    int sd;
};

class Server {
    private:
        user onlineUsers[MAX_CLIENTS];
        string extractClientNonce(string message);
        string extractServerNonce(string message, size_t serverNonceLen);
    public:
        Server(){};
        ~Server(){};

        void handleLogin();
        void addUser(user user);
        void deleteUser(user user);
        int getOperationCode(unsigned char* message);
        int forwardMessage(string dest, string message);
        int authenticate(string dest);
        int sendOnlineUsers(string dest);
};
