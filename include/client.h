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

class Client {
    private:
        string username;
        int sendMessage(string message);
        string convert(unsigned char* value);
        string readMessage();
        bool verifyCertificate();
        string extractClientNonce(string message, size_t clientNonceLen);
        string extractServerNonce(string message, size_t clientNonceLen);

    public:
        Client(); //Constructor
        ~Client(); //Distructor

        int login(string pwd);
        int logout();
        int requestToTalk(string peerUsername);
        int textMessage(string peerUsername, string message);
};