#include <iostream>
#include <string>
#include <stdexcept>
#include "symbols.h"
#include "include/crypto.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <exception>
#include "include/symbols.h"

using namespace std;

class Client {
    private:
        string username;

    public:
        Client() {}; //Constructor
        ~Client() {}; //Distructor

        unsigned char* buildMessage(unsigned char *opCode, unsigned char *iv, unsigned char *msg, unsigned int msg_size, unsigned char *tag, unsigned int &size);

        bool verifyCertificate();
        string extractClientNonce(string message, size_t clientNonceLen);
        string extractServerNonce(string message, size_t clientNonceLen);
};