#include "include/client.h"

unsigned char* Client::buildMessage(unsigned char *opCode, unsigned char *iv, unsigned char *msg, unsigned int msg_size, unsigned char *tag, unsigned int &size) {
    unsigned int max_size = MAX_MESSAGE_SIZE + IV_SIZE + TAG_SIZE + 1;

    if (msg_size > max_size) {
        throw runtime_error("Maximum message size exceeded");
    }

    unsigned char buffer[MAX_MESSAGE_SIZE];
    size = 0;

    memcpy(buffer, opCode, 1);
    size += 1;
    memcpy(buffer+size, iv, IV_SIZE);
    size += IV_SIZE;
    memcpy(buffer+size, msg, msg_size);
    size += msg_size;
    memcpy(buffer+size, tag, TAG_SIZE);
    size += TAG_SIZE;

    return buffer;
}

bool Client::verifyCertificate() {
    //TODO: implement
    return true;
}

string Client::extractClientNonce(string message, size_t clientNonceLen) {
    if (message.length() < 5 + clientNonceLen) throw runtime_error("Uncorrect format of the message received");
    string clientNonce = message.erase(0, 5); // remove the hello message
    return clientNonce.substr(0, clientNonceLen - 1);
}

string Client::extractServerNonce(string message, size_t clientNonceLen) {
    if (message.length() < 5 + clientNonceLen) throw runtime_error("Uncorrect format of the message received");
    string serverNonce = message.erase(0, 5); // remove the hello message
    return serverNonce.erase(0, clientNonceLen);
}