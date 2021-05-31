#include "include/client.h"

void Client::buildMessage(unsigned char *header, unsigned int header_len, unsigned char *iv, unsigned char *msg, unsigned int msg_size, unsigned char *tag, unsigned char *buffer) {

    if (msg_size > MAX_MESSAGE_SIZE) {
        throw runtime_error("Maximum message size exceeded");
    }

    int start = 0;
    memcpy(buffer, header, header_len);
    start += 1;
    memcpy(buffer+start, iv, IV_SIZE);
    start += IV_SIZE;
    memcpy(buffer+start, msg, msg_size);
    start += msg_size;
    memcpy(buffer+start, tag, TAG_SIZE);
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