#include "include/client.h"

string Client::convert(unsigned char* value) {
    string s;
    for (size_t i = 0; i < sizeof(value); i++){
        s.append(1, static_cast<char>(value[i]));
    }
    return s;
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