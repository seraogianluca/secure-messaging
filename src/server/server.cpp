#include "include/server.h"

void Server::handleLogin() {
    try {
        // Crypto crypto((unsigned char*)"qualcosa"); // Refactor
        // string message = readMessage();
        // cout << "Message Received: " << message << endl;
        // string serverNonce = crypto.generateNonce();
        // cout << "Nonce Generated: " << serverNonce << endl;
        // string clientNonce = extractClientNonce(message);
        // cout << "Client Nonce: " << clientNonce << endl;
        // string helloMessage = "hello" + clientNonce + serverNonce;
        // sendMessage(helloMessage);
        // cout << "Hello Message sent" << endl;
    } catch(const runtime_error& e) {
        string message = "Login Error: " + string(e.what());
        throw runtime_error(message);
    }
}

string Server::extractClientNonce(string message) {
    if (message.length() < 5) throw runtime_error("Uncorrect format of the message received");
    return message.erase(0, 5);
}


int Server::getOperationCode(string message) {
    if(message.length() == 0) {throw runtime_error("Message format not correct");}
    int opCode = message.at(0) - '0';
    if (opCode < 0 || opCode > 4) { throw runtime_error("Operation Code not valid");}
    return opCode;
}
