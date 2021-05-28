#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include "include/client.h"
#include "include/socket.h"

int showMenu();

string readFromStdout(string message);
void authentication();

int main(int argc, char* const argv[]) {
    try {

        string password = readFromStdout("Insert password: ");

        Crypto c((unsigned char*)"1234567890123456");
        unsigned char msg[] = "Test message";
        unsigned char *ciphertext;
        unsigned char *tag;
        unsigned char *iv;
        unsigned char *dec_msg; 
        int ciphertext_len;
        int plaintext_len = sizeof(msg);
        SocketClient socketClient = SocketClient(SOCK_STREAM);
        Client client = Client();
        socketClient.makeConnection();
        // string greetingMessage = socketClient.receiveMessage(socketClient.getMasterFD());
        // cout << "Connection confirmed: " << greetingMessage  << endl;
        while(true) {
            int value = showMenu();
            if(value == 1) {
                ciphertext = (unsigned char*)malloc(plaintext_len+TAG_SIZE);
                tag = (unsigned char*)malloc(TAG_SIZE);
                ciphertext_len = c.encryptMessage(msg, 
                                                plaintext_len, 
                                                ciphertext, 
                                                tag);
                cout << "Ciphertext: " <<ciphertext_len<<endl;
                BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
                cout << "Tag:" << endl;
                BIO_dump_fp(stdout, (const char*)tag, TAG_SIZE);
                unsigned char* msg = (unsigned char*)malloc(1+ciphertext_len);
                memcpy(msg, "1", sizeof(int));
                memcpy(msg,ciphertext,ciphertext_len);
                socketClient.sendMessage(msg, socketClient.getMasterFD());
                unsigned char* message = socketClient.receiveMessage(socketClient.getMasterFD());
                cout << "Message Received: " << message << endl;
            } else if(value == 2) {

            } else {
                cout << "Exit from the application." << endl;
                return 0;
            }
        }
    } catch(const exception& e) {
        cerr << e.what() << '\n';
    }
    return 0;
}

int showMenu() {
    cout << endl;
    cout << "1. Send a message" << endl;
    cout << "0. Exit" << endl;
    cout << "--> ";
    size_t value;
    cin >> value;
    return value;
}

string readFromStdout(string message) {
    cout << message << "\n --> ";
    string value;
    getline(cin, value);
    while (value.length() == 0) {
        cout << "Insert at least a character." << endl;
        cout << message << "\n --> ";
        getline(cin, value);
    }
    return value;
}

void authentication(Crypto crypto, SocketClient s, Client c) {
    try {
        string nonce_client = crypto.generateNonce();
        string helloMessage = "hello" + nonce_client;
        // s.sendMessage(helloMessage.c_str(), s.getMasterFD());

        // unsigned char* receivedMessage =  s.receiveMessage(s.getMasterFD());
        // string nonce_received = c.extractClientNonce(receivedMessage, nonce_client.length());
        // string nonce_server = c.extractServerNonce(receivedMessage, nonce_client.length());
        // if(nonce_client.compare(nonce_received) != 0) {
        //     throw runtime_error("Login Error: The freshness of the message is not confirmed");
        // }
        // cout << "Freshness Confirmed" << endl;
        // string requestCertificateMessage = (char)OP_CERTIFICATE_REQUEST + nonce_server + nonce_client;
        // s.sendMessage(requestCertificateMessage, s.getMasterFD());

        // string certificate = s.receiveMessage(s.getMasterFD());
        // bool verification = c.verifyCertificate();
    } catch(const std::exception& e) {
        throw runtime_error(e.what() + '\n');
    }
}