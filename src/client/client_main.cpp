#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include "include/client.h"
#include "include/socket.h"

//TODO: serve costruttore con parametri di default per fare solo dichiarazione
Crypto crypto = Crypto((unsigned char *)"1234567890123456");
SocketClient socketClient = SocketClient(SOCK_STREAM);
Client client = Client();

int showMenu();
string readFromStdout(string message);
void authentication();
void keyEstablishment();
void sendMessage(unsigned char *header, unsigned int head_len, unsigned char *msg, unsigned int pln_len);

int main(int argc, char *const argv[]) {
    try {
        string password = readFromStdout("Insert password: ");
        socketClient.makeConnection();
        
        unsigned int greetingMessageLen;
        //TODO: to check
        unsigned char *greetingMessage = new unsigned char[256];
        greetingMessageLen = socketClient.receiveMessage(socketClient.getMasterFD(), greetingMessage);
        cout << "Connection confirmed: " << greetingMessage << endl;
        delete[] greetingMessage;

        while (true) {
            int value = showMenu();
            string input;

            switch(value) {
                case 1:
                    keyEstablishment();
                    break;
                case 2:
                    break;
                case 3:
                    cout << "> ";
                    getline(cin, input);
                    sendMessage(OP_MESSAGE, 1, (unsigned char*)input.c_str(), input.length() + 1);
                    cout << "Message sent." << endl;
                    break;
                case 0:
                    cout << "Bye." << endl;
                    return 0;

                default:
                    cout << "Insert a valid command." << endl;
            }
        }
    }
    catch (const exception &e) {
        cerr << e.what() << endl;
    }

    return 0;
}

int showMenu() {
    cout << endl;
    cout << "3. Send a message" << endl;
    cout << "0. Exit" << endl;
    cout << "--> ";
    size_t value;
    cin >> value;
    cin.ignore();
    return value;
}

string readFromStdout(string message) {
    cout << message << "\n --> ";
    string value;
    getline(cin, value);
    while (value.length() == 0)
    {
        cout << "Insert at least a character." << endl;
        cout << message << "\n --> ";
        getline(cin, value);
    }
    return value;
}

void authentication(Crypto crypto, SocketClient s, Client c) {
    try
    {
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
    }
    catch (const std::exception &e)
    {
        throw runtime_error(e.what());
    }
}

void sendMessage(unsigned char *header, unsigned int head_len, unsigned char *msg, unsigned int pln_len) {
    unsigned char *ciphertext = NULL;
    unsigned char *tag = NULL;
    unsigned char *buffer = NULL;
    unsigned int ciphr_len;
    unsigned int msg_len = 0;
    int start = 0;

    try {
        ciphertext = new unsigned char[pln_len + TAG_SIZE];
        tag = new unsigned char[TAG_SIZE];
        ciphr_len = crypto.encryptMessage(msg,pln_len,ciphertext,tag);

        msg_len = head_len + IV_SIZE + ciphr_len + TAG_SIZE;
        if (msg_len > MAX_MESSAGE_SIZE) {
            throw runtime_error("Maximum message size exceeded");
        }

        buffer = new unsigned char[msg_len];
        memcpy(buffer, header, head_len);
        start += 1;
        memcpy(buffer+start, crypto.getIV(), IV_SIZE);
        start += IV_SIZE;
        memcpy(buffer+start, ciphertext, ciphr_len);
        start += ciphr_len;
        memcpy(buffer+start, tag, TAG_SIZE);

        socketClient.sendMessage(socketClient.getMasterFD(), buffer, msg_len);
    } catch(const exception& e) {
        delete[] ciphertext;
        delete[] tag;
        delete[] buffer;
        throw runtime_error(e.what());
    }
    
    delete[] ciphertext;
    delete[] tag;
    delete[] buffer;
}

void keyEstablishment() {
    unsigned char *buffer = NULL;
    unsigned char *secret = NULL;
    unsigned int key_len;
    EVP_PKEY *prv_key_a = NULL;
    EVP_PKEY *pub_key_b = NULL;

    try {
        // TODO: check where put the login request
        socketClient.sendMessage(socketClient.getMasterFD(), OP_LOGIN, 1);
        
        // Generate public key
        crypto.keyGeneration(prv_key_a);

        // Send public key to peer
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        key_len = crypto.serializePublicKey(prv_key_a, buffer);
        socketClient.sendMessage(socketClient.getMasterFD(), buffer, key_len);

        // Receive peer's public key
        key_len = socketClient.receiveMessage(socketClient.getMasterFD(), buffer);
        crypto.deserializePublicKey(buffer, key_len, pub_key_b);

        // Secret derivation
        secret = new unsigned char[DIGEST_LEN];
        crypto.secretDerivation(prv_key_a, pub_key_b, secret);
        crypto.setSessionKey(secret);
    } catch(const exception& e) {
        delete[] buffer;
        delete[] secret;
        throw runtime_error(e.what());
    }

    delete[] buffer;
    delete[] secret;
}