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
void sendMessage(unsigned char *opCode, unsigned char *msg, unsigned int pln_len);

int main(int argc, char *const argv[]) {
    try {
        string password = readFromStdout("Insert password: ");
        socketClient.makeConnection();
        unsigned int greetingMessageLen;
        unsigned char *greetingMessage = socketClient.receiveMessage(socketClient.getMasterFD(), greetingMessageLen);
        cout << "Connection confirmed: " << greetingMessage << endl;
        while (true) {
            int value = showMenu();
            string input;
            unsigned int inputSize;

            switch(value) {
                case 1:
                    keyEstablishment();
                    break;
                case 2:
                    break;
                case 3:
                    cout << "> ";
                    getline(cin, input);
                    inputSize = input.length() + 1;
                    sendMessage(OP_MESSAGE, (unsigned char*)input.c_str(), inputSize);
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
        cerr << e.what() << '\n';
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

void sendMessage(unsigned char *opCode, unsigned char *msg, unsigned int pln_len) {
    unsigned char *ciphertext;
    unsigned char *tag;
    unsigned int ciphr_len;
    unsigned int msg_len = 0;
    unsigned char *buffer;
    ciphertext = (unsigned char *)malloc(pln_len + TAG_SIZE);
    if (ciphertext == NULL) {
        throw "An error occurred during ciphertext allocation.";
    }
    tag = (unsigned char *)malloc(TAG_SIZE);
    if (tag == NULL) {
        free(ciphertext);
        throw "An error occurred during tag allocation.";
    }

    ciphr_len = crypto.encryptMessage(msg,pln_len,ciphertext,tag);
    
    buffer = client.buildMessage(opCode, crypto.getIV(), ciphertext, ciphr_len, tag, msg_len);
    socketClient.sendMessage(socketClient.getMasterFD(), buffer, msg_len);
    
    free(ciphertext);
    free(tag);
}

void keyEstablishment() {
    unsigned char* buffer = (unsigned char*) malloc(256);
    //Check on the malloc and free
    unsigned char* bufferRecvd;
    unsigned char* secret;
    unsigned char* hashedSecret;
    unsigned char* loginMsg = OP_LOGIN;
    size_t secretlen;
    unsigned int buffer_rcvd_len;
    EVP_PKEY* params;
    EVP_PKEY* prv_key_a;
    EVP_PKEY* pub_key_b;

    socketClient.sendMessage(socketClient.getMasterFD(), loginMsg, 1);
    params = crypto.buildParameters();
    prv_key_a = crypto.keyGeneration(params);
    //send g^a mod p
    unsigned int pubKeyLen = crypto.serializePublicKey(prv_key_a, buffer);
    socketClient.sendMessage(socketClient.getMasterFD(), buffer, pubKeyLen);
    cout << "pub_key_a: " << endl;
    BIO_dump_fp(stdout, (const char*)buffer, pubKeyLen);
    //receive g^b mod p
    bufferRecvd = socketClient.receiveMessage(socketClient.getMasterFD(), buffer_rcvd_len);
    pub_key_b = crypto.deserializePublicKey(bufferRecvd, buffer_rcvd_len);
    cout << "pub_key_b: " << endl;
    BIO_dump_fp(stdout, (const char*)bufferRecvd, buffer_rcvd_len);

    secret = crypto.secretDerivation(prv_key_a, pub_key_b, secretlen);
    hashedSecret = crypto.computeHash(secret, secretlen); //128 bit digest
    cout << "Secret: " << endl;
    BIO_dump_fp(stdout, (const char*)secret, secretlen);
    cout << "Hash: " << endl;
    BIO_dump_fp(stdout, (const char*)hashedSecret, DIGEST_LEN);

    crypto.setSessionKey(hashedSecret, DIGEST_LEN);
}