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

bool isNonceEquivalent(unsigned char* clientNonceReceived, unsigned char* clientNonce, unsigned int clientNonceLen);

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

            switch(value) {
                case 1:
                    keyEstablishment();
                    break;
                case 2:
                    cout << "\n-------Authentication-------" << endl;
                    authentication();
                    cout << "-----------------------------" << endl << endl;
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
    cout << "2. Authentication" << endl;
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

void authentication() {
    unsigned int nonceClientLen;
    unsigned char* nonceClient;
    unsigned char* nonceClientReceived;
    unsigned char* helloMessage;
    unsigned int helloMessageLen;
    unsigned char* receivedMessage;
    unsigned int messageReceivedLen;
    unsigned char* nonceServerReceived;
    unsigned int nonceServerReceivedLen;
    unsigned int certificateRequestLen;
    unsigned char* certificateRequestMessage;
    try {
        nonceClientLen = 16;
        helloMessageLen = nonceClientLen + 6;
        nonceClient = new unsigned char[nonceClientLen];
        crypto.generateNonce(nonceClient, nonceClientLen);
        cout << "Generated Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceClient, nonceClientLen);

        helloMessage = new unsigned char[nonceClientLen + 6];
        memcpy(helloMessage, OP_LOGIN, 1);
        memcpy(&helloMessage[1], (unsigned char*)"hello", 6);
        memcpy(&helloMessage[6], nonceClient, helloMessageLen);
        
        cout << "Hello Message: " << endl;
        BIO_dump_fp(stdout, (const char*) helloMessage, helloMessageLen);

        socketClient.sendMessage(socketClient.getMasterFD(), helloMessage, helloMessageLen);

        receivedMessage = socketClient.receiveMessage(socketClient.getMasterFD(), messageReceivedLen); //REFACTOR

        cout << "Message Received: " << endl;
        BIO_dump_fp(stdout, (const char*) receivedMessage, messageReceivedLen);

        nonceClientReceived = new unsigned char[nonceClientLen];
        if (messageReceivedLen < 5 + nonceClientLen) { throw runtime_error("Uncorrect format of the message received");}
        memcpy(nonceClientReceived, &receivedMessage[5], 5 + nonceClientLen);

        cout << "Client Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceClientReceived, nonceClientLen);

        if(!isNonceEquivalent(nonceClientReceived, nonceClient, nonceClientLen)) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }
        cout << "Freshness Confirmed" << endl;

        nonceServerReceivedLen = messageReceivedLen - nonceClientLen - 5;
        nonceServerReceived = new unsigned char[nonceServerReceivedLen];
        memcpy(nonceServerReceived, &receivedMessage[5 + nonceClientLen], messageReceivedLen); // Estract the server nonce
        
        cout << "Server Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceServerReceived, nonceServerReceivedLen);

        certificateRequestLen = 1 + nonceServerReceivedLen + nonceClientLen;
        certificateRequestMessage = new unsigned char[certificateRequestLen];
        memcpy(certificateRequestMessage, OP_CERTIFICATE_REQUEST, 1);
        memcpy(&certificateRequestMessage[1], nonceServerReceived, nonceServerReceivedLen);
        memcpy(&certificateRequestMessage[nonceServerReceivedLen + 1], nonceClient, certificateRequestLen);

        cout << "Certificate Request: " << endl;
        BIO_dump_fp(stdout, (const char*) certificateRequestMessage, certificateRequestLen);
        socketClient.sendMessage(socketClient.getMasterFD(), certificateRequestMessage, certificateRequestLen);

        // string certificate = s.receiveMessage(s.getMasterFD());
        // bool verification = c.verifyCertificate();
    } catch (const std::exception &e) {
        //FARE LE DELETE
        delete[] nonceClient;
        delete[] helloMessage;
        delete[] receivedMessage;
        delete[] nonceClientReceived;
        delete[] nonceServerReceived;
        delete[] certificateRequestMessage;
        throw runtime_error(e.what());
    }
}

bool isNonceEquivalent(unsigned char* clientNonceReceived, unsigned char* clientNonce, unsigned int clientNonceLen) {
    int ret = memcmp(clientNonceReceived, clientNonce, clientNonceLen);
    return ret == 0;
}

void sendMessage(unsigned char *header, unsigned int head_len, unsigned char *msg, unsigned int pln_len) {
    unsigned char *ciphertext;
    unsigned char *tag;
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