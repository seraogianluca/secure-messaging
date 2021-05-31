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
        
        //TODO: to check
        unsigned char *greetingMessage = new unsigned char[MAX_MESSAGE_SIZE ];
        socketClient.receiveMessage(socketClient.getMasterFD(), greetingMessage);
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
    unsigned char *nonceClient = NULL;
    unsigned char *nonceClientReceived = NULL;
    unsigned char *helloMessage = NULL;
    unsigned char *receivedMessage = NULL;
    unsigned char *nonceServerReceived = NULL;
    unsigned char *certificateRequestMessage = NULL;
    unsigned char *cert_buff = NULL;
    X509 *cert = NULL;
    unsigned int messageReceivedLen;
    unsigned int start;
    unsigned int cert_len;

    try {
        // Generate nonce
        nonceClient = new unsigned char[NONCE_SIZE];
        crypto.generateNonce(nonceClient);
        cout << "Generated Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceClient, NONCE_SIZE);

         // Build hello message
        helloMessage = new unsigned char[NONCE_SIZE + 6];
        start = 0;
        memcpy(helloMessage, OP_LOGIN, 1);
        start += 1;
        memcpy(helloMessage+start, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonceClient, NONCE_SIZE);
        cout << "Hello Message: " << endl;
        BIO_dump_fp(stdout, (const char*) helloMessage, NONCE_SIZE + 6);
        socketClient.sendMessage(socketClient.getMasterFD(), helloMessage, NONCE_SIZE + 6);

        // Receive server hello
        receivedMessage = new unsigned char[MAX_MESSAGE_SIZE];
        messageReceivedLen = socketClient.receiveMessage(socketClient.getMasterFD(), receivedMessage);
        cout << "Message Received: " << endl;
        BIO_dump_fp(stdout, (const char*) receivedMessage, messageReceivedLen);

        // Check nonce
        if (messageReceivedLen != (5 + 2*NONCE_SIZE)) { 
            throw runtime_error("Uncorrect format of the message received");
        }

        nonceClientReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceClientReceived, receivedMessage+5, NONCE_SIZE);
        cout << "Client Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceClientReceived, NONCE_SIZE);

        if(memcmp(nonceClientReceived, nonceClient, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }

        cout << "Freshness Confirmed" << endl;
        nonceServerReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceServerReceived, receivedMessage+5+NONCE_SIZE, NONCE_SIZE);
        cout << "Server Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceServerReceived, NONCE_SIZE);

        // Send certificate request
        //TODO: check message format
        certificateRequestMessage = new unsigned char[2*NONCE_SIZE];
        start = 0;
        memcpy(certificateRequestMessage, nonceServerReceived, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(certificateRequestMessage+start, nonceClient, NONCE_SIZE);
        cout << "Certificate Request: " << endl;
        BIO_dump_fp(stdout, (const char*)certificateRequestMessage, (2*NONCE_SIZE));
        socketClient.sendMessage(socketClient.getMasterFD(), certificateRequestMessage, (2*NONCE_SIZE));
        
        //VERIFY CERTIFICATE
        cert_buff = new unsigned char[MAX_MESSAGE_SIZE];        
        cert_len = socketClient.receiveMessage(socketClient.getMasterFD(),cert_buff);
        crypto.deserializeCertificate(cert_len, cert_buff,cert);
        if(!crypto.verifyCertificate(cert))
            throw runtime_error("Pay attention, server is not authenticated.");
        cout << "Server authenticated." << endl;
    } catch (const exception &e) {
        delete[] nonceClient;
        delete[] helloMessage;
        delete[] receivedMessage;
        delete[] nonceClientReceived;
        delete[] nonceServerReceived;
        delete[] certificateRequestMessage;
        delete[] cert_buff;
        throw runtime_error(e.what());
    }

    delete[] nonceClient;
    delete[] helloMessage;
    delete[] receivedMessage;
    delete[] nonceClientReceived;
    delete[] nonceServerReceived;
    delete[] certificateRequestMessage;
    delete[] cert_buff;
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