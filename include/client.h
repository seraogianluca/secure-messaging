#include "socket.h"
#include "crypto.h"
#include <cstring>

//TODO: serve costruttore con parametri di default per fare solo dichiarazione
Crypto crypto = Crypto((unsigned char *)"1234567890123456");
SocketClient socketClient = SocketClient(SOCK_STREAM);

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

void sendHelloMessage(unsigned char *nonce) {
    unsigned char *helloMessage = NULL;
    unsigned int start = 0;
    try {
        helloMessage = new unsigned char[NONCE_SIZE + 6];
        memcpy(helloMessage, OP_LOGIN, 1);
        start += 1;
        memcpy(helloMessage+start, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonce, NONCE_SIZE);
        socketClient.sendMessage(socketClient.getMasterFD(), helloMessage, NONCE_SIZE + 6);
    } catch(const exception& e) {
        delete[] helloMessage;
        throw runtime_error(e.what());
    }
    delete[] helloMessage;
}

void checkNonce(unsigned char *nonce, unsigned char *receivedMessage) {
    unsigned char *nonceReceived = NULL;
    try {
        nonceReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceReceived, receivedMessage+5, NONCE_SIZE);
        if(memcmp(nonceReceived, nonce, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        } 
    } catch (const exception& e) {
        delete[] nonceReceived;
        throw runtime_error(e.what());
    }
}

void sendCertificateRequest(unsigned char *nonceClient, unsigned char *receivedMessage) {
    unsigned char *certificateRequestMessage = NULL;
    unsigned char *nonceServerReceived = NULL;
    unsigned int start = 0;
    try {
        nonceServerReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceServerReceived, receivedMessage+5+NONCE_SIZE, NONCE_SIZE);
        //TODO: check message format
        certificateRequestMessage = new unsigned char[2*NONCE_SIZE];
        memcpy(certificateRequestMessage, nonceServerReceived, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(certificateRequestMessage+start, nonceClient, NONCE_SIZE);
        socketClient.sendMessage(socketClient.getMasterFD(), certificateRequestMessage, (2*NONCE_SIZE));
    } catch(const exception& e) {
        delete[] nonceServerReceived;
        delete[] certificateRequestMessage;
        throw runtime_error(e.what());
    }
    delete[] nonceServerReceived;
    delete[] certificateRequestMessage;
}

void verifyServerCertificate() {
    unsigned char *cert_buff = NULL;
    unsigned int cert_len;
    X509 *cert = NULL;
    try {
        cert_buff = new unsigned char[MAX_MESSAGE_SIZE];        
        cert_len = socketClient.receiveMessage(socketClient.getMasterFD(),cert_buff);
        crypto.deserializeCertificate(cert_len, cert_buff,cert);
        if(!crypto.verifyCertificate(cert))
            throw runtime_error("Pay attention, server is not authenticated.");
        cout << "Server authenticated." << endl;
    } catch(const exception& e) {
        delete[] cert_buff;
        throw runtime_error(e.what());
    }
    delete[] cert_buff;
}

void authentication() {
    unsigned char *nonceClient = NULL;
    unsigned char *receivedMessage = NULL;
    unsigned int messageReceivedLen;

    try {
        // Generate nonce
        nonceClient = new unsigned char[NONCE_SIZE];
        crypto.generateNonce(nonceClient);

        // Build hello message
        sendHelloMessage(nonceClient);

        // Receive server hello
        receivedMessage = new unsigned char[MAX_MESSAGE_SIZE];
        messageReceivedLen = socketClient.receiveMessage(socketClient.getMasterFD(), receivedMessage);
        if (messageReceivedLen != (5 + 2*NONCE_SIZE)) {
            throw runtime_error("Uncorrect format of the message received");
        }

        // Check nonce
        checkNonce(nonceClient, receivedMessage);
        
        // Extract server nonce and send certificate request
        sendCertificateRequest(nonceClient, receivedMessage);

        // Verify certificate
        verifyServerCertificate();
    } catch (const exception &e) {
        delete[] nonceClient;
        delete[] receivedMessage;
        throw runtime_error(e.what());
    }
    delete[] nonceClient;
    delete[] receivedMessage;
}

void sendMessage(unsigned char *header, unsigned int head_len, unsigned char *msg, unsigned int pln_len) {
    unsigned char *msg_cipher = NULL;
    unsigned char *buffer = NULL;
    unsigned int ciphr_len;
    unsigned int msg_len = 0;
    int start = 0;

    try {
        msg_cipher = new unsigned char[pln_len + TAG_SIZE + IV_SIZE];
        ciphr_len = crypto.encryptMessage(msg,pln_len,msg_cipher);

        msg_len = head_len + ciphr_len;
        if (msg_len > MAX_MESSAGE_SIZE) {
            throw runtime_error("Maximum message size exceeded");
        }

        buffer = new unsigned char[msg_len];
        memcpy(buffer, header, head_len);
        start += head_len;
        memcpy(buffer+start, msg_cipher, ciphr_len);
        start += ciphr_len;

        socketClient.sendMessage(socketClient.getMasterFD(), buffer, msg_len);
    } catch(const exception& e) {
        delete[] buffer;
        throw runtime_error(e.what());
    }
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