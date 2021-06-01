#include <fstream>
#include "crypto.h"
#include "socket.h"

SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
Crypto crypto((unsigned char*)"1234567890123456");

int getOperationCode(unsigned char* message) {
    int opCode = message[0] - '0';
    if (opCode < 0 || opCode > 4) { throw runtime_error("Operation Code not valid");}
    return opCode;
}

unsigned int readPassword(unsigned char* username, unsigned int usernameLen, unsigned char* password) {
    ifstream file("./resources/credentials.txt");
    string line;
    string delimiter = " ";
    string pwd;
    string usn;
    const char* usernameChar = (const char*) username;
    while (getline(file, line)) {
        cout << "Line: " << line << endl;
        usn = line.substr(0, line.find(delimiter));
        cout << usn.compare(usernameChar) << endl;
        if(usn.compare(usernameChar) == 0) {
            pwd = line.substr(line.find(delimiter) + 1);
            password = (unsigned char*) pwd.c_str();
            return pwd.length();
        }
    }
    return 0;
}

void buildHelloMessage(int sd, unsigned char *nonceClient, unsigned char *nonceServer){
    unsigned char *helloMessage = NULL;
    unsigned int start;
    try{
        helloMessage = new unsigned char[5 + 2*NONCE_SIZE];
        start = 0;
        memcpy(helloMessage, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonceClient, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(helloMessage+start, nonceServer, NONCE_SIZE);
        serverSocket.sendMessage(sd, helloMessage, (5 + 2*NONCE_SIZE));
    }catch(const exception& e) {
        delete[] helloMessage;
        throw;
    }
    delete[] helloMessage;
}

void checkNonce(unsigned char *certificateRequest, unsigned char *nonceServer){
    unsigned char *nonceServerReceived = NULL;
    try{       
        nonceServerReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceServerReceived, certificateRequest, NONCE_SIZE);

        if(memcmp(nonceServerReceived, nonceServer, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }
    }catch(const exception& e) {
        delete[] nonceServerReceived;
        throw;
    }
    delete[] nonceServerReceived;
}

void sendCertificate(int sd, unsigned char* username, unsigned int usernameLen, unsigned char *nonceClient, unsigned char *nonceServer){
    unsigned char *cert_buff = NULL;
    unsigned char *buffer = NULL;
    unsigned char *encrypt_msg = NULL;
    X509 *cert = NULL;
    EVP_PKEY *user_pubkey = NULL;
    unsigned int cert_len;
    unsigned int start = 0;
    unsigned int bufferLen = 0;
    unsigned int encrypted_msg_len;
    try{
        crypto.loadCertificate(cert,"server_cert");
        cert_buff = new unsigned char[MAX_MESSAGE_SIZE];
        cert_len = crypto.serializeCertificate(cert,cert_buff);

        bufferLen = usernameLen + cert_len + 2*NONCE_SIZE;
        buffer = new unsigned char[bufferLen];
        encrypt_msg = new unsigned char[MAX_MESSAGE_SIZE];
        memcpy(buffer, username, usernameLen);
        start += usernameLen;
        memcpy(buffer+start, cert_buff, cert_len);
        start+=cert_len;
        memcpy(buffer+start, nonceClient, NONCE_SIZE);
        start+=NONCE_SIZE;
        memcpy(buffer+start, nonceServer, NONCE_SIZE);

        crypto.readPublicKey((const char*)username, user_pubkey);
        encrypted_msg_len = crypto.publicKeyEncryption(buffer,bufferLen,encrypt_msg,user_pubkey);
        serverSocket.sendMessage(sd,encrypt_msg,encrypted_msg_len);
    }catch(const exception& e) {
        delete[] cert_buff;
        delete[] buffer;
        delete[] encrypt_msg;
        throw;
    }
    delete[] cert_buff;
    delete[] buffer;
    delete[] encrypt_msg;
}

void authentication(int sd, unsigned char *messageReceived, unsigned int message_len) {
    unsigned char *nonceServer = NULL;
    unsigned char *nonceClient = NULL;
    unsigned char *username = NULL;
    unsigned char *buffer = NULL;
    unsigned char *plaintext = NULL;
    EVP_PKEY *prvkey = NULL;
    unsigned int bufferLen;
    unsigned int usernameLen;
    unsigned int plainlen;

    try {
        // Generate nonce
        nonceServer = new unsigned char[NONCE_SIZE];
        crypto.generateNonce(nonceServer);

        // Get peer nonce
        nonceClient = new unsigned char[NONCE_SIZE];
        memcpy(nonceClient, messageReceived+message_len-NONCE_SIZE, NONCE_SIZE);
        // Get peer username
        usernameLen = message_len-NONCE_SIZE-1;
        username = new unsigned char[usernameLen];
        memcpy(username, messageReceived+1, usernameLen);
        cout << "Client username: " << username << endl;

        //Send Certificate
        sendCertificate(sd, username, usernameLen, nonceClient, nonceServer);

        //Receive hashed passwords
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        bufferLen = serverSocket.receiveMessage(sd, buffer);
        plaintext = new unsigned char[bufferLen];
        crypto.readPrivateKey(prvkey);
        plainlen = crypto.publicKeyDecryption(buffer, bufferLen,plaintext,prvkey);

        cout << "Client authenticated." << endl;
    } catch(const exception& e) {
        delete[] nonceServer;
        delete[] nonceClient;
        delete[] username;
        delete[] buffer;
        delete[] plaintext;
        throw;
    }
    delete[] nonceServer;
    delete[] nonceClient;
    delete[] username;
    delete[] buffer;
    delete[] plaintext;
}

void keyEstablishment(int sd){
    unsigned char *buffer = NULL;
    unsigned char *secret = NULL;
    unsigned int key_len;
    EVP_PKEY *prv_key_a = NULL;
    EVP_PKEY *pub_key_b = NULL;

    try {
        // Generate public key
        crypto.keyGeneration(prv_key_a);
        
        // Receive peer's public key
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        key_len = serverSocket.receiveMessage(sd, buffer);
        crypto.deserializePublicKey(buffer, key_len, pub_key_b);

        // Send public key to peer
        key_len = crypto.serializePublicKey(prv_key_a, buffer);
        serverSocket.sendMessage(sd, buffer, key_len);

        // Secret derivation
        secret = new unsigned char[DIGEST_LEN];
        crypto.secretDerivation(prv_key_a, pub_key_b, secret);
        crypto.setSessionKey(secret);
    } catch(const exception& e) {
        delete[] buffer;
        delete[] secret;
        throw;
    }
    
    delete[] buffer;
    delete[] secret;
}