#include "crypto.h"
#include "socket.h"

SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
Crypto crypto((unsigned char*)"1234567890123456");

int getOperationCode(unsigned char* message) {
    int opCode = message[0] - '0';
    if (opCode < 0 || opCode > 4) { throw runtime_error("Operation Code not valid");}
    return opCode;
}

void authentication(int sd, unsigned char *messageReceived, unsigned int message_len) {
    unsigned char *nonceServer = NULL;
    unsigned char *nonceServerReceived = NULL;
    unsigned char *nonceClient = NULL;
    unsigned char *helloMessage = NULL;
    unsigned char *certificateRequest = NULL;
    unsigned char *cert_buff = NULL;
    X509 *cert = NULL;
    unsigned int start;
    unsigned int certificateRequestLen;
    unsigned int cert_len;

    try {
        cout << "Hello Message from the client: " << endl;
        BIO_dump_fp(stdout, (const char*) messageReceived, message_len);

        // Generate nonce
        nonceServer = new unsigned char[NONCE_SIZE];
        crypto.generateNonce(nonceServer);
        cout << "Nonce Server: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceServer, NONCE_SIZE);

        // Get peer nonce
        nonceClient = new unsigned char[NONCE_SIZE];
        memcpy(nonceClient, messageReceived+6, NONCE_SIZE);
        cout << "Client Nonce: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceClient, NONCE_SIZE);

        // Build hello message
        helloMessage = new unsigned char[5 + 2*NONCE_SIZE];
        start = 0;
        memcpy(helloMessage, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonceClient, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(helloMessage+start, nonceServer, NONCE_SIZE);
        cout << "Server Hello Message: " << endl;
        BIO_dump_fp(stdout, (const char*) helloMessage, (5 + 2*NONCE_SIZE));
        serverSocket.sendMessage(sd, helloMessage, (5 + 2*NONCE_SIZE));
        cout << "Hello message sent" << endl;

        // Receive certificate request
        certificateRequest = new unsigned char[MAX_MESSAGE_SIZE];
        certificateRequestLen = serverSocket.receiveMessage(sd, certificateRequest);
        cout << "Certificate Request Received: " << endl;
        BIO_dump_fp(stdout, (const char*) certificateRequest, certificateRequestLen);

        // Check nonce
        if (certificateRequestLen != (2*NONCE_SIZE)) { 
            throw runtime_error("Uncorrect format of the message received");
        }

        nonceServerReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceServerReceived, certificateRequest, NONCE_SIZE);
        cout << "Nonce Server Received: " << endl;
        BIO_dump_fp(stdout, (const char*) nonceServerReceived, NONCE_SIZE);

        if(memcmp(nonceServerReceived, nonceServer, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }

        cout << "Freshness Confirmed" << endl;

        //VERIFY CERTIFICATE
        crypto.loadCertificate(cert,"server_cert");
        cert_buff = new unsigned char[MAX_MESSAGE_SIZE];
        cert_len = crypto.serializeCertificate(cert,cert_buff);
        serverSocket.sendMessage(sd,cert_buff,cert_len);

    } catch(const exception& e) {
        delete[] nonceServer;
        delete[] nonceClient;
        delete[] helloMessage;
        delete[] certificateRequest;
        delete[] nonceServerReceived;
        delete[] cert_buff;
        throw runtime_error(e.what());
    }

    delete[] nonceServer;
    delete[] nonceClient;   
    delete[] helloMessage;
    delete[] certificateRequest;
    delete[] nonceServerReceived; 
    delete[] cert_buff;
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
        throw runtime_error(e.what());
    }
    
    delete[] buffer;
    delete[] secret;
}