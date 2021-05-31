#include "include/server.h"
#include "include/socket.h"

SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
Server server = Server();
Crypto crypto((unsigned char*)"1234567890123456");

void login();
void logout();
void keyEstablishment(int sd);
void authentication(int sd, unsigned char* messageReceived, unsigned int message_len);
bool isNonceEquivalent(unsigned char* nonceReceived, unsigned char* clientNonce, unsigned int nonceLen);
void extractClientNonce(unsigned char* clientNonce, unsigned int clientNonceLen, unsigned char* msg, unsigned int msgLen, unsigned int serverNonceLen);
void extractServerNonce(unsigned char* serverNonce, unsigned int serverNonceLen, unsigned char* msg, unsigned int msgLen);

int main(int argc, char* const argv[]) {
    try {
        while(true) {
            serverSocket.initSet();
            serverSocket.selectActivity();

            if(serverSocket.isFDSet(serverSocket.getMasterFD())) {
                serverSocket.acceptNewConnection();
            } else {
                for (unsigned int i = 0; i < MAX_CLIENTS; i++)  {  
                    int sd = serverSocket.getClient(i); 
                    if (serverSocket.isFDSet(sd)) {
                        //Check if it was for closing , and also read the 
                        //incoming message                         
                        unsigned int message_len;    
                        unsigned char *messageReceived = new unsigned char[MAX_MESSAGE_SIZE];
                        message_len = serverSocket.receiveMessage(sd, messageReceived);
                        cout << "Message received length: " << message_len << endl;
                        if (message_len == 0)  { 
                            //Somebody disconnected , get his details and print 
                            serverSocket.disconnectHost(sd, i);
                        } else {
                            int operationCode;
                            operationCode = server.getOperationCode(messageReceived);
                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                cout << "\n-------Authentication-------" << endl;
                                authentication(sd, messageReceived, message_len);
                                cout << "-----------------------------" << endl << endl;
                                // keyEstablishment(sd);
                            } else if (operationCode == 3) {
                                unsigned char iv[IV_SIZE];
                                unsigned char tag[TAG_SIZE];
                                int start;
                                int ciphertext_len;

                                start = 1;
                                memcpy(iv, messageReceived+start, IV_SIZE);
                                start += IV_SIZE;

                                ciphertext_len = message_len-IV_SIZE-TAG_SIZE-1;
                                unsigned char encMessage[ciphertext_len];
                                memcpy(encMessage, messageReceived+start, ciphertext_len);
                                memcpy(tag, messageReceived+message_len-TAG_SIZE, TAG_SIZE);
                                unsigned char dec_msg[ciphertext_len];
                                int plaintext_len = crypto.decryptMessage(encMessage,ciphertext_len,iv,tag,dec_msg);
                                if(plaintext_len == -1)
                                    cout << "Not corresponding tag." << endl;
                                else {
                                    cout << "Plaintext: " << dec_msg << endl;
                                }
                            }
                            if (operationCode == 2) {
                                // Request to talk
                            }
                            if (operationCode == 3) {
                                // Message
                            }
                            if (operationCode == 4) {
                                // Certificate Request
                            }
                        }
                    }  
                }
            }
        }
    } catch(const exception& e) {
        cerr << e.what() << endl;
    }
    return 0;
}


void login() {

}

void logout() {

}

void authentication(int sd, unsigned char* messageReceived, unsigned int message_len) {
    unsigned char* nonceServer;
    unsigned char* nonceServerReceived;
    unsigned char* nonceClient;
    unsigned char* helloMessage;
    unsigned int nonceServerLen;
    unsigned int nonceClientLen;
    unsigned int helloMessageLen;

    unsigned char* certificateRequest;
    unsigned int certificateRequestLen;

    cout << "Hello Message from the client: " << endl;
    BIO_dump_fp(stdout, (const char*) messageReceived, message_len);

    nonceServerLen = 16;
    nonceServer = new unsigned char[nonceServerLen];
    crypto.generateNonce(nonceServer, nonceServerLen);

    cout << "Nonce Server: " << endl;
    BIO_dump_fp(stdout, (const char*) nonceServer, nonceServerLen);

    nonceClientLen = message_len - 6;
    cout << "Nonce Client Len: " << nonceClientLen << endl;
    nonceClient = new unsigned char[nonceClientLen];
    extractClientNonce(nonceClient, nonceClientLen, messageReceived, message_len, nonceServerLen);

    cout << "Client Nonce: " << endl;
    BIO_dump_fp(stdout, (const char*) nonceClient, nonceClientLen);

    helloMessageLen = 5 + nonceClientLen + nonceServerLen;
    helloMessage = new unsigned char[helloMessageLen];
    memcpy(helloMessage, "hello", 5);
    memcpy(&helloMessage[5], nonceClient, 5 + nonceClientLen);
    memcpy(&helloMessage[5 + nonceClientLen], nonceServer, helloMessageLen);
    
    cout << "Server Hello Message: " << endl;
    BIO_dump_fp(stdout, (const char*) helloMessage, helloMessageLen);

    serverSocket.sendMessage(sd, helloMessage, helloMessageLen);
    cout << "Hello message sent" << endl;

    certificateRequest = serverSocket.receiveMessage(sd, certificateRequestLen);

    cout << "Certificate Request Received: " << endl;
    BIO_dump_fp(stdout, (const char*) certificateRequest, certificateRequestLen);

    nonceServerReceived = new unsigned char[nonceServerLen];
    if (certificateRequestLen < 1 + nonceServerLen) { throw runtime_error("Uncorrect format of the message received");}
    memcpy(nonceServerReceived, &certificateRequest[1], nonceServerLen);

    cout << "Nonce Server Received: " << endl;
    BIO_dump_fp(stdout, (const char*) nonceServerReceived, nonceServerLen);

    if(!isNonceEquivalent(nonceServer, nonceServerReceived, nonceServerLen)) {
        throw runtime_error("Login Error: The freshness of the message is not confirmed");
    }
    cout << "Freshness Confirmed" << endl;
}

void extractClientNonce(unsigned char* clientNonce, unsigned int clientNonceLen, unsigned char* msg, unsigned int msgLen, unsigned int serverNonceLen) {
    if (msgLen < 6) { throw runtime_error("Uncorrect format of the message received");}
    memcpy(clientNonce, &msg[6], 6 + clientNonceLen); // 6 perchè dobbiamo togliere l'OP code
}

void extractServerNonce(unsigned char* serverNonce, unsigned int serverNonceLen, unsigned char* msg, unsigned int msgLen) {
    if (msgLen < 5 + serverNonceLen) { throw runtime_error("Uncorrect format of the message received");}
    int clientNonceLen = msgLen - 5 - serverNonceLen;
    memcpy(serverNonce, &msg[5 + clientNonceLen], serverNonceLen);
}

bool isNonceEquivalent(unsigned char* clientNonceReceived, unsigned char* clientNonce, unsigned int clientNonceLen) {
    int ret = memcmp(clientNonceReceived, clientNonce, clientNonceLen);
    return ret == 0;
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