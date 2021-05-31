#include "include/server.h"
#include "include/socket.h"

SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
Server server = Server();
Crypto crypto((unsigned char*)"1234567890123456");

void login();
void logout();
void keyEstablishment(int sd);
void authentication(int sd, unsigned char* messageReceived, unsigned int message_len);

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