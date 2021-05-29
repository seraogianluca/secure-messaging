#include "include/server.h"
#include "include/socket.h"

SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
Server server = Server();
Crypto crypto((unsigned char*)"1234567890123456");

void login();
void logout();
void keyEstablishment(int sd);

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
                        unsigned char* messageReceived = serverSocket.receiveMessage(sd, message_len);
                        cout << "Message received." << endl;
                        if (message_len == 0)  { 
                            //Somebody disconnected , get his details and print 
                            serverSocket.disconnectHost(sd, i);
                        } else {
                            int operationCode;
                            operationCode = server.getOperationCode(messageReceived);
                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                keyEstablishment(sd);
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
        cerr << e.what() << '\n';
    }
    return 0;
}


void login() {

}

void logout() {

}

void keyEstablishment(int sd){
    unsigned char buffer[2048] = {0};
    unsigned char* bufferRecvd;
    unsigned char* secret;
    unsigned char* hashedSecret;
    size_t secretlen;
    unsigned int buffer_rcvd_len;
    EVP_PKEY* params;
    EVP_PKEY* prv_key_a;
    EVP_PKEY* pub_key_b;

    params = crypto.buildParameters();
    prv_key_a = crypto.keyGeneration(params);
    

    //send g^b mod p
    bufferRecvd = serverSocket.receiveMessage(sd, buffer_rcvd_len);
    pub_key_b = crypto.deserializePublicKey(bufferRecvd, buffer_rcvd_len);
    cout << "pub_key_b: " << endl;
    BIO_dump_fp(stdout, (const char*)bufferRecvd, buffer_rcvd_len);
    //receive g^a mod p
    unsigned int pubKeyLen = crypto.serializePublicKey(prv_key_a, buffer); // Estrae la chiave pubblica e la mette in buffer
    serverSocket.sendMessage(sd, buffer, pubKeyLen);
    cout << "pub_key_a: " << endl;
    BIO_dump_fp(stdout, (const char*)buffer, pubKeyLen);

    secret = crypto.secretDerivation(prv_key_a, pub_key_b, secretlen);
    hashedSecret = crypto.computeHash(secret, secretlen); //128 bit digest
    cout << "Secret: " << endl;
    BIO_dump_fp(stdout, (const char*)secret, secretlen);
    cout << "Hash: " << endl;
    BIO_dump_fp(stdout, (const char*)hashedSecret, DIGEST_LEN);

    crypto.setSessionKey(hashedSecret, DIGEST_LEN);
}