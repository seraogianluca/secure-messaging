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
        cerr << e.what() << endl;
    }
    return 0;
}


void login() {

}

void logout() {

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