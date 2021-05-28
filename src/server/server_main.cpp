#include "include/server.h"
#include "include/socket.h"

#define PORT 8080

void login();
void logout();

int main(int argc, char* const argv[]) {
    try {
        SocketServer serverSocket = SocketServer(SOCK_STREAM); //TCP
        Server server = Server();
        Crypto c((unsigned char*)"1234567890123456");
        unsigned char *tag;
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
                        string messageReceived = serverSocket.receiveMessage(sd);
                        if (messageReceived.length() == 0)  { 
                            //Somebody disconnected , get his details and print 
                            serverSocket.disconnectHost(sd, i);
                        } else {
                            cout << "Received message from peer: " << messageReceived << endl;
                            int operationCode = server.getOperationCode(messageReceived);
                            cout << "Operation code: " << operationCode << endl;
                            if (operationCode == 0) {
                                // Login
                                login();
                            }
                            if (operationCode == 1) {
                                // Logout
                                unsigned char iv[IV_SIZE];
                                int ciphertext_len = messageReceived.length()-IV_SIZE-1;
                                cout<<"Lunghezza: "<<messageReceived.length()<<endl;
                                unsigned char enc[ciphertext_len];
                                string ivMessage = messageReceived.substr(1,IV_SIZE+1);
                                string encMessage = messageReceived.substr(IV_SIZE+1,messageReceived.length());
                                strncpy((char*)iv,ivMessage.c_str(),IV_SIZE);
                                strncpy((char*)enc,encMessage.c_str(),ciphertext_len);
                                unsigned char* dec_msg = (unsigned char*)malloc(ciphertext_len);
                                iv[IV_SIZE]='\0';
                                enc[ciphertext_len]='\0';
                                int plaintext_len = c.decryptMessage(enc,
                                                                ciphertext_len,
                                                                iv,
                                                                tag,
                                                                dec_msg);
                                if(plaintext_len == -1)
                                    cout << "Not corresponding tag." << endl;
                                else {
                                    cout<<"Plaintext:"<<endl;
                                    BIO_dump_fp (stdout, (const char *)dec_msg, plaintext_len);
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