#include "include/server.h"

int main(int argc, char* const argv[]) {
    vector<onlineUser> onlineUsers;
    vector<activeChat> activeChats;
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
                            operationCode = getOperationCode(messageReceived);
                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                cout << "\n-------Authentication-------" << endl;
                                string username = authentication(sd, messageReceived, message_len);
                                keyEstablishment(sd, i);
                                cout << "-----------------------------" << endl << endl;
                                onlineUser user = onlineUser();
                                user.username = username;
                                user.sd = sd;
                                user.key_pos = i;
                                onlineUsers.push_back(user);
                                sendOnlineUsers(onlineUsers, user);
                            } else if (operationCode == 3) {
                                //CHECK HEADER SIZE
                                int ciphertext_len = message_len-1;
                                unsigned char ciphertext[ciphertext_len];
                                unsigned char plaintext[ciphertext_len];

                                memcpy(ciphertext, messageReceived+1, ciphertext_len);
                                int plaintext_len = crypto.decryptMessage(ciphertext,ciphertext_len,plaintext);
                                if(plaintext_len == -1)
                                    cout << "Not corresponding tag." << endl;
                                else {
                                    cout << "Plaintext: " << plaintext << endl;
                                }
                            }
                            if (operationCode == 2) {
                                // Request to talk
                                cout << "\n-------Request to Talk-------" << endl;
                                requestToTalkProtocol(messageReceived, message_len, onlineUsers.at(i), onlineUsers);
                                cout << "------------------------------" << endl;
                            }
                            if (operationCode == 3) {
                                // Message
                            }
                            if (operationCode == 4) {
                                // Certificate Request
                            }
                        }

                        delete[] messageReceived;
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

