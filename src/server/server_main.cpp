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

                        onlineUser user = onlineUser();
                        onlineUser receiver = onlineUser();

                        message_len = serverSocket.receiveMessage(sd, messageReceived);
                        cout << "Message received length: " << message_len << endl;
                        if (message_len == 0)  { 
                            //Somebody disconnected , get his details and print 
                            serverSocket.disconnectHost(sd, i);
                            // Remove its chat from the active chats
                            onlineUser userDisconnected = onlineUsers.at(i);
                            cout << "Users size: " << onlineUsers.size() << endl;
                            deleteUser(userDisconnected, onlineUsers);
                            cout << "Users size: " << onlineUsers.size() << endl;
                            cout << "Active chat size: " << activeChats.size() << endl;
                            deleteActiveChat(userDisconnected, activeChats);
                            cout << "Active chat size: " << activeChats.size() << endl;
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
                                user.username = username;
                                user.sd = sd;
                                user.key_pos = i;
                                onlineUsers.push_back(user);
                                sendOnlineUsers(onlineUsers, user);
                            }
                            if (operationCode == 1){
                                cout << "-------Starting close connection--------" << endl;
                                user = onlineUsers.at(i);
                                cout << "Sender Username: " << user.username << endl;

                                int ciphertextLen = message_len-1;
                                unsigned char ciphertext[message_len - 1];
                                memcpy(ciphertext, messageReceived+1, ciphertextLen);
                                //Find the receiver
                                if (getReceiver(activeChats, user, receiver)) {
                                    forward(user, receiver, ciphertext, ciphertextLen);
                                    deleteActiveChat(user, activeChats);
                                } else {
                                    cout << "No receiver for the user " << user.username << endl;
                                }
                                cout << "--------Connection closed------------" << endl;
                            }
                            if (operationCode == 2) {
                                // Request to talk
                                cout << "\n-------Request to Talk-------" << endl;
                                activeChat chat = activeChat();
                                bool success = requestToTalkProtocol(messageReceived, message_len, onlineUsers.at(i), onlineUsers, chat);
                                if (success) {
                                    activeChats.push_back(chat);
                                    cout << "New chat active between " << chat.a.username << " and " << chat.b.username << endl;
                                    cout << "------------------------------" << endl;
                                } else {
                                    cout << "No chat has been created" << endl;
                                    cout << "------------------------------" << endl;
                                }
                            }
                            if (operationCode == 3) {
                                //Message Forwarding
                                //Remove OP code
                                user = onlineUsers.at(i);
                                cout << "Sender Username: " << user.username << endl;

                                int ciphertextLen = message_len-1;
                                unsigned char ciphertext[message_len - 1];
                                memcpy(ciphertext, messageReceived+1, ciphertextLen);
                                //Find the receiver
                                if (getReceiver(activeChats, user, receiver)) {
                                    cout << "Receiver: " << receiver.username << " - " << receiver.key_pos << endl;
                                    forward(user, receiver, ciphertext, ciphertextLen);
                                } else {
                                    cout << "No receiver for the user " << user.username << endl;
                                }
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