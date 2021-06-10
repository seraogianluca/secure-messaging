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
                        vector<unsigned char> messageReceived;
                        messageReceived.reserve(MAX_MESSAGE_SIZE);
                        unsigned char *messageReceivedBuffer = new unsigned char[MAX_MESSAGE_SIZE];

                        onlineUser user = onlineUser();
                        onlineUser receiver = onlineUser();

                        message_len = serverSocket.receiveMessage(sd, messageReceivedBuffer);
                        messageReceived.insert(messageReceived.end(), messageReceivedBuffer, messageReceivedBuffer + message_len);
                        delete[] messageReceivedBuffer;
                        
                        cout << "Message received length: " << message_len << endl;

                        if (message_len == 0)  { 
                            //Somebody disconnected , get his details and print 
                            serverSocket.disconnectHost(sd, i);
                            // Remove its chat from the active chats
                            onlineUser userDisconnected = onlineUsers.at(i);
                            deleteUser(userDisconnected, onlineUsers);
                            deleteActiveChat(userDisconnected, activeChats);
                        } else {
                            int operationCode = messageReceived[0] - '0';
                            if (operationCode < 0 || operationCode > 4) { throw runtime_error("Operation Code not valid");}
                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                cout << "\n-------Authentication-------" << endl;
                                messageReceived.erase(messageReceived.begin()); // TODO
                                string username = authentication(sd, messageReceived);
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
                                memcpy(ciphertext, messageReceived.data()+1, ciphertextLen);
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
                                bool success = requestToTalkProtocol(messageReceived.data(), message_len, onlineUsers.at(i), onlineUsers, chat);
                                if (success) {
                                    activeChats.push_back(chat);
                                    cout << "New chat active between " << chat.a.username << " and " << chat.b.username << endl;
                                } else {
                                    cout << "No chat has been created" << endl;
                                }
                                cout << "------------------------------" << endl;
                            }
                            if (operationCode == 3) {
                                //Message Forwarding
                                //Remove OP code
                                user = onlineUsers.at(i);
                                cout << "Sender Username: " << user.username << endl;

                                int ciphertextLen = message_len-1;
                                unsigned char ciphertext[message_len - 1];
                                memcpy(ciphertext, messageReceived.data()+1, ciphertextLen);
                                //Find the receiver
                                if (getReceiver(activeChats, user, receiver)) {
                                    cout << "Receiver: " << receiver.username << " - " << receiver.key_pos << endl;
                                    forward(user, receiver, ciphertext, ciphertextLen);
                                } else {
                                    cout << "No receiver for the user " << user.username << endl;
                                }
                            }
                            if (operationCode == 4) {
                                cout << "\n----Online User List Request----" << endl;
                                user = onlineUsers.at(i);
                                sendOnlineUsers(onlineUsers, user);
                                cout << "---------------------------------" << endl;
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