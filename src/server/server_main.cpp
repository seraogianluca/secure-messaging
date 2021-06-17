#include "include/server.h"

int main(int argc, char* const argv[]) {
    vector<onlineUser> onlineUsers;
    vector<activeChat> activeChats;
    ServerContext ctx;


    while(true) {
        try {
            ctx.serverSocket->initSet();
            ctx.serverSocket->selectActivity();

            if(ctx.serverSocket->isFDSet(ctx.serverSocket->getMasterFD())) {
                ctx.serverSocket->acceptNewConnection();
            } else {
                for(unsigned int i = 0; i < MAX_CLIENTS; i++)  {  
                    int sd = ctx.serverSocket->getClient(i);
                    if (ctx.serverSocket->isFDSet(sd)) {
                        //Check if it was for closing , and also read the 
                        //incoming message                         
                        unsigned int message_len;  
                        vector<unsigned char> messageReceived;
                        messageReceived.reserve(MAX_MESSAGE_SIZE);
                        unsigned char *messageReceivedBuffer = new unsigned char[MAX_MESSAGE_SIZE];

                        onlineUser user = onlineUser();
                        onlineUser receiver = onlineUser();

                        message_len = ctx.serverSocket->receiveMessage(sd, messageReceivedBuffer);
                        messageReceived.insert(messageReceived.end(), messageReceivedBuffer, messageReceivedBuffer + message_len);
                        delete[] messageReceivedBuffer;
                        
                        cout << "Message received length: " << message_len << endl;

                        if (message_len == 0)  { 
                            //Somebody disconnected , get his details and print 
                            ctx.serverSocket->disconnectHost(sd, i);
                            // Remove its chat from the active chats
                            // TODO
                        } else {
                            int operationCode = messageReceived[0] - '0';
                            if (operationCode < 0 || operationCode > 4) {
                                cout << "Operation code not valid." << endl;
                                break;
                            }     

                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                cout << "\n-------Authentication-------" << endl;
                                authentication(ctx, sd, messageReceived);
                                cout << "-----------------------------" << endl;
                            } else if (operationCode == 1) {
                                cout << "-------Starting close connection--------" << endl;
                                // TODO: 
                                cout << "--------Connection closed------------" << endl;
                            } else if (operationCode == 2) {
                                // Request to talk
                                cout << "\n-------Request to Talk-------" << endl;
                                user = ctx.getUser(sd);
                                requestToTalk(ctx, messageReceived, user);
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 3) {
                                //Message Forwarding
                                user = ctx.getUser(sd);
                                cout<<"user "<<user.username;
                                chat(ctx, messageReceived, user);
                            } else if (operationCode == 4) {
                                cout << "\n----Online User List Request----" << endl;
                                user = ctx.getUser(sd);
                                receiveOnlineUsersRequest(ctx, user, messageReceived);
                                cout << "---------------------------------" << endl;
                            } else if (operationCode == 5) {
                                cout << "\n----Error on a client----" << endl;
                                // printBuffer(messageReceived);
                                cout << "---------------------------------" << endl;
                            }
                        }
                    }  
                }
            }
        } catch(const exception& e) { cerr << e.what() << endl; }
    }
    return 0;
}