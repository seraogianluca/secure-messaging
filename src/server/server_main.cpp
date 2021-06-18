#include "include/server.h"

int main(int argc, char* const argv[]) {
    ServerContext ctx;
    vector<unsigned char> messageReceived;
    OnlineUser user;

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

                        receive(ctx.serverSocket, sd, messageReceived);
                        cout << "Message received length: " << messageReceived.size() << endl;

                        if (messageReceived.size() == 0)  {
                            try {
                                //Somebody disconnected , get his details and print 
                                ctx.serverSocket->disconnectHost(sd, i);
                                // Remove its chat from the active chats                        
                                user = ctx.getUser(sd);
                                ctx.crypto->removeKey(user.key_pos);
                                ctx.deleteUser(user);
                                ctx.deleteActiveChat(user);
                            } catch(...) {
                                cerr << "Something bad occurs at client on socket " << sd << endl;
                            }
                        } else {
                            int operationCode = messageReceived[0] - '0';
                            if (operationCode < 0 || operationCode > 5) {
                                cout << "Operation code not valid." << endl;
                                break;
                            }     

                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                cout << endl << "-------Authentication-------" << endl;
                                authentication(ctx, sd, messageReceived);
                                cout << "-----------------------------" << endl;
                            } else if (operationCode == 1) {
                                cout << endl << "-------Close connection--------" << endl;
                                logout(ctx, sd, i);
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 2) {
                                // Request to talk
                                cout << endl << "-------Request to Talk-------" << endl;
                                user = ctx.getUser(sd);
                                requestToTalk(ctx, messageReceived, user);
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 3) {
                                //Message Forwarding
                                user = ctx.getUser(sd);
                                chat(ctx, messageReceived, user);
                            } else if (operationCode == 4) {
                                cout << endl << "----Online User List Request----" << endl;
                                user = ctx.getUser(sd);
                                cout << user.username << " requested the online users list" << endl;
                                receiveOnlineUsersRequest(ctx, user, messageReceived);
                                cout << "Online users list sent to " << user.username << endl;
                                cout << "---------------------------------" << endl;
                            } else if (operationCode == 5) {
                                cout << "\n----A client wants to close a chat----" << endl;
                                user = ctx.getUser(sd);
                                cout << user.username << " wants to close the chat" << endl;
                                chat(ctx, messageReceived, user);
                                logout(ctx, sd, i);
                                cout << "---------------------------------" << endl;
                            }
                        }
                    }  

                    messageReceived.clear();
                }
            }
        } catch(const exception& e) { cerr << e.what() << endl; }
    }
    return 0;
}