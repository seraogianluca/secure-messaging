#include "include/server.h"

void errorhandling(ServerContext &ctx, int sd, int i) {
    lock_guard<mutex> lock(ctx.m);
    OnlineUser user;
    try {
        //Somebody disconnected , get his details and print 
        ctx.serverSocket->disconnectHost(sd, i);
        // Remove its chat from the active chats                        
        user = ctx.getUser(sd);
        ctx.crypto->removeKey(user.key_pos);
        ctx.deleteUser(user);
        ctx.deleteActiveChat(user);
    } catch(const exception& e){
        cerr << e.what() << endl;
        cerr << "Something bad occurs at client on socket " << sd << endl;
    }
}

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
                            thread err(errorhandling, ref(ctx), sd, i);
                            err.join();
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
                                thread auth(authentication,std::ref(ctx), sd, messageReceived);
                                auth.join();
                                cout << "-----------------------------" << endl;
                            } else if (operationCode == 1) {
                                cout << endl << "-------Close connection--------" << endl;
                                thread log(logout, std::ref(ctx), sd, i);
                                log.join();
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 2) {
                                // Request to talk
                                cout << endl << "-------Request to Talk-------" << endl;
                                user = ctx.getUser(sd);
                                thread rtt(requestToTalk,std::ref(ctx), messageReceived, user);
                                rtt.join();
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 3) {
                                //Message Forwarding
                                user = ctx.getUser(sd);
                                thread cht(chat, std::ref(ctx), messageReceived, user);
                                cht.join();
                            } else if (operationCode == 4) {
                                cout << endl << "----Online User List Request----" << endl;
                                user = ctx.getUser(sd);
                                cout << user.username << " requested the online users list" << endl;
                                thread onlusr(receiveOnlineUsersRequest, std::ref(ctx), user, messageReceived);
                                onlusr.join();
                                cout << "Online users list sent to " << user.username << endl;
                                cout << "---------------------------------" << endl;
                            } else if (operationCode == 5) {
                                cout << "\n----A client wants to close a chat----" << endl;
                                user = ctx.getUser(sd);
                                cout << user.username << " wants to close the chat" << endl;
                                chat(ctx, messageReceived, user);
                                thread log(logout, std::ref(ctx), sd, i);
                                log.join();
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