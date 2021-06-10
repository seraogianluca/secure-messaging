#include "include/client.h"
#include <sys/select.h>

void showMenu();
void insertCommand();

int main(int argc, char *const argv[]) {
    string input;
    string peer;
    string username;
    string password;
    string message;
    unsigned char *buffer = NULL;
    vector<string> onlineUsers;
    fd_set fds;
    int maxfd;
    int option = -1;

    try {
        buffer = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer) throw runtime_error("Buffer not allocated.");

        cout << "\n-------Authentication-------" << endl;

        socketClient.makeConnection();
        socketClient.receiveMessage(socketClient.getMasterFD(), buffer);
        cout << "Connection confirmed: " << buffer << endl;
        username = readFromStdout("Insert username: ");
        password = readPassword();
        authentication(username, password);
        crypto.setSessionKey(0);

        cout << "-----------------------------" << endl << endl;

        receiveOnlineUsersList(onlineUsers);    
        while (true) {
            maxfd = (socketClient.getMasterFD() > STDIN_FILENO) ? socketClient.getMasterFD() : STDIN_FILENO;
            FD_ZERO(&fds);
            FD_SET(socketClient.getMasterFD(), &fds); 
            FD_SET(STDIN_FILENO, &fds); 

            showMenu();
            cout << "--> ";
            cout.flush();  
            
            select(maxfd+1, &fds, NULL, NULL, NULL); 

            if (FD_ISSET(0, &fds)) {  
                cin >> option;
                cin.ignore();
            }

            if (FD_ISSET(socketClient.getMasterFD(), &fds)) option = 3;

            switch(option) {
                case 1:
                    askOnlineUserList();
                    receiveOnlineUsersList(onlineUsers);
                    break;
                case 2:
                    cout << "\n-------Request to talk-------" << endl;
                    peer = readFromStdout("Insert username: ");

                    if(!checkUserOnline(peer, onlineUsers)) {
                        cout << "No user online with this username: insert a valid username or ask for the list of online users." << endl;
                        cout << "-----------------------------" << endl;
                        break;
                    }

                    sendRequestToTalk(peer, username, password);
                    cout << "-----------------------------" << endl;

                    while(true){
                        message = readFromStdout(username + ": ");

                        if(message.compare("!deh") == 0){
                            cout << "You closed the chat." << endl;
                            sendCloseConnection(username);
                            break;
                        }

                        sendMessage(message);
                        message = receiveMessage();

                        if(message.compare("!deh") == 0){
                            cout << peer << " closed the chat." << endl;
                            crypto.removeKey(1);
                            crypto.setSessionKey(0);
                            break;
                        }

                        cout << peer << ": " << message << endl;
                    }

                    break;
                case 3:
                    cout << "\n-------Received request to talk-------" << endl;
                    receiveRequestToTalk(username, password, peer);
                    cout << "------------------------------------------" << endl;

                    while(true){
                        message = receiveMessage();

                        if(message.compare("!deh") == 0){
                            cout << peer << " closed the chat." << endl;
                            crypto.removeKey(1);
                            crypto.setSessionKey(0);
                            break;
                        }

                        cout << peer << ": " << message << endl;
                        message = readFromStdout(username + ": ");

                        if(message.compare("!deh") == 0){
                            cout << "You closed the chat." << endl;
                            sendCloseConnection(username);
                            break;
                        }

                        sendMessage(message);
                    }
                    break;
                case 0:
                    cout << "Bye." << endl;
                    return 0;
                default:
                    cout << "Insert a valid command." << endl;
            }
        }
    } catch (const exception &e) {
        if(buffer != nullptr) delete[] buffer;
        cout << "Exit due to an error:\n" << endl;
        cerr << e.what() << endl;
        return 0;
    }

    delete[] buffer;
    return 0;
}

void showMenu() {
    cout << endl;
    cout << "1. Online users" << endl;
    cout << "2. Request to talk" << endl;
    cout << "0. Exit" << endl;
}

