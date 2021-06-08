#include "include/client.h"
#include <sys/select.h>

void showMenu();
void insertCommand();

int main(int argc, char *const argv[]) {
    unsigned char *buffer = NULL;
    string input;
    string user;
    string username;
    string password;
    string message;

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
        keyEstablishment(0);
        crypto.setSessionKey(0);
        cout << "-----------------------------" << endl << endl;

        receiveOnlineUsersList();    
        while (true) {
            fd_set fds;
            int maxfd;
            int option = -1;

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

            if (FD_ISSET(socketClient.getMasterFD(), &fds)) option = 4;

            

            switch(option) {
                case 1:
                    askOnlineUserList();
                    receiveOnlineUsersList();
                    break;
                case 2:
                    cout << "\n-------Request to talk-------" << endl; 
                    user = readFromStdout("Insert username: ");
                    sendRequestToTalk(user, username, password);
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
                            cout << user << " closed the chat." << endl;
                            break;
                        }
                        cout << user << ": " << message << endl;
                    }
                    break;
                case 3:
                    cout << "> ";
                    getline(cin, input);
                    sendMessage(OP_MESSAGE, 1, (unsigned char*)input.c_str(), input.length() + 1);
                    cout << "Message sent." << endl;
                    break;
                case 4:
                    cout << "\n-------Received request to talk-------" << endl;
                    receiveRequestToTalk(username, password, user);
                    cout << "------------------------------------------" << endl;
                    while(true){
                        message = receiveMessage();
                        if(message.compare("!deh") == 0){
                            cout << user << " closed the chat." << endl;
                            crypto.removeKey(1);
                            crypto.setSessionKey(0);
                            break;
                        }
                        cout << user << ": " << message << endl;
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
    }
    catch (const exception &e) {
        if(buffer != nullptr) delete[] buffer;
        cerr << e.what() << endl;
        return 0;
    }

    if(buffer != nullptr) delete[] buffer;

    return 0;
}

void showMenu() {
    cout << endl;
    cout << "1. Online users" << endl;
    cout << "2. Request to talk" << endl;
    cout << "3. Send a message" << endl;
    cout << "4. Wait for Request for Talk" << endl;
    cout << "0. Exit" << endl;
}

