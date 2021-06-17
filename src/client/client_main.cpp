#include "include/client.h"
#include <sys/select.h>

void showMenu();
void insertCommand();

int main(int argc, char *const argv[]) {
    ClientContext context;
    vector<unsigned char> buffer;
    string username;
    string password;
    fd_set fds;
    int maxfd;
    int option = -1;
   
    try {
        cout << "\n-------Authentication-------" << endl;
        context.clientSocket->makeConnection();
        receive(context.clientSocket, buffer);
        cout << "Connection confirmed: " << buffer.data() << endl;
        buffer.clear();
        username = readFromStdout("Insert username: ");
        password = readPassword();
        context.username = username;
        context.crypto->readPrivateKey(username, password, context.prvKeyClient);
        authentication(context);
        cout << "-----------------------------" << endl << endl;

        while (true) {
            maxfd = (context.clientSocket->getMasterFD() > STDIN_FILENO) ? context.clientSocket->getMasterFD() : STDIN_FILENO;
            FD_ZERO(&fds);
            FD_SET(context.clientSocket->getMasterFD(), &fds); 
            FD_SET(STDIN_FILENO, &fds); 

            showMenu();
            cout << "--> ";
            cout.flush();  
            
            select(maxfd+1, &fds, NULL, NULL, NULL); 

            if(FD_ISSET(0, &fds)) {  
                cin >> option;
                cin.ignore();
            }

            if(FD_ISSET(context.clientSocket->getMasterFD(), &fds)) {
                receive(context.clientSocket, buffer);
                
                if(buffer.at(0) == OP_REQUEST_TO_TALK) {
                    cout << "\n-------Received request to talk-------" << endl;
                    receiveRequestToTalk(context, buffer);
                    buffer.clear();
                    cout << "---------------------------------------" << endl;
                }
            }

            switch(option) {
                case 1:
                    cout << "\n--------- Online User List ---------" << endl;
                    onlineUsersListRequest(context);
                    cout << "-------------------------------------" << endl;
                    break;
                case 2:
                    cout << "\n------------Request to talk-----------" << endl;
                    sendRequestToTalk(context);
                    cout << "---------------------------------------" << endl;
                    break;
                case 0:
                    cout << "Bye." << endl;
                    buffer.clear();
                    buffer.insert(buffer.begin(), OP_LOGOUT);
                    append("logout", buffer);
                    send(context.clientSocket, context.crypto, buffer);
                    return 0;
                default:
                    cout << "Insert a valid command." << endl;
            }
        }
    } catch (const exception &e) {
        cout << "Exit due to an error:\n" << endl;
        cerr << e.what() << endl;
        return 0;
    }
    return 0;
}

void showMenu() {
    cout << endl;
    cout << "1. Online users" << endl;
    cout << "2. Request to talk" << endl;
    cout << "0. Exit" << endl;
}

