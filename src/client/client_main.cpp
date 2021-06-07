#include "include/client.h"

int showMenu();

int main(int argc, char *const argv[]) {
    unsigned char *greetingMessage;
    int menuOption;
    string input;
    string user;
    string username;
    string message;

    try {
        
        cout << "\n-------Authentication-------" << endl;
        socketClient.makeConnection();

        greetingMessage = new unsigned char[MAX_MESSAGE_SIZE ];
        socketClient.receiveMessage(socketClient.getMasterFD(), greetingMessage);
        cout << "Connection confirmed: " << greetingMessage << endl;
        delete[] greetingMessage;
        username = readFromStdout("Insert username: ");
        authentication(username);
        keyEstablishment(0);
        crypto.setSessionKey(0);
        cout << "-----------------------------" << endl << endl;
        receiveOnlineUsersList();
        
        while (true) {
            menuOption = showMenu();

            switch(menuOption) {
                case 1:
                    break;
                case 2:
                    cout << "\n-------Request to talk-------" << endl;
                    user = readFromStdout("Insert username: ");
                    sendRequestToTalk(user, username, username);
                    cout << "-----------------------------" << endl;
                    while(true){
                        message = readFromStdout(username + ": ");
                        sendMessage(message);
                        message = receiveMessage();
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
                    cout << "\n-------Waiting for request to talk-------" << endl;
                    cout << "Waiting for request to talk" << endl;
                    receiveRequestToTalk(username, username); //REFACTOR
                    cout << "------------------------------------------" << endl;
                    while(true){
                        message = receiveMessage();
                        cout << "lore" << ": " << message << endl;;
                        message = readFromStdout(username + ": ");
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
        delete[] greetingMessage;
        cerr << e.what() << endl;
    }

    return 0;
}

int showMenu() {
    size_t value;

    cout << endl;
    cout << "1. Online users" << endl;
    cout << "2. Request to talk" << endl;
    cout << "3. Send a message" << endl;
    cout << "4. Wait for Request for Talk" << endl;
    cout << "0. Exit" << endl;
    cout << "> ";
    cin >> value;
    cin.ignore();
    return value;
}

