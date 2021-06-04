#include "include/client.h"

int showMenu();

int main(int argc, char *const argv[]) {
    unsigned char *greetingMessage;
    int menuOption;
    string input;
    string user;

    try {
        
        cout << "\n-------Authentication-------" << endl;
        socketClient.makeConnection();

        greetingMessage = new unsigned char[MAX_MESSAGE_SIZE ];
        socketClient.receiveMessage(socketClient.getMasterFD(), greetingMessage);
        cout << "Connection confirmed: " << greetingMessage << endl;
        delete[] greetingMessage;

        authentication();
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
                    user = readFromStdout("Insert username: ");
                    sendRequestToTalk(user);
                    break;
                case 3:
                    cout << "> ";
                    getline(cin, input);
                    sendMessage(OP_MESSAGE, 1, (unsigned char*)input.c_str(), input.length() + 1);
                    cout << "Message sent." << endl;
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
    cout << "0. Exit" << endl;
    cout << "> ";
    cin >> value;
    cin.ignore();
    return value;
}

