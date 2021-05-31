#include "include/client.h"

int showMenu();

int main(int argc, char *const argv[]) {
    try {
        string password = readFromStdout("Insert password: ");
        socketClient.makeConnection();
        
        //TODO: to check
        unsigned char *greetingMessage = new unsigned char[MAX_MESSAGE_SIZE ];
        socketClient.receiveMessage(socketClient.getMasterFD(), greetingMessage);
        cout << "Connection confirmed: " << greetingMessage << endl;
        delete[] greetingMessage;

        while (true) {
            int value = showMenu();
            string input;

            switch(value) {
                case 1:
                    keyEstablishment();
                    break;
                case 2:
                    cout << "\n-------Authentication-------" << endl;
                    authentication();
                    cout << "-----------------------------" << endl << endl;
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
        cerr << e.what() << endl;
    }

    return 0;
}

int showMenu() {
    cout << endl;
    cout << "2. Authentication" << endl;
    cout << "3. Send a message" << endl;
    cout << "0. Exit" << endl;
    cout << "--> ";
    size_t value;
    cin >> value;
    cin.ignore();
    return value;
}

