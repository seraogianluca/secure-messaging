#include "socket.h"
#include "crypto.h"
#include <iterator>
#include <array>
#include <cstring>
#include <algorithm>
#include <termios.h>
#include "utils.h"

struct clientContext {
    SocketClient *clientSocket;
    Crypto *crypto;

    clientContext() {
        clientSocket = new SocketClient(SOCK_STREAM);
        crypto = new Crypto();
    }
};

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

string readPassword() {
    string password;
    cout << "Insert password: ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

string readFromStdout(string message) {
    string value;
    cout << message;
    
    do {
        getline(cin, value);
        if(value.length() == 0) {
            cout << "Insert at least a character." << endl;
            cout << message;
        }
    } while (value.length() == 0);
    
    return value;
}