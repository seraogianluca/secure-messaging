#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include "include/client.h"
#include "include/socket.h"

int showMenu();

int main(int argc, char* const argv[]) {
    try {
        SocketClient socketClient = SocketClient(SOCK_STREAM);
        socketClient.makeConnection();
        string greetingMessage = socketClient.receiveMessage(socketClient.getMasterFD());
        cout << "Connection confirmed: " << greetingMessage  << endl;
        while(true) {
            int value = showMenu();
            if(value == 1) {
                socketClient.sendMessage("1Hey there", socketClient.getMasterFD());
                string message = socketClient.receiveMessage(socketClient.getMasterFD());
                cout << "Message Received: " << message << endl;
            } else if(value == 2) {

            } else {
                cout << "Exit from the application." << endl;
                return 0;
            }
        }
    } catch(const exception& e) {
        cerr << e.what() << '\n';
    }
    return 0;
}

int showMenu() {
    cout << endl;
    cout << "1. Send a message" << endl;
    cout << "0. Exit" << endl;
    cout << "--> ";
    size_t value;
    cin >> value;
    return value;
}