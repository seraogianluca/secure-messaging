#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include "include/client.h"
#include "include/socket.h"

using namespace std;

string readMessage();
int sendMessage(string message);

int main(int argc, char* const argv[]) {
    try {
        SocketClient socketClient = SocketClient(SOCK_STREAM);
        socketClient.makeConnection();
        string greetingMessage = socketClient.receiveMessage();
        cout << "Received a greeting message to confirm the connection: " << greetingMessage  << endl;
        socketClient.sendMessage("Saluti");
        string message = socketClient.receiveMessage();
        cout << message << endl;
    } catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
    return 0;
}
