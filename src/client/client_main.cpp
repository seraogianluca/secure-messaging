#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

#define PORT 8080

using namespace std;

const string LOCALHOST = "127.0.0.1";
const int MESSAGE_MAX_SIZE = 10000;

string readMessage();
int sendMessage(string message);

int main(int argc, char* const argv[]) {

    cout << "Welcome in the Secure-Messaging client" << endl;

    string message = readMessage();

    int res = sendMessage(message);
    if (res >= 0) {
        cout << "Message sent\n" << endl;
    } 

    return 0;
}


string readMessage() {
    string message;
    cout << "Write here your message >> ";
    getline(cin, message);
    if(!cin) {
        cerr << "Error in standard input." << endl;

    }
    if (message.length() > MESSAGE_MAX_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}
