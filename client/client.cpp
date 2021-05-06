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

int main(int argc, char* const argv[]) {

    cout << "Welcome in the Secure-Messaging client" << endl;

    int sock = 0, valread;
    struct sockaddr_in serv_addr;

    string message = readMessage();

    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\n Socket creation error \n" << endl;
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, LOCALHOST.c_str(), &serv_addr.sin_addr)<=0) {
        cerr << "\nInvalid address/ Address not supported \n" << endl;
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "\nConnection Failed \n" << endl;
        return -1;
    }
    send(sock , message.c_str() , message.length() , 0 );
    cout << "Hello message sent\n" << endl;
    valread = read( sock , buffer, 1024);
    cout << buffer << endl;
    return 0;
}


string readMessage() {
    string message;
    cout << "Write here your message >> ";
    getline(cin, message);
    if (message.length() > MESSAGE_MAX_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}