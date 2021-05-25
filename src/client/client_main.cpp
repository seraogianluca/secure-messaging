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
        Crypto c((unsigned char*)"1234567890123456");
        unsigned char msg[] = "Test message";
        unsigned char *ciphertext;
        unsigned char *tag;
        unsigned char *iv;
        unsigned char *dec_msg; 
        int ciphertext_len;
        int plaintext_len = sizeof(msg);
        SocketClient socketClient = SocketClient(SOCK_STREAM);
        Client client = Client();
        socketClient.makeConnection();
        string greetingMessage = socketClient.receiveMessage(socketClient.getMasterFD());
        cout << "Connection confirmed: " << greetingMessage  << endl;
        while(true) {
            int value = showMenu();
            if(value == 1) {
                ciphertext = (unsigned char*)malloc(plaintext_len+TAG_SIZE);
                tag = (unsigned char*)malloc(TAG_SIZE);
                ciphertext_len = c.encryptMessage(msg, 
                                                plaintext_len, 
                                                ciphertext, 
                                                tag);
                cout << "Ciphertext:" << endl;
                BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
                cout << "Tag:" << endl;
                BIO_dump_fp(stdout, (const char*)tag, TAG_SIZE);
                string msg_enc = "1"+client.convert(ciphertext);
                socketClient.sendMessage(msg_enc, socketClient.getMasterFD());
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