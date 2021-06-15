#include <fstream>
#include <sstream>
#include <fstream>
#include <iterator>
#include <vector>
#include <array>
#include "crypto.h"
#include "socket.h"


struct onlineUser {
    string username;
    int sd;
    unsigned int key_pos;
};

struct activeChat {
    onlineUser a;
    onlineUser b;
};

struct serverContext {
    vector<onlineUser> onlineUsers;
    vector<activeChat> activeChats;
    SocketServer *serverSocket;
    Crypto *crypto;

    serverContext() {
        serverSocket = new SocketServer(SOCK_STREAM);
        crypto = new Crypto();
    }

    void deleteUser(onlineUser user) {
        bool found = false;
        int i = 0;

        for (onlineUser usr : onlineUsers) {
            if (usr.username.compare(user.username) == 0){
                found = true;
                break;
            }
            i++;
        }

        if (found && i < onlineUsers.size()) {
            onlineUsers.erase(onlineUsers.begin() + i);
            return;
        }

        throw runtime_error("User not found");
    }

    void deleteActiveChat(onlineUser user) {
        int i = 0;
        bool found = false;
        for (activeChat chat : activeChats) {
            if(chat.a.username.compare(user.username) == 0 || (chat.b.username.compare(user.username) == 0)) {
                found = true;
                break;
            }
            i++;
        }

        if (found && i < activeChats.size()) {
            activeChats.erase(activeChats.begin() + i);
            return;
        }

        throw runtime_error("Chat not found.");
    }

    onlineUser getUser(string username){
        for (onlineUser user : onlineUsers) {
            if(username.compare(user.username) == 0) {
                return user;
            }
        }

        throw runtime_error("The user is not online");
    }

    onlineUser getReceiver(onlineUser sender) {
        onlineUser receiver;
        for (activeChat chat : activeChats) {
            if(chat.a.username.compare(sender.username) == 0) {
                receiver = chat.b;
                return receiver;
            }
            if (chat.b.username.compare(sender.username) == 0) {
                receiver = chat.a;
                return receiver;
            }
        }

        throw runtime_error("Receiver not found.");
    }
};

void receive(SocketServer socket, int sd, vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> msg;
    unsigned int size;

    size = socket.receiveMessage(sd, msg.data());
    buffer.insert(buffer.end(), msg.begin(), msg.begin() + size);
}

void send(SocketServer socket, int sd, vector<unsigned char> &buffer) {
    socket.sendMessage(sd, buffer.data(), buffer.size());
    buffer.clear();
}

// Utility
unsigned int readPassword(unsigned char* username, unsigned int usernameLen, unsigned char* password) {
    ifstream file("./resources/credentials.txt");
    string line;
    string delimiter = " ";
    string pwd;
    string usn;
    const char* usernameChar = (const char*) username;
    
    while (getline(file, line)) {
        usn = line.substr(0, line.find(delimiter));
        if(usn.compare(usernameChar) == 0) {
            pwd = line.substr(line.find(delimiter) + 1);
            for (int i = 0; i < pwd.length()/2; i++) {
                string substr = pwd.substr(i*2, 2);
                unsigned char v = stoi(substr, 0, 16);
                password[i] = v;
            }
            return pwd.length()/2;
        }
    }
    return 0;
}