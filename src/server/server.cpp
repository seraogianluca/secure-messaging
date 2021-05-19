#include "include/server.h"

void Server::sendMessage(string message) {
    int sock = 0;
    struct sockaddr_in serv_addr;

    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\n Socket creation error \n" << endl;
        throw "Socket creation error";
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, SERVER, &serv_addr.sin_addr)<=0) {
        throw "\nInvalid address/ Address not supported \n";
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        throw "\nConnection Failed \n";
    }
    send(sock, message.c_str(), message.length(), 0 );
    if(read(sock,buffer,1024) == -1) {
        // TODO: controllare se vogliamo usare errno.h
        throw "\nError in response\n";
    }
}

string Server::readMessage() {
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
       
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        throw "socketFailed";
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        throw "setsockopt";
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
       
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        throw "bind failed";
    }
    if (listen(server_fd, 3) < 0) {
        throw "listen";
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        throw "accept";
    }
    valread = read(new_socket, buffer, 1024);
    return string(buffer);
}