#include "include/server.h"

void Server::handleLogin() {
    try {
        Crypto crypto((unsigned char*)"qualcosa"); // Refactor
        string message = readMessage();
        cout << "Message Received: " << message << endl;
        string serverNonce = crypto.generateNonce();
        cout << "Nonce Generated: " << serverNonce << endl;
        string clientNonce = extractClientNonce(message);
        cout << "Client Nonce: " << clientNonce << endl;
        string helloMessage = "hello" + clientNonce + serverNonce;
        sendMessage(helloMessage);
        cout << "Hello Message sent" << endl;
    } catch(const runtime_error& e) {
        string message = "Login Error: " + string(e.what());
        throw runtime_error(message);
    }
}

void Server::sendMessage(string message) {
    int sock = 0;
    struct sockaddr_in serv_addr;

    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\n Socket creation error \n" << endl;
        throw runtime_error("Socket creation error");
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, SERVER, &serv_addr.sin_addr)<=0) {
        throw runtime_error("Invalid address/ Address not supported");
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        throw runtime_error("Connection Failed");
    }
    send(sock, message.c_str(), message.length(), 0 );
}

string Server::readMessage() {
    int TCP_SOCKET, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
       
    // Creating socket file descriptor
    if ((TCP_SOCKET = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        throw runtime_error("socketFailed");
    }

    //Forcefully attaching socket to the port 8080
    int setSocketOpt = setsockopt(TCP_SOCKET, SOL_SOCKET, 
        SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (setSocketOpt) {
        cerr << setSocketOpt << endl;
        throw runtime_error("Problem setting the socket options");
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
       
    // Forcefully attaching socket to the port 8080
    if (bind(TCP_SOCKET, (struct sockaddr *)&address, sizeof(address)) < 0) {
        throw runtime_error("bind failed");
    }
    if (listen(TCP_SOCKET, 3) < 0) {
        throw runtime_error("listen");
    }
    if ((new_socket = accept(TCP_SOCKET, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        throw runtime_error("accept");
    }
    valread = read(new_socket, buffer, 1024);
    return string(buffer);
}

string Server::extractClientNonce(string message) {
    if (message.length() < 5) throw runtime_error("Uncorrect format of the message received");
    return message.erase(0, 5);
}