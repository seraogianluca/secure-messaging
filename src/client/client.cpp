#include "include/client.h"

int Client::login(string pwd) {
    // Generate nonce
    // Check if the argument is null in the constructor
    Crypto crypto((unsigned char*)"qualcosa"); // Refactor
    string nonce_client = crypto.generateNonce();
    cout << "Nonce: " << nonce_client << endl;
    try {
        string helloMessage = "hello" + nonce_client;
        sendMessage(helloMessage);
        cout << "Message sent" << endl;
        string message_received = readMessage();
        cout << "Received Message: " << message_received << endl;
        string nonce_received = extractClientNonce(message_received, nonce_client.length());
        string nonce_server = extractServerNonce(message_received, nonce_client.length());
        if(nonce_client.compare(nonce_received) != 0) {
            throw "Login Error: The freshness of the message is not confirmed";
        }
        cout << "Freshness Confirmed" << endl;
        string requestCertificateMessage = (char)OP_CERTIFICATE_REQUEST + nonce_server + nonce_client;
        sendMessage(requestCertificateMessage);
        string certificate = readMessage();
        // bool verification = verifyCertificate();
        return 0;
    } catch(const runtime_error& ex){
        string message = "**Login Error: " + string(ex.what());
        throw runtime_error(message);
    }
}

void Client::sendMessage(string message) {
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
        throw runtime_error("\nInvalid address/ Address not supported \n");
    }
    int connect_ret = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (connect_ret < 0) {
        throw runtime_error("Connection Failed");
    }
    send(sock, message.c_str(), message.length(), 0 );
}

string Client::convert(unsigned char* value) {
    string s;
    for (size_t i = 0; i < sizeof(value); i++){
        s.append(1, static_cast<char>(value[i]));
    }
    return s;
}

string Client::readMessage() {
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

bool Client::verifyCertificate() {
    //TODO: implement
    return true;
}

string Client::extractClientNonce(string message, size_t clientNonceLen) {
    if (message.length() < 5 + clientNonceLen) throw runtime_error("Uncorrect format of the message received");
    string clientNonce = message.erase(0, 5); // remove the hello message
    return clientNonce.substr(0, clientNonceLen - 1);
}

string Client::extractServerNonce(string message, size_t clientNonceLen) {
    if (message.length() < 5 + clientNonceLen) throw runtime_error("Uncorrect format of the message received");
    string serverNonce = message.erase(0, 5); // remove the hello message
    return serverNonce.erase(0, clientNonceLen);
}