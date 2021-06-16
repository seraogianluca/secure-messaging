#include <fstream>
#include <sstream>
#include <fstream>
#include <iterator>
#include <vector>
#include <array>
#include "socket.h"
#include "utils.h"


struct onlineUser {
    string username;
    int sd;
    unsigned int key_pos;

    onlineUser(){}

    onlineUser(string usr, int _sd) {
        username = usr;
        sd = _sd;
        key_pos = _sd;
    }
};

struct activeChat {
    onlineUser a;
    onlineUser b;
};

struct ServerContext {
    vector<onlineUser> onlineUsers;
    vector<activeChat> activeChats;
    SocketServer *serverSocket;
    Crypto *crypto;

    ServerContext() {
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

void receive(SocketServer *socket, int sd, vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> msg;
    unsigned int size;

    size = socket->receiveMessage(sd, msg.data());
    buffer.insert(buffer.end(), msg.begin(), msg.begin() + size);
}

void send(SocketServer *socket, int sd, vector<unsigned char> &buffer) {
    socket->sendMessage(sd, buffer.data(), buffer.size());
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

void authentication(ServerContext ctx, int sd, vector<unsigned char> startMessage) {
    vector<unsigned char> buffer;
    vector<unsigned char> signature;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    array<unsigned char, NONCE_SIZE> nonceServer;
    array<unsigned char, NONCE_SIZE> nonceClient;
    unsigned int tempBufferLen;
    unsigned int pubKeyDHBufferLen;
    EVP_PKEY *pubKeyClient = NULL;
    EVP_PKEY *prvKeyServer = NULL;
    EVP_PKEY *prvKeyDHServer = NULL;
    EVP_PKEY *pubKeyDHClient = NULL;
    X509 *cert;
    try {

        // Receive M1
        ctx.crypto->generateNonce(nonceServer.data());
        
        if(startMessage[0] != OP_LOGIN) {
            throw runtime_error("Opcode not valid!");
        }
        startMessage.erase(startMessage.begin());

        // Extract username
        string username = extract(startMessage);
        // Extract nc
        extract(startMessage, nonceClient);

        // Building M2
        buffer.push_back(OP_LOGIN);

        // Add certificate buffer to message
        ctx.crypto->readPrivateKey(prvKeyServer);
        ctx.crypto->loadCertificate(cert, "server_cert");
        tempBufferLen = ctx.crypto->serializeCertificate(cert, tempBuffer.data());
        append(tempBuffer, tempBufferLen, buffer); 

        // Add DH public key to message
        ctx.crypto->keyGeneration(prvKeyDHServer);
        pubKeyDHBufferLen = ctx.crypto->serializePublicKey(prvKeyDHServer, pubKeyDHBuffer.data());
        append(pubKeyDHBuffer, pubKeyDHBufferLen, buffer);

        append(nonceServer, NONCE_SIZE, buffer);

        // Add digital signature
        signature.push_back(OP_LOGIN);
        signature.insert(signature.end(), pubKeyDHBuffer.begin(), pubKeyDHBuffer.data() + pubKeyDHBufferLen);
        signature.insert(signature.end(), nonceClient.begin(), nonceClient.end());
        tempBufferLen = ctx.crypto->sign(signature.data(), signature.size(), tempBuffer.data(), prvKeyServer);
        append(tempBuffer, tempBufferLen, buffer);

        // Sending M2
        send(ctx.serverSocket, sd, buffer);
        cout << "M2 sent correctly" << endl;

        // Receiving M3
        receive(ctx.serverSocket, sd, buffer);
        if(buffer[0] != OP_LOGIN) {
            throw runtime_error("Opcode not valid");
        }
        buffer.erase(buffer.begin());
        pubKeyDHBufferLen = extract(buffer, pubKeyDHBuffer);
        ctx.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHBufferLen, pubKeyDHClient);

        // Verify Signature and nonce
        tempBufferLen = extract(buffer, tempBuffer);
        
        signature.clear();
        signature.push_back(OP_LOGIN);
        signature.insert(signature.end(), pubKeyDHBuffer.begin(), pubKeyDHBuffer.begin() + pubKeyDHBufferLen);
        signature.insert(signature.end(), nonceServer.begin(), nonceServer.end());

        ctx.crypto->readPublicKey(username, pubKeyClient);

        bool verification = ctx.crypto->verifySignature(tempBuffer.data(), tempBufferLen, signature.data(), signature.size(), pubKeyClient);

        // TODO: rimettere il !
        if(verification) {
            throw runtime_error("Signature not verified or message not fresh.");
        }

        cout << "Signature verified." << endl;

        // Generate secret
        ctx.crypto->secretDerivation(prvKeyDHServer, pubKeyDHClient, tempBuffer.data());
        printBuffer("O' Secret derivat: ", tempBuffer, DIGEST_LEN);
        ctx.crypto->insertKey(tempBuffer.data(), sd);

        onlineUser user(username, sd);
        ctx.onlineUsers.push_back(user);

        cout << "Created a new online user" << endl;

        // Send Online Users List

        buffer.clear();
        buffer.push_back(OP_LOGIN);
        for(onlineUser user : ctx.onlineUsers) {
            append(user.username, buffer);
        }

        printBuffer("Online users: ", buffer);

        ctx.crypto->setSessionKey(user.key_pos);

        tempBufferLen = ctx.crypto->encryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

        printBuffer("Encrypted stuff: ", tempBuffer, tempBufferLen);
        
        buffer.clear();
        buffer.push_back(OP_LOGIN);
        buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);

        printBuffer("Online users encrypted: ", buffer);

        send(ctx.serverSocket, sd, buffer);

    } catch(const exception& e) {
        throw;
    }
    
}