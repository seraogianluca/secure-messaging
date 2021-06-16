#include <fstream>
#include <sstream>
#include <iterator>
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

    activeChat(onlineUser an, onlineUser bn){
        a = an;
        b = bn;
    }
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

    bool isUserChatting(string username){
        for(activeChat chat: activeChats) {
            if(chat.a.username.compare(username) == 0 || chat.a.username.compare(username) == 0){
                return true;
            }
        }
        return false;
    }

    onlineUser getUser(string username){
        for (onlineUser user : onlineUsers) {
            if(username.compare(user.username) == 0) {
                return user;
            }
        }
        throw runtime_error("The user is not online");
    }

    onlineUser getUser(int sd){
        for (onlineUser user : onlineUsers) {
            if(user.sd == sd) {
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

void receive(SocketServer *socket, Crypto *crypto, onlineUser sender, vector<unsigned char> &buffer) {
    unsigned char opCode;
    try {
        receive(socket, sender.sd, buffer);
        opCode = buffer.at(0);
        buffer.erase(buffer.begin());
        decrypt(crypto, sender.key_pos, buffer);
        if(buffer.at(0) != opCode) {
            cout << "Message tampered" << endl;
            throw runtime_error("Message tampered");
        }
    } catch(const exception& e) {
        throw;
    }
}

void send(SocketServer *socket, Crypto *crypto, onlineUser receiver, vector<unsigned char> &buffer) {
    unsigned char opCode;
    try {
        opCode = buffer.at(0);
        encrypt(crypto, receiver.key_pos, buffer);
        buffer.insert(buffer.begin(), opCode);
        send(socket, receiver.sd, buffer);
    } catch(const exception& e) {
        throw;
    }
}

void forward(ServerContext ctx, onlineUser sender, onlineUser receiver){
    vector<unsigned char> buffer;
    receive(ctx.serverSocket, ctx.crypto, sender, buffer);
    send(ctx.serverSocket, ctx.crypto, receiver, buffer);
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

void authentication(ServerContext &ctx, int sd, vector<unsigned char> startMessage) {
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

        if(!verification) {
            throw runtime_error("Signature not verified or message not fresh.");
        }
        cout << "Signature verified." << endl;

        // Generate secret
        ctx.crypto->secretDerivation(prvKeyDHServer, pubKeyDHClient, tempBuffer.data());
        ctx.crypto->insertKey(tempBuffer.data(), sd);

        onlineUser user(username, sd);
        ctx.onlineUsers.push_back(user);

        // Send Online Users List

        buffer.clear();
        buffer.push_back(OP_LOGIN);
        for(onlineUser user : ctx.onlineUsers) {
            append(user.username, buffer);
        }

        ctx.crypto->setSessionKey(user.key_pos);

        tempBufferLen = ctx.crypto->encryptMessage(buffer.data(), buffer.size(), tempBuffer.data());
        
        buffer.clear();
        buffer.push_back(OP_LOGIN);
        buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);

        send(ctx.serverSocket, sd, buffer);

    } catch(const exception& e) {
        throw;
    }
}
    
void requestToTalk(ServerContext &ctx, vector<unsigned char> msg, onlineUser sender){
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, NONCE_SIZE> nonce;
    vector<unsigned char> buffer;
    unsigned int tempBufferLen = 0;
    string usernameB;
    onlineUser receiver;
    EVP_PKEY *pubKeyB = NULL;
    EVP_PKEY *pubKeyA = NULL;
    
    try {
        // Receive M1 FROM A
        msg.erase(msg.begin()); //delete the OPCODE in clear
        decrypt(ctx.crypto, sender.key_pos, msg);
        if(msg.at(0) != OP_REQUEST_TO_TALK){
            errorMessage("Error in the initialization of the RTT", buffer);
            send(ctx.serverSocket, ctx.crypto, sender, buffer);
            return;
        }
        msg.erase(msg.begin());
        usernameB = extract(msg);
        if(ctx.isUserChatting(usernameB)){
            errorMessage("User is busy", buffer);
            send(ctx.serverSocket, ctx.crypto, sender, buffer);
            return;
        }
        receiver = ctx.getUser(usernameB);
        extract(msg, nonce);

        // Send M2 TO B
        buffer.push_back(OP_REQUEST_TO_TALK);
        append(sender.username, buffer);
        append(nonce, NONCE_SIZE, buffer);
        send(ctx.serverSocket, ctx.crypto, receiver, buffer);

        // Receive M3 FROM B
        receive(ctx.serverSocket, ctx.crypto, receiver, buffer);
        if(buffer.at(0) == OP_ERROR){
            cout<<"Request to talk refused"<<endl;
            buffer.erase(buffer.begin());
            send(ctx.serverSocket, ctx.crypto, receiver, buffer);
            return;
        } else if(buffer.at(0) != OP_REQUEST_TO_TALK){
            errorMessage("Error in the initialization of the RTT", buffer);
            send(ctx.serverSocket, ctx.crypto, receiver, buffer);
            return;
        }

        //Send M4 TO A
        ctx.crypto->readPublicKey(usernameB, pubKeyB);
        tempBufferLen = ctx.crypto->serializePublicKey(pubKeyB, tempBuffer.data());
        append(tempBuffer, tempBufferLen, buffer);
        printBuffer(buffer);
        send(ctx.serverSocket, ctx.crypto, sender, buffer);

        // Receive M5 FROM A
        receive(ctx.serverSocket, ctx.crypto, sender, buffer);
        if(buffer.at(0) != OP_ERROR){
            errorMessage("Error in request to talk", buffer);
            cout<<"Error in request to talk"<<endl;
            send(ctx.serverSocket, ctx.crypto, receiver, buffer);
            errorMessage("Error in request to talk", buffer);
            send(ctx.serverSocket, ctx.crypto, receiver, buffer);
            return;
        }

        //Send M6 TO B
        ctx.crypto->readPublicKey(sender.username, pubKeyA);
        tempBufferLen = ctx.crypto->serializePublicKey(pubKeyA, tempBuffer.data());
        append(tempBuffer, tempBufferLen, buffer);
        send(ctx.serverSocket, ctx.crypto, receiver, buffer);

        //Receive M7 FROM B AND FORWORD TO A
        receive(ctx.serverSocket, ctx.crypto, receiver, buffer);
        if(buffer.at(0) == OP_REQUEST_TO_TALK){
            send(ctx.serverSocket, ctx.crypto, sender, buffer);
            activeChat a(sender, receiver);
            ctx.activeChats.push_back(a);
        } else {
            send(ctx.serverSocket, ctx.crypto, sender, buffer);
            cout<<"Error during the finalizing of the request to talk"<<endl;
        }
    } catch(const exception& e) {
        throw;
    }  
}