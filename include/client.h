#include <cstring>
#include <termios.h>
#include "socket.h"
#include "crypto.h"
#include "utils.h"

struct ClientContext {
    vector<string> onlineUsers;
    EVP_PKEY *prvKeyClient;
    SocketClient *clientSocket;
    Crypto *crypto;

    ClientContext() {
        clientSocket = new SocketClient(SOCK_STREAM);
        crypto = new Crypto();
    }

    void addOnlineUser(string username) {
        onlineUsers.push_back(username);
    }

    void clearOnlineUsers() {
        onlineUsers.clear();
    }
};

void receive(SocketClient *socket, vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> msg;
    unsigned int size;

    size = socket->receiveMessage(socket->getMasterFD(), msg.data());
    buffer.insert(buffer.end(), msg.begin(), msg.begin() + size);
}

void send(SocketClient *socket, vector<unsigned char> &buffer) {
    socket->sendMessage(socket->getMasterFD(), buffer.data(), buffer.size());
    buffer.clear();
}

void encrypt(Crypto *crypto, unsigned int key, vector<unsigned char> &buffer) {
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    unsigned int tempBufferLen;

    crypto->setSessionKey(SERVER_SECRET);
    tempBufferLen = crypto->encryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

    buffer.clear();
    buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
}

void decrypt(Crypto *crypto, unsigned int key, vector<unsigned char> &buffer) {
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    unsigned int tempBufferLen;

    crypto->setSessionKey(SERVER_SECRET);
    tempBufferLen = crypto->decryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

    buffer.clear();
    buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
}

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

string readPassword() {
    string password;
    cout << "Insert password: ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

string readFromStdout(string message) {
    string value;
    cout << message;
    
    do {
        getline(cin, value);
        if(value.length() == 0) {
            cout << "Insert at least a character." << endl;
            cout << message;
        }
    } while (value.length() == 0);
    
    return value;
}

void authentication(ClientContext ctx, string username, EVP_PKEY *prvKeyClient) {
    vector<unsigned char> buffer;
    vector<unsigned char> signature;
    array<unsigned char, NONCE_SIZE> nonceClient;
    array<unsigned char, NONCE_SIZE> nonceServer;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    EVP_PKEY *pubKeyServer;
    EVP_PKEY *prvKeyDHClient;
    EVP_PKEY *pubKeyDHServer;
    X509 *cert;
    unsigned int tempBufferLen;
    unsigned int pubKeyDHServerLen;
    unsigned int pubKeyDHClientLen;

    try {
        // M1: 0, username, nc
        ctx.crypto->generateNonce(nonceClient.data());
        buffer.push_back(OP_LOGIN);
        append(username, buffer);
        append(nonceClient, NONCE_SIZE, buffer);
        send(ctx.clientSocket, buffer);

        // Receive M2: 0, cert, g^b mod p, ns, <0, g^b mod p, nc > pKs
        receive(ctx.clientSocket, buffer);
        if (buffer.at(0) != OP_LOGIN) {
            // TODO: Handle Error!
            throw runtime_error("Opcode not valid");
        }
        buffer.erase(buffer.begin());
        tempBufferLen = extract(buffer, tempBuffer);
        ctx.crypto->deserializeCertificate(tempBufferLen, tempBuffer.data(), cert);

        if(!ctx.crypto->verifyCertificate(cert)) {
            // TODO: 
            throw runtime_error("Certificate not valid.");
        }

        ctx.crypto->getPublicKeyFromCertificate(cert, pubKeyServer);

        pubKeyDHServerLen = extract(buffer, pubKeyDHBuffer);
        extract(buffer, nonceServer);
        tempBufferLen = extract(buffer, tempBuffer);

        signature.push_back(OP_LOGIN);
        signature.insert(signature.end(), pubKeyDHBuffer.begin(), pubKeyDHBuffer.begin() + pubKeyDHServerLen);
        signature.insert(signature.end(), nonceClient.begin(), nonceClient.end());

        bool signatureVerification = ctx.crypto->verifySignature(tempBuffer.data(), tempBufferLen, signature.data(), signature.size(), pubKeyServer);
        if(!signatureVerification) {
            // TODO: Send Message to other client
            throw runtime_error("Sign verification failed");
        }

        ctx.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHServerLen, pubKeyDHServer);

        // Send M3: 0, g^a mod p, ns, < 0, g^a mod b,  ns>
        buffer.clear();
        buffer.push_back(OP_LOGIN);

        ctx.crypto->keyGeneration(prvKeyDHClient);
        pubKeyDHClientLen = ctx.crypto->serializePublicKey(prvKeyDHClient, pubKeyDHBuffer.data());
        append(pubKeyDHBuffer, pubKeyDHClientLen, buffer);

        signature.clear();
        signature.push_back(OP_LOGIN);
        signature.insert(signature.end(), pubKeyDHBuffer.begin(), pubKeyDHBuffer.begin() + pubKeyDHClientLen);
        signature.insert(signature.begin(), nonceServer.begin(), nonceServer.end());

        tempBufferLen = ctx.crypto->sign(signature.data(), signature.size(), tempBuffer.data(), prvKeyClient);
        
        append(tempBuffer, tempBufferLen, buffer);

        send(ctx.clientSocket, buffer);

        // Receive M4: 
        receive(ctx.clientSocket, buffer);
        if (buffer.at(0) != OP_LOGIN) {
            // TODO: Handle Error!
            throw runtime_error("Authentication Failed");
        }
        buffer.erase(buffer.begin());
        cout << "Authentication succeeded" << endl;
        
        ctx.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHServerLen, pubKeyDHServer);
        ctx.crypto->secretDerivation(prvKeyDHClient, pubKeyDHServer, tempBuffer.data());
        ctx.crypto->insertKey(tempBuffer.data(), SERVER_SECRET);

        ctx.crypto->setSessionKey(SERVER_SECRET);
        tempBufferLen = ctx.crypto->decryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

    } catch(const exception& e) {
        throw;
    }
}

void receiveRequestToTalk(ClientContext ctx, vector<unsigned char> msg) {
    array<unsigned char, NONCE_SIZE> nonce;
    array<unsigned char, NONCE_SIZE> peerNonce;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    vector<unsigned char> buffer;
    vector<unsigned char> signature;
    unsigned int tempBufferLen = 0;
    EVP_PKEY *keyDH = NULL;
    string peerUsername;
    string input;
    bool accepted = false;
    try {
        // Receive request
        //TODO: decrypt function
        tempBufferLen = ctx.crypto->decryptMessage(msg.data(), msg.size(), tempBuffer.data());

        if(tempBuffer.at(0) != OP_REQUEST_TO_TALK) {
            errorMessage("Request to talk failed", buffer);
            send(ctx.clientSocket, buffer);
            throw runtime_error("Request to talk failed");
        }

        // Get peer username
        buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
        buffer.erase(buffer.begin());
        peerUsername = extract(buffer);
        cout << peerUsername << " sent you a request to talk" << endl;

        // Accept or refuse request
        cout << "Do you want to accept the request? (y/n):" << endl;
        do {
            getline(cin, input);
            if(input.length() == 0){
                cout << "Insert at least a character." << endl;
            } else if(input.compare("y") == 0) {
                cout << "Request accepted" << endl;
                accepted = true;
                break;
            } else if (input.compare("n") == 0) {
                cout << "Request refused" << endl;
                accepted = false;
                break;
            } else {
                cout << "Insert a valid answer" << endl;
            }       
        } while (input.length() == 0);

        if(accepted) {
            extract(buffer, peerNonce);
        } else {
            buffer.clear();
            errorMessage("Request to talk refused", buffer);
            send(ctx.clientSocket, buffer);
            cout << "Request to talk refused" << endl;
            return;
        }

        // Send nonce and DH public key
        ctx.crypto->generateNonce(nonce.data());
        ctx.crypto->keyGeneration(keyDH);

        buffer.clear();
        buffer.push_back(OP_REQUEST_TO_TALK);

        tempBufferLen = ctx.crypto->serializePublicKey(keyDH, tempBuffer.data());
        append(tempBuffer, tempBufferLen, buffer);
        append(nonce, NONCE_SIZE, buffer);

        signature.insert(signature.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
        signature.insert(signature.end(), peerNonce.begin(), peerNonce.end());
        tempBufferLen = ctx.crypto->sign(signature.data(), signature.size(), tempBuffer.data(), ctx.prvKeyClient);
        append(tempBuffer, tempBufferLen, buffer);

        encrypt(ctx.crypto, SERVER_SECRET, buffer);
        send(ctx.clientSocket, buffer);

    } catch(const exception& e) {
        throw;
    }
    
}