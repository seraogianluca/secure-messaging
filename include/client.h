#include <cstring>
#include <termios.h>
#include "socket.h"
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

    try {
        size = socket->receiveMessage(socket->getMasterFD(), msg.data());
        buffer.insert(buffer.end(), msg.begin(), msg.begin() + size);
    } catch(const exception& e) {
        throw;
    }
}

void send(SocketClient *socket, vector<unsigned char> &buffer) {
    try {
        socket->sendMessage(socket->getMasterFD(), buffer.data(), buffer.size());
        buffer.clear();
    } catch(const exception& e) {
        throw;
    }
}

void receive(SocketClient *socket, Crypto *crypto, vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> msg;
    unsigned char opCode;
    unsigned int size;

    try {
        size = socket->receiveMessage(socket->getMasterFD(), msg.data());
        buffer.insert(buffer.end(), msg.begin(), msg.begin() + size);

        opCode = buffer.at(0);
        buffer.erase(buffer.begin());
        decrypt(crypto, SERVER_SECRET, buffer);

        if(buffer.at(0) != opCode) {
            cout << "Message tampered" << endl;
            throw runtime_error("Message tampered");
        }
    } catch(const exception& e) {
        throw;
    }
}

void send(SocketClient *socket, Crypto *crypto, vector<unsigned char> &buffer) {
    unsigned char opCode;
    try {
        opCode = buffer.at(0);

        encrypt(crypto, SERVER_SECRET, buffer);
        buffer.insert(buffer.begin(), opCode);

        socket->sendMessage(socket->getMasterFD(), buffer.data(), buffer.size());
        buffer.clear();
    } catch(const exception& e) {
        throw;
    }
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
    array<unsigned char, MAX_MESSAGE_SIZE> keyBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> keyBufferDH;
    vector<unsigned char> buffer;
    vector<unsigned char> signature;
    unsigned int tempBufferLen = 0;
    unsigned int keyBufferLen = 0;
    unsigned int keyBufferDHLen = 0;
    EVP_PKEY *keyDH = NULL;
    EVP_PKEY *peerKeyDH = NULL;
    EVP_PKEY *peerPubKey = NULL;
    string peerUsername;
    string input;
    bool verify = false;

    try {
        // Receive request
        tempBufferLen = ctx.crypto->decryptMessage(msg.data(), msg.size(), tempBuffer.data());

        if(tempBuffer.at(0) != OP_REQUEST_TO_TALK) {
            errorMessage("Request to talk failed", buffer);
            send(ctx.clientSocket, ctx.crypto, buffer);
            throw runtime_error("Request to talk failed");
        }

        // Get peer username
        buffer.insert(buffer.end(), tempBuffer.begin() + 1, tempBuffer.begin() + tempBufferLen);
        peerUsername = extract(buffer);
        cout << peerUsername << " sent you a request to talk" << endl;

        // Accept or refuse request
        cout << "Do you want to accept the request? (y/n):" << endl;
        do {
            getline(cin, input);
            if(input.length() == 0) {
                cout << "Insert at least a character." << endl;
            } else if(input.compare("y") == 0) {
                cout << "Request accepted" << endl;
                break;
            } else if (input.compare("n") == 0) {
                cout << "Request refused" << endl;
                buffer.clear();
                errorMessage("Request to talk refused", buffer);
                encrypt(ctx.crypto, SERVER_SECRET, buffer);
                buffer.insert(buffer.begin(), OP_ERROR);
                send(ctx.clientSocket, buffer);
                cout << "Request to talk refused" << endl;
                return;
            } else {
                cout << "Insert a valid answer" << endl;
            }       
        } while (input.length() == 0);

        // Send nonce and DH public key
        extract(buffer, peerNonce);
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

        send(ctx.clientSocket, ctx.crypto, buffer);

        // Receive peer's public key
        receive(ctx.clientSocket, ctx.crypto, buffer);
        if(buffer.at(0) == OP_ERROR) {
            buffer.erase(buffer.begin());
            cout << extract(buffer) << endl;
            return;
        }

        buffer.erase(buffer.begin());
        keyBufferDHLen = extract(buffer, keyBufferDH);
        signature.clear();
        signature.insert(signature.end(), keyBufferDH.begin(), keyBufferDH.begin() + keyBufferDHLen);
        signature.insert(signature.end(), nonce.begin(), nonce.end());

        // Extract signed content
        tempBufferLen = extract(buffer, tempBuffer);
        // Extract public key and verify sign
        keyBufferLen = extract(buffer, keyBuffer);
        ctx.crypto->deserializePublicKey(keyBuffer.data(), keyBufferLen, peerPubKey);        
        verify = ctx.crypto->verifySignature(tempBuffer.data(), tempBufferLen, signature.data(), signature.size(), peerPubKey);
        
        if(!verify) {
            errorMessage("Signature not verified", buffer);
            send(ctx.clientSocket, ctx.crypto, buffer);
            throw runtime_error("Signature not verified");
        }

        ctx.crypto->deserializePublicKey(keyBufferDH.data(), keyBufferDHLen, peerKeyDH);
        ctx.crypto->secretDerivation(keyDH, peerKeyDH, tempBuffer.data());
        ctx.crypto->insertKey(tempBuffer.data(), CLIENT_SECRET);

        buffer.clear();
        append("Success", buffer);
        encrypt(ctx.crypto, CLIENT_SECRET, buffer);
        buffer.insert(buffer.begin(), OP_REQUEST_TO_TALK);
        send(ctx.clientSocket, ctx.crypto, buffer);
    } catch(const exception& e) {
        errorMessage("Request to talk failed", buffer);
        send(ctx.clientSocket, ctx.crypto, buffer);
        throw;
    }
}