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

// Utility
unsigned int readPassword(unsigned char* username, unsigned int usernameLen, unsigned char* password);
void sendOnlineUsers(vector<onlineUser> onlineUsers, onlineUser user);
onlineUser getUser(vector<onlineUser> onlineUsers, string username);
bool getReceiver(vector<activeChat> activeChats, onlineUser sender, onlineUser &receiver);
void deleteUser(onlineUser user, vector<onlineUser> &users);
void deleteActiveChat(onlineUser user, vector<activeChat> &chats);

// Authentication
string authentication(int sd, vector<unsigned char> &messageReceived);
void sendCertificate(int sd, unsigned char* username, unsigned int usernameLen, unsigned char *nonceClient, unsigned char *nonceServer);

// Key Establishment
void keyEstablishment(int sd, unsigned int keyPos);

// Request To Talk
string extractUsernameReceiver(unsigned char *msg, unsigned int msgLen, unsigned char *nonceA, onlineUser peerA);
void sendPublicKeyToB(onlineUser peerA, onlineUser peerB, unsigned char *nonceA);
unsigned int extractNonces(onlineUser peerB, unsigned char *nonces);
void sendM4(unsigned char* nonces, uint64_t noncesLen, onlineUser peerB, onlineUser peerA);
void forward(onlineUser peerSender, onlineUser peerReceiver, unsigned char *ciphertext, unsigned int ciphertextLen);
void refuseRequestToTalk(onlineUser peer);
bool requestToTalkProtocol(unsigned char *msg, unsigned int msgLen, onlineUser peerA, vector<onlineUser> onlineUsers, activeChat &chat);


SocketServer serverSocket(SOCK_STREAM); //TCP
Crypto crypto(MAX_CLIENTS);

// ---------- UTILITY ---------- //

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

void sendOnlineUsers(vector<onlineUser> onlineUsers, onlineUser user) {
    string message = "";
    string username = user.username;
    //TODO: Refactor
    unsigned char *encryptedMessage;
    unsigned int encryptedMessageLen;
    unsigned int keyPos = user.key_pos;
    int sd = user.sd;
    try {
        for (onlineUser user : onlineUsers) {
            if(username.compare(user.username) != 0) {
                message.append(user.username);
                message.append("\n");
            }
        }
        if(message.length() == 0) {
            message.append("None");
        }
        crypto.setSessionKey(keyPos);
        encryptedMessage = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!encryptedMessage)
            throw runtime_error("An error occurred while allocating the buffer");
        encryptedMessageLen = crypto.encryptMessage((unsigned char *)message.c_str(), message.length(), encryptedMessage);
        serverSocket.sendMessage(sd, encryptedMessage, encryptedMessageLen);
    } catch(const exception& e) {
        if(encryptedMessage != nullptr) delete[] encryptedMessage;
        throw;
    }
}

onlineUser getUser(vector<onlineUser> onlineUsers, string username){
    for (onlineUser user : onlineUsers) {
        if(username.compare(user.username) == 0) {
            return user;
        }
    }
    throw runtime_error("The user is not online");
}

bool getReceiver(vector<activeChat> activeChats, onlineUser sender, onlineUser &receiver) {
    for (activeChat chat : activeChats) {
        if(chat.a.username.compare(sender.username) == 0) {
            receiver = chat.b;
            return true;
        }
        if (chat.b.username.compare(sender.username) == 0) {
            receiver = chat.a;
            return true;
        }
    }
    return false;
}

void deleteUser(onlineUser user, vector<onlineUser> &users) {
    bool found = false;
    int i = 0;
    for (onlineUser usr : users) {
        if (usr.username.compare(user.username) == 0){
            found = true;
            break;
        }
        i++;
    }
    if (found && i < users.size()) {
        users.erase(users.begin() + i);
    }
}

void deleteActiveChat(onlineUser user, vector<activeChat> &chats) {
    int i = 0;
    bool found = false;
    for (activeChat chat : chats) {
        if(chat.a.username.compare(user.username) == 0 || (chat.b.username.compare(user.username) == 0)) {
            found = true;
            break;
        }
        i++;
    }
    if (found && i < chats.size()) {
        chats.erase(chats.begin() + i);
    }
}

// ---------- AUTHENTICATION ---------- //

string authentication(int sd, vector<unsigned char> &messageReceived) {
    EVP_PKEY *prvkey = NULL;
    string usernameStr;
    array<unsigned char,MAX_MESSAGE_SIZE> buffer;
    array<unsigned char,NONCE_SIZE> nonceClient;
    array<unsigned char,NONCE_SIZE> nonceServer;
    vector<unsigned char> hashedPwd;
    unsigned char *plaintext = NULL;
    unsigned int bufferLen;
    unsigned int plainlen;
    unsigned int passwordLen;
    try {
        // Generate nonce
        crypto.generateNonce(nonceServer.data());
        crypto.readPrivateKey(prvkey);

        // Get peer nonce and username
        copy_n(messageReceived.end() - NONCE_SIZE, NONCE_SIZE, nonceClient.begin());
        usernameStr = string(messageReceived.begin(), messageReceived.end() - NONCE_SIZE);
        cout << "Client username: " << usernameStr << endl;

        // Send Certificate
        sendCertificate(sd, (unsigned char *)usernameStr.c_str(), usernameStr.length(), nonceClient.data(), nonceServer.data());

        // Receive hashed password
        bufferLen = serverSocket.receiveMessage(sd, buffer.data());
        plaintext = new(nothrow) unsigned char[bufferLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer");
        plainlen = crypto.publicKeyDecryption(buffer.data(), bufferLen, plaintext,prvkey);
    
        // Read Hash from file
        passwordLen = readPassword((unsigned char *)usernameStr.c_str(), usernameStr.length(), buffer.data());

        // Compute Hash of the H(pwd) + Nonce
        hashedPwd.insert(hashedPwd.end(), buffer.begin(), buffer.begin() + passwordLen);
        hashedPwd.insert(hashedPwd.end(), nonceServer.begin(), nonceServer.end());
        crypto.computeHash(hashedPwd.data(), hashedPwd.size(), buffer.data());

        if(memcmp(plaintext, buffer.data(), DIGEST_LEN) != 0) {
            throw runtime_error("Wrong Password");
        }
        cout << "Client " << usernameStr << " authenticated." << endl;
        delete[] plaintext;
        return usernameStr;
    } catch(const exception& e) {
        if(plaintext != nullptr) delete[] plaintext;
        throw;
    }
}

void sendCertificate(int sd, unsigned char* username, unsigned int usernameLen, unsigned char *nonceClient, unsigned char *nonceServer){
    X509 *cert = NULL;
    EVP_PKEY *userPubkey = NULL;
    vector<unsigned char> message;
    unsigned char *encryptMsg = NULL;
    unsigned char *certBuff = NULL;
    unsigned int certLen;
    unsigned int encryptedMsgLen;
    try{

        crypto.loadCertificate(cert,"server_cert");
        certBuff = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];

        if(!certBuff)
            throw runtime_error("An error occurred while allocating the buffer");

        certLen = crypto.serializeCertificate(cert,certBuff);
        message.insert(message.end(), certBuff, certBuff + certLen);
        delete[] certBuff;

        message.insert(message.end(), nonceClient, nonceClient + NONCE_SIZE);
        message.insert(message.end(), nonceServer, nonceServer + NONCE_SIZE);

        crypto.readPublicKey((const char*)username, userPubkey);
        encryptMsg = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!encryptMsg)
            throw runtime_error("An error occurred while allocating the buffer");
        encryptedMsgLen = crypto.publicKeyEncryption(message.data(),message.size(),encryptMsg,userPubkey);
        serverSocket.sendMessage(sd,encryptMsg,encryptedMsgLen);
        delete[] encryptMsg;
    }catch(const exception& e) {
        if(certBuff != nullptr) delete[] certBuff;
        if(encryptMsg != nullptr) delete[] encryptMsg;
        throw;
    }
    
}

// ---------- KEY ESTABLISHMENT ---------- //

void keyEstablishment(onlineUser client, unsigned int keyPos){
    EVP_PKEY *serverPrvKeyDH = NULL;
    EVP_PKEY *serverPrvKey = NULL;
    EVP_PKEY *clientPubKeyDH = NULL;
    EVP_PKEY *clientPubKey = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> plaintext;
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    unsigned char *secret = NULL;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;

    try {
        // Generate public key
        crypto.keyGeneration(serverPrvKeyDH);
        crypto.readPublicKey(client.username, clientPubKey);
        crypto.readPrivateKey(serverPrvKey);
        
        // Receive peer's public key
        ciphertextLen = serverSocket.receiveMessage(client.sd, ciphertext.data());
        cout << "Message Received Len: " << ciphertextLen << endl;
        plaintextLen = crypto.publicKeyDecryption(ciphertext.data(), ciphertextLen, plaintext.data(), serverPrvKey);
        crypto.deserializePublicKey(plaintext.data(), plaintextLen, clientPubKeyDH);

        // Send public key to peer
        plaintextLen = crypto.serializePublicKey(serverPrvKeyDH, plaintext.data());
        ciphertextLen = crypto.publicKeyEncryption(plaintext.data(), plaintextLen, ciphertext.data(), clientPubKey);      
        cout << "Ciphertext Len: " << ciphertextLen << endl;  
        serverSocket.sendMessage(client.sd, ciphertext.data(), ciphertextLen);

        // Secret derivation
        secret = new(nothrow) unsigned char[DIGEST_LEN];
        if(!secret)
            throw runtime_error("An error occurred while allocating the buffer");
        crypto.secretDerivation(serverPrvKeyDH, clientPubKeyDH, secret);

        crypto.insertKey(secret, keyPos);

        delete[] secret;
    } catch(const exception& e) {
        if(secret != nullptr) delete[] secret;
        throw;
    }
}

// ---------- REQUEST TO TALK ---------- //

string extractUsernameReceiver(unsigned char *msg, unsigned int msgLen, unsigned char *nonceA, onlineUser peerA) {
    unsigned char *bufferB = NULL;
    unsigned char *usernameB = NULL;
    unsigned int bufferBLen;
    unsigned int usernameBLen;
    try {
        if(memcmp(msg, OP_REQUEST_TO_TALK, 1) != 0) {
            throw runtime_error("Request to talk failed.");
        }
        cout << "Request to talk coming from user " << peerA.username << endl;
        bufferB = new(nothrow) unsigned char[msgLen];
        if(!bufferB)
            throw runtime_error("An error occurred while allocating the buffer");
        crypto.setSessionKey(peerA.key_pos);
        bufferBLen = crypto.decryptMessage(msg+1, msgLen-1, bufferB); //Not consider the OPCODE
        usernameBLen = bufferBLen-NONCE_SIZE;
        usernameB = new(nothrow) unsigned char[usernameBLen];
        if(!usernameB)
            throw runtime_error("An error occurred while allocating the buffer");
        memcpy(usernameB,bufferB,usernameBLen);
        memcpy(nonceA,bufferB+usernameBLen,NONCE_SIZE);

        cout << "Request from " << peerA.username << " to " << usernameB << endl;
        delete[] bufferB;
        delete[] usernameB;
        return string((const char *)usernameB);
    } catch(const exception& e) {
        cout << "Error in extractUsernameReceiver(): " << e.what() << endl; 
        if(bufferB != nullptr) delete[] bufferB;
        if(usernameB != nullptr) delete[] usernameB;
        throw;
    }
}

void sendPublicKeyToB(onlineUser peerA, onlineUser peerB, unsigned char *nonceA) {
    EVP_PKEY *pubkeyA;
    uint64_t peerALen;
    unsigned char *buffer = NULL;
    unsigned char *pubkeyBuffer = NULL;
    unsigned char *ciphertext = NULL;
    unsigned int bufferLen;
    unsigned int pubkeyBufferLen;
    unsigned int ciphertextLen;
    unsigned int start = 0;
    try {
        buffer = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer");
        peerALen = peerA.username.length();
        memcpy(buffer,&peerALen,sizeof(uint64_t));
        start += sizeof(uint64_t);
        memcpy(buffer + start, peerA.username.c_str(), peerALen);
        start += peerALen;
        crypto.readPublicKey(peerA.username,pubkeyA);
        pubkeyBuffer = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!pubkeyBuffer)
            throw runtime_error("An error occurred while allocating the buffer");
        pubkeyBufferLen = crypto.serializePublicKey(pubkeyA,pubkeyBuffer);
        memcpy(buffer + start,pubkeyBuffer,pubkeyBufferLen);

        start += pubkeyBufferLen;
        memcpy(buffer + start, nonceA, NONCE_SIZE);
        bufferLen = sizeof(uint64_t) + peerALen + pubkeyBufferLen + NONCE_SIZE;
        ciphertext = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer");

        crypto.setSessionKey(peerB.key_pos);
        ciphertextLen = crypto.encryptMessage(buffer,bufferLen,ciphertext);

        // Append OPCODE as clear text
        memcpy(buffer, OP_REQUEST_TO_TALK, 1);
        memcpy(buffer+1,ciphertext,ciphertextLen);
        serverSocket.sendMessage(peerB.sd,buffer,ciphertextLen+1);
        delete[] buffer;
        delete[] pubkeyBuffer;
        delete[] ciphertext;
    } catch(const exception& e) {
        if(buffer != nullptr) delete[] buffer;
        if(pubkeyBuffer != nullptr) delete[] pubkeyBuffer;
        if(ciphertext != nullptr) delete[] ciphertext;
        throw;
    }
    
}

unsigned int extractNonces(onlineUser peerB, unsigned char *nonces) {
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned int ciphertextLen;
    unsigned int plaintextLen;
    unsigned int noncesLen;
    try {
        cout << "Extract Nonces" << endl;
        ciphertext = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer");
        ciphertextLen = serverSocket.receiveMessage(peerB.sd, ciphertext);
        crypto.setSessionKey(peerB.key_pos);
        plaintext = new(nothrow) unsigned char[ciphertextLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer");
        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);
        if(memcmp(plaintext, "OK", 2) != 0){
            throw runtime_error("Request to talk failed.");
        }
        noncesLen = plaintextLen - 2;
        memcpy(nonces,plaintext+2,noncesLen);
        delete[] ciphertext;
        delete[] plaintext;
        return noncesLen;
    } catch(const exception& e) {
        cout << e.what() << '\n';
        if (ciphertext != nullptr) delete[] ciphertext;
        if (plaintext != nullptr) delete[] plaintext;
        return 0;
    }
    
}

void sendM4(unsigned char* nonces, uint64_t noncesLen, onlineUser peerB, onlineUser peerA) {
    EVP_PKEY *pubkeyB;
    unsigned char *buffer; 
    unsigned char *pubkeyBBuff;
    unsigned char *ciphertext;
    unsigned int bufferLen;
    unsigned int start;
    unsigned int pubkeyBBuffLen; 
    unsigned int ciphertextLen;
    try {
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        start = 0;
        memcpy(buffer,&noncesLen,8);
        start += 8;
        memcpy(buffer + start, "OK", 2);
        start += 2;
        memcpy(buffer + start, nonces, noncesLen);
        start += noncesLen;

        crypto.readPublicKey(peerB.username, pubkeyB);
        pubkeyBBuff = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!pubkeyBBuff)
            throw runtime_error("An error occurred while allocating the buffer");
        pubkeyBBuffLen = crypto.serializePublicKey(pubkeyB, pubkeyBBuff);
        memcpy(buffer + start, pubkeyBBuff, pubkeyBBuffLen);
        start += pubkeyBBuffLen;

        bufferLen = 8 + 2 + noncesLen + pubkeyBBuffLen;

        ciphertext = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer");
        crypto.setSessionKey(peerA.key_pos);
        ciphertextLen = crypto.encryptMessage(buffer, bufferLen, ciphertext);
        serverSocket.sendMessage(peerA.sd, ciphertext, ciphertextLen);
        delete[] buffer;
        delete[] pubkeyBBuff;
        delete[] ciphertext;
    } catch(const exception& e) {
        if(buffer != nullptr) delete[] buffer;
        if(pubkeyBBuff != nullptr) delete[] pubkeyBBuff;
        if(ciphertext != nullptr) delete[] ciphertext;
        throw;
    }
}

void forward(onlineUser peerSender, onlineUser peerReceiver, unsigned char *ciphertext, unsigned int ciphertextLen) {
    unsigned char *plaintext = NULL;
    unsigned int plaintextLen;
    try {
        crypto.setSessionKey(peerSender.key_pos);

        cout << "Sender " << peerSender.username << " " << peerSender.key_pos << endl;

        plaintext = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!plaintext) 
            throw runtime_error("An error occurred while allocating the buffer");
        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);

        cout << "***    Forwarding message to the receiver " << peerReceiver.username << "..." << endl;
        crypto.setSessionKey(peerReceiver.key_pos);
        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        serverSocket.sendMessage(peerReceiver.sd, ciphertext, ciphertextLen);

        delete[] plaintext;
    } catch(const exception& e) {
        cout << e.what() << '\n';
        if (plaintext != nullptr) delete[] plaintext;
    }
}

void refuseRequestToTalk(onlineUser peer) {
    unsigned char plaintext[2];
    unsigned char *ciphertext = NULL;
    unsigned int plaintextLen = 2;
    unsigned int ciphertextLen;
    try {
        memcpy(plaintext, "NO", 2);
        crypto.setSessionKey(0);
        ciphertext = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(ciphertext != nullptr)
            throw runtime_error("An error occurred while allocating the buffer");
        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        serverSocket.sendMessage(peer.sd, ciphertext, ciphertextLen);
        delete[] ciphertext;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
    }
}

bool requestToTalkProtocol(unsigned char *msg, unsigned int msgLen, onlineUser peerA, vector<onlineUser> onlineUsers, activeChat &chat) {
    onlineUser peerB;
    uint64_t nonces_len;
    unsigned char *nonceA = NULL;
    unsigned char *nonces = NULL;
    unsigned char *ciphertext;
    unsigned int ciphertextLen;
    try {
        
        nonceA = new(nothrow) unsigned char[NONCE_SIZE];
        if(!nonceA)
            throw runtime_error("An error occurred while allocating the buffer");
        string usernameB = extractUsernameReceiver(msg, msgLen, nonceA, peerA);
        peerB = getUser(onlineUsers, usernameB);

        // Encrypt Message M2 OPCODE||{PKa||Na}SB
        sendPublicKeyToB(peerA, peerB, nonceA);
        cout << "Waiting for M3..." << endl;

        // Decrypt Message M3 {OK||{Na||Nb}PKa}SB
        nonces = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!nonces)
            throw runtime_error("An error occurred while allocating the buffer");
        nonces_len = extractNonces(peerB, nonces);

        if (nonces_len == 0) {
            refuseRequestToTalk(peerA);
            cout << "The request to talk has been refused." << endl;
            return false;
        }
        
        // Encrypt Message M4 {nonLen||OK||{Na||Nb}PKa||PKb} --> nonLen = 64 bits
        cout << "\nSending M4..." << endl;
        sendM4(nonces, nonces_len, peerB, peerA);
        cout << "\nM4 sent" << endl << endl;

        // Decrypt Message M5 and Encrypt M6
        ciphertext = new unsigned char[MAX_MESSAGE_SIZE];
        ciphertextLen = serverSocket.receiveMessage(peerA.sd, ciphertext);
        forward(peerA, peerB, ciphertext, ciphertextLen);

        // Decrypt Message M7 and Encrypt M8
        ciphertextLen = serverSocket.receiveMessage(peerB.sd, ciphertext);
        forward(peerB, peerA, ciphertext, ciphertextLen);

        cout << "Create an active chat" << endl;
        chat.a = peerA;
        chat.b = peerB;

        // Decrypt key of A and encrypt key for B
        ciphertextLen = serverSocket.receiveMessage(peerA.sd, ciphertext);
        forward(peerA, peerB, ciphertext, ciphertextLen);

        // Decrypt key of B and encrypt key for A
        ciphertextLen = serverSocket.receiveMessage(peerB.sd, ciphertext);
        forward(peerB, peerA, ciphertext, ciphertextLen);
        delete[] nonceA;
        delete[] nonces;
        delete[] ciphertext;
        return true;
    } catch(const exception& e) {
        if (nonceA != nullptr) delete[] nonceA;
        if (nonces != nullptr) delete[] nonces;
        throw;
    }
}