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
void sendPublicKeyToB(onlineUser peerA, onlineUser peerB, array<unsigned char, NONCE_SIZE> nonceA);
unsigned int extractNonces(onlineUser peerB, unsigned char *nonces);
void sendM4(unsigned char* nonces, uint64_t noncesLen, onlineUser peerB, onlineUser peerA);
void forward(onlineUser peerSender, onlineUser peerReceiver, unsigned char *ciphertext, unsigned int ciphertextLen);
void refuseRequestToTalk(onlineUser peer);
bool requestToTalkProtocol(unsigned char *msg, unsigned int msgLen, onlineUser peerA, vector<onlineUser> onlineUsers, activeChat &chat, vector<activeChat> activeChats);

SocketServer serverSocket(SOCK_STREAM); //TCP
Crypto crypto;

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
        crypto.publicKeyDecryption(buffer.data(), bufferLen, plaintext,prvkey);
    
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

void sendPublicKeyToB(onlineUser peerA, onlineUser peerB, array<unsigned char, NONCE_SIZE> nonceA) {
    EVP_PKEY *pubkeyA;
    uint64_t peerALen;
    array<unsigned char, MAX_MESSAGE_SIZE> buffer;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    unsigned int bufferLen = 0;
    unsigned int pubkeyBufferLen;
    unsigned int ciphertextLen;
    try {
        peerALen = peerA.username.length();
        memcpy(buffer.data(),&peerALen,sizeof(uint64_t));
        bufferLen += sizeof(uint64_t);
        copy_n(peerA.username.c_str(), peerA.username.length(), buffer.begin() + bufferLen);
        bufferLen += peerA.username.length();

        crypto.readPublicKey(peerA.username, pubkeyA);
        pubkeyBufferLen = crypto.serializePublicKey(pubkeyA,tempBuffer.data());

        copy_n(tempBuffer.begin(), pubkeyBufferLen, buffer.begin() + bufferLen);
        bufferLen += pubkeyBufferLen;
        copy_n(nonceA.begin(), NONCE_SIZE, buffer.begin() + bufferLen);
        bufferLen += NONCE_SIZE;

        crypto.setSessionKey(peerB.key_pos);
        ciphertextLen = crypto.encryptMessage(buffer.data(), bufferLen, tempBuffer.data());

        serverSocket.sendMessage(peerB.sd, tempBuffer.begin(), ciphertextLen);
    } catch(const exception& e) {
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

        cout << "***    Forwarding message to the receiver " << peerReceiver.username << endl;
        crypto.setSessionKey(peerReceiver.key_pos);
        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        serverSocket.sendMessage(peerReceiver.sd, ciphertext, ciphertextLen);

        delete[] plaintext;
    } catch(const exception& e) {
        cout << e.what() << '\n';
        if (plaintext != nullptr) delete[] plaintext;
    }
}

bool requestToTalkProtocol(unsigned char *msg, unsigned int msgLen, onlineUser peerA, vector<onlineUser> onlineUsers, activeChat &chat, vector<activeChat> activeChats) {
    EVP_PKEY *pubkeyB;
    string usernameB;
    onlineUser peerB;
    array<unsigned char, NONCE_SIZE> nonceA;
    array<unsigned char, MAX_MESSAGE_SIZE> buffer;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    unsigned int bufferLen;
    unsigned int tempBufferLen;
    unsigned int usernameLen;
    try {        
        cout << "Request to talk coming from user " << peerA.username << endl;
        // Get receiver username
        crypto.setSessionKey(peerA.key_pos);
        bufferLen = crypto.decryptMessage(msg + 1, msgLen - 1, buffer.data());
        usernameLen = bufferLen - NONCE_SIZE;
        usernameB = string(buffer.begin(), buffer.begin() + usernameLen);
        peerB = getUser(onlineUsers, usernameB);
        cout << "Request from " << peerA.username << " to " << usernameB << endl;

        for(activeChat c : activeChats) {
            if(c.a.username.compare(peerB.username) == 0 || c.b.username.compare(peerB.username) == 0) {
                cout << "User " << peerB.username << " busy." << endl;

                copy_n("NO", 2, tempBuffer.data());
                crypto.setSessionKey(peerA.key_pos);
                bufferLen = crypto.encryptMessage(tempBuffer.data(), 2, buffer.data());
                serverSocket.sendMessage(peerA.sd, buffer.data(), bufferLen);

                return false;
            }
        }

        // Encrypt Message M2 OPCODE||{PKa||Na}SB
        copy_n(buffer.begin() + usernameLen, NONCE_SIZE, nonceA.begin());

        sendPublicKeyToB(peerA, peerB, nonceA);
        // Decrypt Message M3 {OK||len||{Na||Nb}PKa}SB
        bufferLen = serverSocket.receiveMessage(peerB.sd, buffer.data());
        crypto.setSessionKey(peerB.key_pos);
        tempBufferLen = crypto.decryptMessage(buffer.data(), bufferLen, tempBuffer.data());

        if(equal(tempBuffer.begin(), tempBuffer.begin() + 2, "OK")) {
            crypto.readPublicKey(peerB.username, pubkeyB);

            bufferLen = crypto.serializePublicKey(pubkeyB, buffer.data());
            copy_n(buffer.begin(), bufferLen, tempBuffer.begin() + tempBufferLen);
            tempBufferLen += bufferLen;
         
            crypto.setSessionKey(peerA.key_pos);
            bufferLen = crypto.encryptMessage(tempBuffer.data(), tempBufferLen, buffer.data());
            serverSocket.sendMessage(peerA.sd, buffer.data(), bufferLen);
        } else {
            forward(peerB, peerA, buffer.data(), bufferLen);
            return false;
        }

        // Decrypt Message M5 and Encrypt M6
        bufferLen = serverSocket.receiveMessage(peerA.sd, buffer.data());
        forward(peerA, peerB, buffer.data(), bufferLen);

        // Decrypt Message M7 and Encrypt M8
        bufferLen = serverSocket.receiveMessage(peerB.sd, buffer.data());
        forward(peerB, peerA, buffer.data(), bufferLen);

        cout << "Create an active chat" << endl;
        chat.a = peerA;
        chat.b = peerB;

        // Decrypt key of A and encrypt key for B
        bufferLen = serverSocket.receiveMessage(peerA.sd, buffer.data());
        forward(peerA, peerB, buffer.data(), bufferLen);

        // Decrypt key of B and encrypt key for A
        bufferLen = serverSocket.receiveMessage(peerB.sd, buffer.data());
        forward(peerB, peerA, buffer.data(), bufferLen);
        return true;
    } catch(const exception& e) {
        throw;
    }
}