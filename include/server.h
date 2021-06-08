#include <fstream>
#include <sstream>
#include <fstream>
#include <iterator>
#include <vector>
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

SocketServer serverSocket(SOCK_STREAM); //TCP
Crypto crypto(MAX_CLIENTS);

int getOperationCode(unsigned char* message) {
    int opCode = message[0] - '0';
    if (opCode < 0 || opCode > 4) { throw runtime_error("Operation Code not valid");}
    return opCode;
}

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

void buildHelloMessage(int sd, unsigned char *nonceClient, unsigned char *nonceServer){
    unsigned char *helloMessage = NULL;
    unsigned int start;
    try{
        helloMessage = new(nothrow) unsigned char[5 + 2*NONCE_SIZE];
        if(!helloMessage) 
            throw runtime_error("An error occurred while allocating the buffer");
        start = 0;
        memcpy(helloMessage, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonceClient, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(helloMessage+start, nonceServer, NONCE_SIZE);
        serverSocket.sendMessage(sd, helloMessage, (5 + 2*NONCE_SIZE));
        delete[] helloMessage;
    }catch(const exception& e) {
        if(helloMessage != nullptr) delete[] helloMessage;
        throw;
    }
}

void checkNonce(unsigned char *certificateRequest, unsigned char *nonceServer){
    unsigned char *nonceServerReceived = NULL;
    try{       
        nonceServerReceived = new(nothrow) unsigned char[NONCE_SIZE];
        if(!nonceServerReceived) 
            throw runtime_error("An error occurred while allocating the buffer");
        memcpy(nonceServerReceived, certificateRequest, NONCE_SIZE);
        if(memcmp(nonceServerReceived, nonceServer, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }
        delete[] nonceServerReceived;
    }catch(const exception& e) {
        if(nonceServerReceived != nullptr) delete[] nonceServerReceived;
        throw;
    }
}

void sendCertificate(int sd, unsigned char* username, unsigned int usernameLen, unsigned char *nonceClient, unsigned char *nonceServer){
    X509 *cert = NULL;
    EVP_PKEY *userPubkey = NULL;
    unsigned char *encryptMsg = NULL;
    unsigned char *certBuff = NULL;
    unsigned char *buffer = NULL;
    unsigned int certLen;
    unsigned int start = 0;
    unsigned int bufferLen = 0;
    unsigned int encryptedMsgLen;
    try{
        crypto.loadCertificate(cert,"server_cert");
        certBuff = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!certBuff)
            throw runtime_error("An error occurred while allocating the buffer");
        certLen = crypto.serializeCertificate(cert,certBuff);

        bufferLen = usernameLen + certLen + 2*NONCE_SIZE;
        buffer = new(nothrow) unsigned char[bufferLen];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer");
        encryptMsg = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!encryptMsg)
            throw runtime_error("An error occurred while allocating the buffer");
        memcpy(buffer, username, usernameLen);
        start += usernameLen;
        memcpy(buffer+start, certBuff, certLen);
        start+=certLen;
        memcpy(buffer+start, nonceClient, NONCE_SIZE);
        start+=NONCE_SIZE;
        memcpy(buffer+start, nonceServer, NONCE_SIZE);

        crypto.readPublicKey((const char*)username, userPubkey);
        encryptedMsgLen = crypto.publicKeyEncryption(buffer,bufferLen,encryptMsg,userPubkey);
        serverSocket.sendMessage(sd,encryptMsg,encryptedMsgLen);
        delete[] certBuff;
        delete[] buffer;
        delete[] encryptMsg;
    }catch(const exception& e) {
        if(certBuff != nullptr) delete[] certBuff;
        if(buffer != nullptr) delete[] buffer;
        if(encryptMsg != nullptr) delete[] encryptMsg;
        throw;
    }
    
}

string authentication(int sd, unsigned char *messageReceived, unsigned int messageLen) {
    EVP_PKEY *prvkey = NULL;
    string usernameStr;
    unsigned char *nonceServer = NULL;
    unsigned char *nonceClient = NULL;
    unsigned char *username = NULL;
    unsigned char *buffer = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *password = NULL;
    unsigned char *hashedPwd = NULL;
    unsigned char *finalDigest = NULL;
    unsigned int bufferLen;
    unsigned int usernameLen;
    unsigned int plainlen;
    unsigned int passwordLen;
    try {
        // Generate nonce
        nonceServer = new(nothrow) unsigned char[NONCE_SIZE];
        if(!nonceServer) {
            throw runtime_error("An error occurred while allocating the buffer");
        }
        crypto.generateNonce(nonceServer);

        // Get peer nonce
        nonceClient = new(nothrow) unsigned char[NONCE_SIZE];
        if(!nonceClient) {
            throw runtime_error("An error occurred while allocating the buffer");
        }
        memcpy(nonceClient, messageReceived+messageLen-NONCE_SIZE, NONCE_SIZE);
        // Get peer username
        usernameLen = messageLen-NONCE_SIZE-1;
        username = new(nothrow) unsigned char[usernameLen];
        if(!username)
            throw runtime_error("An error occurred while allocating the buffer");
        memcpy(username, messageReceived+1, usernameLen);
        cout << "Client username: " << username << endl;

        //Send Certificate
        sendCertificate(sd, username, usernameLen, nonceClient, nonceServer);

        //Receive hashed passwords
        buffer = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer) {
            throw runtime_error("An error occurred while allocating the buffer");
        }
        bufferLen = serverSocket.receiveMessage(sd, buffer);
        plaintext = new(nothrow) unsigned char[bufferLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer");
        crypto.readPrivateKey(prvkey);
        plainlen = crypto.publicKeyDecryption(buffer, bufferLen,plaintext,prvkey);

        password = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!password) 
            throw runtime_error("An error occurred while allocating the buffer");
        passwordLen = readPassword(username, usernameLen, password);

        hashedPwd = new(nothrow) unsigned char[passwordLen + NONCE_SIZE];
        if(!hashedPwd)
            throw runtime_error("An error occurred while allocating the buffer");
        memcpy(hashedPwd, password, passwordLen);
        memcpy(hashedPwd+passwordLen, nonceServer, NONCE_SIZE);

        finalDigest = new(nothrow) unsigned char[DIGEST_LEN];
        if(!finalDigest)
            throw runtime_error("An error occurred while allocating the buffer");
        crypto.computeHash(hashedPwd, passwordLen + NONCE_SIZE, finalDigest);

        if(memcmp(plaintext, finalDigest, DIGEST_LEN) != 0) {
            throw runtime_error("Wrong Password");
        }
        usernameStr = string((const char *)username);
        cout << "Client " << usernameStr << " authenticated." << endl;
        delete[] nonceServer;
        delete[] nonceClient;
        delete[] username;
        delete[] buffer;
        delete[] plaintext;
        return usernameStr;
    } catch(const exception& e) {
        if(nonceServer != nullptr) delete[] nonceServer;
        if(nonceClient != nullptr) delete[] nonceClient;
        if(username != nullptr) delete[] username;
        if(buffer != nullptr) delete[] buffer;
        if(plaintext != nullptr) delete[] plaintext;
        throw;
    }
}

void keyEstablishment(int sd, unsigned int keyPos){
    EVP_PKEY *prvKeyA = NULL;
    EVP_PKEY *pubKeyB = NULL;
    unsigned char *buffer = NULL;
    unsigned char *secret = NULL;
    unsigned int keyLen;

    try {
        // Generate public key
        crypto.keyGeneration(prvKeyA);
        
        // Receive peer's public key
        buffer = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer");
        keyLen = serverSocket.receiveMessage(sd, buffer);
        crypto.deserializePublicKey(buffer, keyLen, pubKeyB);

        // Send public key to peer
        keyLen = crypto.serializePublicKey(prvKeyA, buffer);
        serverSocket.sendMessage(sd, buffer, keyLen);

        // Secret derivation
        secret = new(nothrow) unsigned char[DIGEST_LEN];
        if(!secret)
            throw runtime_error("An error occurred while allocating the buffer");
        crypto.secretDerivation(prvKeyA, pubKeyB, secret);

        crypto.insertKey(secret, keyPos);

        delete[] buffer;
        delete[] secret;
    } catch(const exception& e) {
        if(buffer != nullptr) delete[] buffer;
        if(buffer != nullptr) delete[] secret;
        throw;
    }
}

void sendOnlineUsers(vector<onlineUser> onlineUsers, onlineUser user) {
    string message = "";
    string username = user.username;
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