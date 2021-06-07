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
        helloMessage = new unsigned char[5 + 2*NONCE_SIZE];
        start = 0;
        memcpy(helloMessage, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonceClient, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(helloMessage+start, nonceServer, NONCE_SIZE);
        serverSocket.sendMessage(sd, helloMessage, (5 + 2*NONCE_SIZE));
    }catch(const exception& e) {
        delete[] helloMessage;
        throw;
    }
    delete[] helloMessage;
}

void checkNonce(unsigned char *certificateRequest, unsigned char *nonceServer){
    unsigned char *nonceServerReceived = NULL;
    try{       
        nonceServerReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceServerReceived, certificateRequest, NONCE_SIZE);

        if(memcmp(nonceServerReceived, nonceServer, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }
    }catch(const exception& e) {
        delete[] nonceServerReceived;
        throw;
    }
    delete[] nonceServerReceived;
}

void sendCertificate(int sd, unsigned char* username, unsigned int usernameLen, unsigned char *nonceClient, unsigned char *nonceServer){
    unsigned char *cert_buff = NULL;
    unsigned char *buffer = NULL;
    unsigned char *encrypt_msg = NULL;
    X509 *cert = NULL;
    EVP_PKEY *user_pubkey = NULL;
    unsigned int cert_len;
    unsigned int start = 0;
    unsigned int bufferLen = 0;
    unsigned int encrypted_msg_len;
    try{
        crypto.loadCertificate(cert,"server_cert");
        cert_buff = new unsigned char[MAX_MESSAGE_SIZE];
        cert_len = crypto.serializeCertificate(cert,cert_buff);

        bufferLen = usernameLen + cert_len + 2*NONCE_SIZE;
        buffer = new unsigned char[bufferLen];
        encrypt_msg = new unsigned char[MAX_MESSAGE_SIZE];
        memcpy(buffer, username, usernameLen);
        start += usernameLen;
        memcpy(buffer+start, cert_buff, cert_len);
        start+=cert_len;
        memcpy(buffer+start, nonceClient, NONCE_SIZE);
        start+=NONCE_SIZE;
        memcpy(buffer+start, nonceServer, NONCE_SIZE);

        crypto.readPublicKey((const char*)username, user_pubkey);
        encrypted_msg_len = crypto.publicKeyEncryption(buffer,bufferLen,encrypt_msg,user_pubkey);
        serverSocket.sendMessage(sd,encrypt_msg,encrypted_msg_len);
    }catch(const exception& e) {
        delete[] cert_buff;
        delete[] buffer;
        delete[] encrypt_msg;
        throw;
    }
    delete[] cert_buff;
    delete[] buffer;
    delete[] encrypt_msg;
}

string authentication(int sd, unsigned char *messageReceived, unsigned int message_len) {
    unsigned char *nonceServer = NULL;
    unsigned char *nonceClient = NULL;
    unsigned char *username = NULL;
    unsigned char *buffer = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *password = NULL;
    unsigned char *hashedPwd = NULL;
    unsigned char *finalDigest = NULL;
    EVP_PKEY *prvkey = NULL;
    unsigned int bufferLen;
    unsigned int usernameLen;
    unsigned int plainlen;
    unsigned int passwordLen;
    string usernameStr;
    try {
        // Generate nonce
        nonceServer = new unsigned char[NONCE_SIZE];
        crypto.generateNonce(nonceServer);

        // Get peer nonce
        nonceClient = new unsigned char[NONCE_SIZE];
        memcpy(nonceClient, messageReceived+message_len-NONCE_SIZE, NONCE_SIZE);
        // Get peer username
        usernameLen = message_len-NONCE_SIZE-1;
        username = new unsigned char[usernameLen];
        memcpy(username, messageReceived+1, usernameLen);
        cout << "Client username: " << username << endl;

        //Send Certificate
        sendCertificate(sd, username, usernameLen, nonceClient, nonceServer);

        //Receive hashed passwords
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        bufferLen = serverSocket.receiveMessage(sd, buffer);
        plaintext = new unsigned char[bufferLen];
        crypto.readPrivateKey(prvkey);
        plainlen = crypto.publicKeyDecryption(buffer, bufferLen,plaintext,prvkey);

        password = new unsigned char[MAX_MESSAGE_SIZE];
        passwordLen = readPassword(username, usernameLen, password);

        hashedPwd = new unsigned char[passwordLen + NONCE_SIZE];
        memcpy(hashedPwd, password, passwordLen);
        memcpy(hashedPwd+passwordLen, nonceServer, NONCE_SIZE);

        finalDigest = new unsigned char[DIGEST_LEN];
        crypto.computeHash(hashedPwd, passwordLen + NONCE_SIZE, finalDigest);

        if(memcmp(plaintext, finalDigest, DIGEST_LEN) != 0) {
            throw runtime_error("Wrong Password");
        }
        usernameStr = string((const char *)username);
        cout << "Client " << usernameStr << " authenticated." << endl;
    } catch(const exception& e) {
        delete[] nonceServer;
        delete[] nonceClient;
        delete[] username;
        delete[] buffer;
        delete[] plaintext;
        throw;
    }
    delete[] nonceServer;
    delete[] nonceClient;
    delete[] username;
    delete[] buffer;
    delete[] plaintext;
    return usernameStr;
}

void keyEstablishment(int sd, unsigned int key_pos){
    unsigned char *buffer = NULL;
    unsigned char *secret = NULL;
    unsigned int key_len;
    EVP_PKEY *prv_key_a = NULL;
    EVP_PKEY *pub_key_b = NULL;

    try {
        // Generate public key
        crypto.keyGeneration(prv_key_a);
        
        // Receive peer's public key
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        key_len = serverSocket.receiveMessage(sd, buffer);
        crypto.deserializePublicKey(buffer, key_len, pub_key_b);

        // Send public key to peer
        key_len = crypto.serializePublicKey(prv_key_a, buffer);
        serverSocket.sendMessage(sd, buffer, key_len);

        // Secret derivation
        secret = new unsigned char[DIGEST_LEN];
        crypto.secretDerivation(prv_key_a, pub_key_b, secret);

        cout << "O' secret: " << endl;
        BIO_dump_fp(stdout, (const char*)secret, DIGEST_LEN);

        crypto.insertKey(secret, key_pos);
    } catch(const exception& e) {
        delete[] buffer;
        delete[] secret;
        throw;
    }
    
    delete[] buffer;
    delete[] secret;
}

void sendOnlineUsers(vector<onlineUser> onlineUsers, onlineUser user) {
    unsigned char *encryptedMessage;
    unsigned int encryptedMessageLen;
    string message = "";
    string username = user.username;
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
            message.append("You are the only online user");
        }
        crypto.setSessionKey(keyPos);
        encryptedMessage = new unsigned char[MAX_MESSAGE_SIZE];
        encryptedMessageLen = crypto.encryptMessage((unsigned char *)message.c_str(), message.length(), encryptedMessage);
        serverSocket.sendMessage(sd, encryptedMessage, encryptedMessageLen);
    } catch(const exception& e) {
        delete[] encryptedMessage;
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

bool getReceiver(vector<activeChat> activeChats, onlineUser sender, onlineUser receiver) {
    bool found = false;
    for (activeChat chat : activeChats) {
        if(chat.a.username.compare(sender.username)) {
            receiver = chat.b;
            found = true;
        }
        if (chat.b.username.compare(sender.username)) {
            receiver = chat.a;
            found = true;
        }
    }
    return found;
}

string extractUsernameReceiver(unsigned char *msg, unsigned int msgLen, unsigned char *nonceA, onlineUser peer_a) {
    unsigned char *buffer_b = NULL, *username_b = NULL;
    unsigned int buffer_b_len, username_b_len;
    try {
        if(memcmp(msg, OP_REQUEST_TO_TALK, 1) != 0) {
            throw runtime_error("Request to talk failed.");
        }
        cout << "Request to talk coming from user " << peer_a.username << endl;
        buffer_b = new unsigned char[msgLen];
        crypto.setSessionKey(peer_a.key_pos);
        buffer_b_len = crypto.decryptMessage(msg+1, msgLen-1, buffer_b); //Not consider the OPCODE
        username_b_len = buffer_b_len-NONCE_SIZE;
        username_b = new unsigned char[username_b_len];
        memcpy(username_b,buffer_b,username_b_len);
        memcpy(nonceA,buffer_b+username_b_len,NONCE_SIZE);
            
        cout << "Nonce A" << endl;
        BIO_dump_fp(stdout, (const char *) nonceA, NONCE_SIZE);

        cout << "Request from " << peer_a.username << " to " << username_b << endl;
        delete[] buffer_b;
        delete[] username_b;
        return string((const char *)username_b);
    } catch(const exception& e) {
        cout << "Error in extractUsernameReceiver(): " << e.what() << endl; 
        delete[] buffer_b;
        delete[] username_b;
        throw;
    }
}

void sendPublicKeyToB(onlineUser peerA, onlineUser peerB, unsigned char *nonceA) {
    unsigned char *buffer, *pubkeyBuffer, *ciphertext;
    unsigned int bufferLen, pubkeyBufferLen, ciphertextLen;
    EVP_PKEY *pubkey_a;
    unsigned int start = 0;
    try {
        buffer = new unsigned char[MAX_MESSAGE_SIZE];

        crypto.readPublicKey(peerA.username,pubkey_a);
        pubkeyBuffer = new unsigned char[MAX_MESSAGE_SIZE];
        pubkeyBufferLen = crypto.serializePublicKey(pubkey_a,pubkeyBuffer);
        memcpy(buffer,pubkeyBuffer,pubkeyBufferLen);

        start += pubkeyBufferLen;
        memcpy(buffer + start, nonceA, NONCE_SIZE);
        bufferLen = pubkeyBufferLen + NONCE_SIZE;
        ciphertext = new unsigned char[MAX_MESSAGE_SIZE];

        crypto.setSessionKey(peerB.key_pos);
        ciphertextLen =  crypto.encryptMessage(buffer,bufferLen,ciphertext);

        // Append OPCODE as clear text
        memcpy(buffer, OP_REQUEST_TO_TALK, 1);
        memcpy(buffer+1,ciphertext,ciphertextLen);
        serverSocket.sendMessage(peerB.sd,buffer,ciphertextLen+1);
        delete[] buffer;
        delete[] pubkeyBuffer;
        delete[] ciphertext;
    } catch(const exception& e) {
        cout << "Error in sendPublicKeyToB: " << e.what() << endl;
        delete[] buffer;
        delete[] pubkeyBuffer;
        delete[] ciphertext;
        throw;
    }
    
}

unsigned int extractNonces(onlineUser peerB, unsigned char *nonces) {
    unsigned char *ciphertext = NULL, *plaintext = NULL;
    unsigned int ciphertextLen, plaintextLen, noncesLen;
    try {
        cout << "Extract Nonces" << endl;
        ciphertext = new unsigned char[MAX_MESSAGE_SIZE];
        ciphertextLen = serverSocket.receiveMessage(peerB.sd, ciphertext);
        crypto.setSessionKey(peerB.key_pos);
        plaintext = new unsigned char[ciphertextLen];
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
        if (ciphertext) delete[] ciphertext;
        if (plaintext) delete[] plaintext;
        return 0;
    }
    
}

void sendM4(unsigned char* nonces, uint64_t nonces_len, onlineUser peerB, onlineUser peerA) {
    unsigned char *buffer, *pubkeyBBuff, *ciphertext;
    unsigned int bufferLen, start, pubkeyBBuffLen, ciphertextLen;
    EVP_PKEY *pubkeyB;
    try {
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        start = 0;
        memcpy(buffer,&nonces_len,8);
        start += 8;
        memcpy(buffer + start, "OK", 2);
        start += 2;
        memcpy(buffer + start, nonces, nonces_len);
        start += nonces_len;

        crypto.readPublicKey(peerB.username, pubkeyB);
        pubkeyBBuff = new unsigned char[MAX_MESSAGE_SIZE];
        pubkeyBBuffLen = crypto.serializePublicKey(pubkeyB, pubkeyBBuff);
        memcpy(buffer + start, pubkeyBBuff, pubkeyBBuffLen);
        start += pubkeyBBuffLen;

        bufferLen = 8 + 2 + nonces_len + pubkeyBBuffLen;

        ciphertext = new unsigned char[MAX_MESSAGE_SIZE];
        crypto.setSessionKey(peerA.key_pos);
        ciphertextLen = crypto.encryptMessage(buffer, bufferLen, ciphertext);
        serverSocket.sendMessage(peerA.sd, ciphertext, ciphertextLen);
        delete[] buffer;
        delete[] pubkeyBBuff;
        delete[] ciphertext;
    } catch(const exception& e) {
        cout << "Error in sendM4(): " << e.what() << '\n';
        delete[] buffer;
        delete[] pubkeyBBuff;
        delete[] ciphertext;
        throw;
    }
}

void forward(onlineUser peerSender, onlineUser peerReceiver, unsigned char *ciphertext, unsigned int ciphertextLen) {
    unsigned char *plaintext = NULL;
    unsigned int plaintextLen;
    try {
        crypto.setSessionKey(peerSender.key_pos);
        plaintext = new unsigned char[ciphertextLen];
        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);
        
        cout << "***    Forwarding message to the receiver " << peerReceiver.username << "..." << endl;
        crypto.setSessionKey(peerReceiver.key_pos);
        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        serverSocket.sendMessage(peerReceiver.sd, ciphertext, ciphertextLen);

        delete[] plaintext;
    } catch(const exception& e) {
        cout << e.what() << '\n';
        if (plaintext) delete[] plaintext;
    }
}

void refuseRequestToTalk(onlineUser peer) {
    unsigned char plaintext[2];
    unsigned char *ciphertext = NULL;
    unsigned int plaintextLen = 2, ciphertextLen;
    try {
        memcpy(plaintext, "NO", 2);
        crypto.setSessionKey(0);
        ciphertext = new(nothrow) unsigned char[MAX_MESSAGE_SIZE];
        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        serverSocket.sendMessage(peer.sd, ciphertext, ciphertextLen);
        delete[] ciphertext;
    } catch(const exception& e) {
        cout << e.what() << '\n';
        if(!ciphertext) delete[] ciphertext;
    }
}

bool requestToTalkProtocol(unsigned char *msg, unsigned int msgLen, onlineUser peerA, vector<onlineUser> onlineUsers, activeChat chat) {
    unsigned char *nonceA = NULL, *nonces = NULL, *ciphertext;
    unsigned int ciphertextLen;
    onlineUser peerB;
    uint64_t nonces_len;
    try {
        
        nonceA = new unsigned char[NONCE_SIZE];
        string usernameB = extractUsernameReceiver(msg, msgLen, nonceA, peerA);
        
        peerB = getUser(onlineUsers, usernameB);

        // Encrypt Message M2 OPCODE||{PKa||Na}SB
        sendPublicKeyToB(peerA, peerB, nonceA);
        cout << "Waiting for M3..." << endl;

        // Decrypt Message M3 {OK||{Na||Nb}PKa}SB
        nonces = new unsigned char[MAX_MESSAGE_SIZE];
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
        if (nonceA) delete[] nonceA;
        if (nonces) delete[] nonces;
        throw;
    }
}